//! Browser authorization for a registered public client. Credentials stay here.
use std::{collections::HashMap, sync::Mutex};

use anyhow::{ensure, Result};
use axum::{
    extract::{DefaultBodyLimit, Form, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand_core::{OsRng, RngCore};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{auth::now, registry::Registry};

mod page;
use page::form;

const FORM_SECONDS: u64 = 300;
const CODE_SECONDS: u64 = 60;
const MAX_PENDING: usize = 1024;

#[derive(Default)]
pub struct OAuth {
    inner: Mutex<Store>,
}

#[derive(Default)]
struct Store {
    client_id: String,
    redirects: Vec<String>,
    forms: HashMap<String, Pending>,
    codes: HashMap<String, Code>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Authorization {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    state: String,
    code_challenge: String,
    code_challenge_method: String,
    #[serde(default)]
    scope: String,
}

struct Pending {
    request: Authorization,
    cookie: String,
    expires: u64,
}

struct Code {
    request: Authorization,
    user: String,
    expires: u64,
}

impl Store {
    fn prune(&mut self) {
        let time = now();
        self.forms.retain(|_, p| p.expires > time);
        self.codes.retain(|_, p| p.expires > time);
    }
}

impl OAuth {
    pub fn configure(&self, client_id: &str, redirects: &[String]) -> Result<()> {
        ensure!(
            !client_id.is_empty() && client_id.len() <= 128
                && client_id.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b)),
            "OAuth client ID must contain 1-128 letters, digits, dots, underscores, tildes or hyphens"
        );
        ensure!(
            !redirects.is_empty(),
            "Register at least one OAuth redirect URI"
        );
        for redirect in redirects {
            let url = Url::parse(redirect)?;
            let host = url.host_str().unwrap_or("").trim_matches(['[', ']']);
            let loopback = host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback());
            ensure!(
                (url.scheme() == "https" || (url.scheme() == "http" && loopback))
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none(),
                "OAuth redirect must be an HTTPS or loopback HTTP URL without credentials, query or fragment"
            );
        }
        let mut store = self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("OAuth store lock failed"))?;
        store.client_id = client_id.into();
        store.redirects = redirects.to_vec();
        store.forms.clear();
        store.codes.clear();
        Ok(())
    }
}

pub fn router() -> Router<std::sync::Arc<Registry>> {
    Router::new()
        .route("/oauth/config", get(config))
        .route("/oauth/authorize", get(authorize).post(consent))
        .route("/oauth/token", post(exchange))
        .layer(DefaultBodyLimit::max(16 * 1024))
}

fn random() -> String {
    let mut bytes = [0; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn hardened(response: impl IntoResponse) -> Response {
    let mut response = response.into_response();
    for (key, value) in [
        ("cache-control", "no-store"),
        ("pragma", "no-cache"),
        ("referrer-policy", "no-referrer"),
        ("x-frame-options", "DENY"),
        ("x-content-type-options", "nosniff"),
        ("content-security-policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"),
    ] {
        response.headers_mut().insert(key, value.parse().expect("static header"));
    }
    response
}

fn error(status: StatusCode, code: &str) -> Response {
    hardened((status, Json(json!({"error": code}))))
}

async fn config(State(registry): State<std::sync::Arc<Registry>>) -> Response {
    let Ok(store) = registry.oauth.inner.lock() else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    };
    let endpoint = registry.oauth_authorization_endpoint();
    hardened(Json(
        json!({"client_id":store.client_id,"authorization_endpoint":endpoint,
        "token_endpoint":"/oauth/token","redirect_uris":store.redirects,
        "code_challenge_methods_supported":["S256"]}),
    ))
}

fn scopes(value: &str) -> Result<Vec<String>> {
    let scopes: Vec<_> = value.split_whitespace().map(str::to_string).collect();
    for scope in &scopes {
        if scope == "registry:catalog:read" {
            continue;
        }
        let grant = scope
            .strip_prefix("repository:")
            .ok_or_else(|| anyhow::anyhow!("Unsupported scope"))?;
        crate::auth::parse_grant(grant)?;
    }
    Ok(scopes)
}

async fn authorize(
    State(registry): State<std::sync::Arc<Registry>>,
    Query(request): Query<Authorization>,
) -> Response {
    let Ok(mut store) = registry.oauth.inner.lock() else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    };
    // Never redirect an invalid authorization request, especially a bad redirect URI.
    if store.client_id.is_empty()
        || request.client_id != store.client_id
        || !store.redirects.contains(&request.redirect_uri)
        || request.response_type != "code"
        || request.code_challenge_method != "S256"
        || request.state.is_empty()
        || request.state.len() > 256
        || request.code_challenge.len() != 43
        || !request
            .code_challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        || scopes(&request.scope).is_err()
    {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    store.prune();
    if store.forms.len() + store.codes.len() >= MAX_PENDING {
        return error(StatusCode::TOO_MANY_REQUESTS, "temporarily_unavailable");
    }
    let id = random();
    let pending = Pending {
        request,
        cookie: random(),
        expires: now() + FORM_SECONDS,
    };
    let mut response = form(&id, &pending, "", "");
    response.headers_mut().insert(header::SET_COOKIE,
        format!("ifcx_oauth_{id}={}; HttpOnly; SameSite=Strict; Path=/oauth/authorize; Max-Age={FORM_SECONDS}", pending.cookie)
            .parse().expect("generated cookie"));
    store.forms.insert(id, pending);
    response
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Consent {
    request_id: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    decision: String,
}

async fn consent(
    State(registry): State<std::sync::Arc<Registry>>,
    headers: HeaderMap,
    Form(input): Form<Consent>,
) -> Response {
    let expected_origin = Url::parse(&registry.oauth_authorization_endpoint())
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_default();
    if headers.get(header::ORIGIN).and_then(|h| h.to_str().ok()) != Some(expected_origin.as_str()) {
        return error(StatusCode::FORBIDDEN, "invalid_request");
    }
    let Ok(mut store) = registry.oauth.inner.lock() else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    };
    store.prune();
    let Some(pending) = store.forms.get(&input.request_id) else {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let expected = format!("ifcx_oauth_{}={}", input.request_id, pending.cookie);
    let has_cookie = headers
        .get(header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|h| h.split(';').any(|part| part.trim() == expected));
    if !has_cookie || !matches!(input.decision.as_str(), "allow" | "deny") {
        return error(StatusCode::FORBIDDEN, "invalid_request");
    }
    if input.decision == "allow"
        && registry
            .auth
            .authenticate(&input.username, &input.password)
            .is_err()
    {
        return form(
            &input.request_id,
            pending,
            "Sign-in failed. Check your username and password.",
            &input.username,
        );
    }
    let pending = store
        .forms
        .remove(&input.request_id)
        .expect("validated pending form");
    let mut redirect = Url::parse(&pending.request.redirect_uri).expect("registered redirect");
    redirect
        .query_pairs_mut()
        .append_pair("state", &pending.request.state);
    if input.decision == "deny" {
        redirect
            .query_pairs_mut()
            .append_pair("error", "access_denied");
    } else {
        let code = random();
        redirect.query_pairs_mut().append_pair("code", &code);
        store.codes.insert(
            code,
            Code {
                request: pending.request,
                user: input.username,
                expires: now() + CODE_SECONDS,
            },
        );
    }
    let mut response = hardened(Redirect::to(redirect.as_str()));
    response.headers_mut().insert(
        header::SET_COOKIE,
        format!(
            "ifcx_oauth_{}=; HttpOnly; SameSite=Strict; Path=/oauth/authorize; Max-Age=0",
            input.request_id
        )
        .parse()
        .expect("generated cookie"),
    );
    response
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Exchange {
    grant_type: String,
    client_id: String,
    redirect_uri: String,
    code: String,
    code_verifier: String,
}

async fn exchange(
    State(registry): State<std::sync::Arc<Registry>>,
    Form(input): Form<Exchange>,
) -> Response {
    let code = {
        let Ok(mut store) = registry.oauth.inner.lock() else {
            return error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        };
        store.prune();
        // Consume even failed exchanges: never allow code reuse or verifier guessing.
        store.codes.remove(&input.code)
    };
    let Some(code) = code else {
        return error(StatusCode::BAD_REQUEST, "invalid_grant");
    };
    if input.grant_type != "authorization_code"
        || input.client_id != code.request.client_id
        || input.redirect_uri != code.request.redirect_uri
        || !(43..=128).contains(&input.code_verifier.len())
        || !input
            .code_verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
        || challenge(&input.code_verifier) != code.request.code_challenge
    {
        return error(StatusCode::BAD_REQUEST, "invalid_grant");
    }
    let requested = scopes(&code.request.scope).expect("validated scopes");
    match registry
        .auth
        .issue(&code.user, &requested, crate::auth::TOKEN_SECONDS)
    {
        Ok((token, claims)) => hardened(Json(json!({"token":token,"access_token":token,
            "token_type":"Bearer","expires_in":crate::auth::TOKEN_SECONDS,
            "subject":claims.sub,"access":claims.access}))),
        Err(_) => error(StatusCode::BAD_REQUEST, "invalid_grant"),
    }
}

#[cfg(test)]
#[path = "oauth_tests.rs"]
mod tests;
