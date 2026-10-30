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

use crate::{
    auth::{now, PasswordLoginError},
    registry::Registry,
};

mod page;
mod session;
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

#[derive(Clone)]
struct Pending {
    request: Authorization,
    cookie: String,
    expires: u64,
}

struct Code {
    permissions: Vec<crate::policy::Grant>,
    request: Authorization,
    user: String,
    expires: u64,
    remember: bool,
}

impl Store {
    fn prune(&mut self) {
        let time = now();
        self.forms.retain(|_, p| p.expires > time);
        self.codes.retain(|_, p| p.expires > time);
    }
}

impl OAuth {
    pub(crate) fn validate_transport(&self, https: bool) -> Result<()> {
        let store = self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("OAuth store lock failed"))?;
        ensure!(
            !https
                || store
                    .redirects
                    .iter()
                    .all(|uri| Url::parse(uri).is_ok_and(|u| u.scheme() == "https")),
            "An HTTPS public URL requires exact HTTPS OAuth callback URLs"
        );
        Ok(())
    }
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
    router_with_cors(None)
}

pub(crate) fn router_with_cors(
    cors: Option<tower_http::cors::CorsLayer>,
) -> Router<std::sync::Arc<Registry>> {
    let mut api = Router::new()
        .route("/oauth/config", get(config))
        .route("/oauth/token", post(exchange))
        .route("/oauth/revoke", post(session::revoke));
    if let Some(cors) = cors {
        api = api.layer(cors);
    }
    api.route("/oauth/authorize", get(authorize).post(consent))
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
        "token_endpoint":"/oauth/token","session_scope":crate::auth::SESSION_SCOPE,"scoped_token_endpoint":"/token","redirect_uris":store.redirects,
        "refresh_cookie_name":session::COOKIE,"revocation_endpoint":"/oauth/revoke",
        "session_max_age":crate::auth::SESSION_SECONDS,"remembered_session_max_age":crate::auth::REMEMBER_SECONDS,
        "code_challenge_methods_supported":["S256"]}),
    ))
}

fn scopes(value: &str) -> Result<Vec<String>> {
    let scopes: Vec<_> = value.split_whitespace().map(str::to_string).collect();
    if scopes == [crate::auth::SESSION_SCOPE] {
        return Ok(scopes);
    }
    for scope in &scopes {
        if matches!(
            scope.as_str(),
            "registry:catalog:read" | "registry:catalog:*" | crate::auth::CATALOG_GRANTS_SCOPE
        ) {
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
    let mut response = form(&id, &pending, "", "", false);
    response.headers_mut().insert(header::SET_COOKIE,
        format!("ifcx_oauth_{id}={}; HttpOnly; SameSite=Strict; Path=/oauth/authorize; Max-Age={FORM_SECONDS}{}", pending.cookie, if registry.secure_cookies() { "; Secure" } else { "" })
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
    #[serde(default)]
    remember_me: bool,
}

async fn consent(
    State(registry): State<std::sync::Arc<Registry>>,
    headers: HeaderMap,
    Form(input): Form<Consent>,
) -> Response {
    let expected_origin = registry.public_origin();
    if headers.get(header::ORIGIN).and_then(|h| h.to_str().ok()) != Some(expected_origin.as_str()) {
        return error(StatusCode::FORBIDDEN, "invalid_request");
    }
    let pending = {
        let Ok(mut store) = registry.oauth.inner.lock() else {
            return error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        };
        store.prune();
        let Some(pending) = store.forms.get(&input.request_id) else {
            return error(StatusCode::BAD_REQUEST, "invalid_request");
        };
        pending.clone()
    };
    let expected = format!("ifcx_oauth_{}={}", input.request_id, pending.cookie);
    let has_cookie = headers
        .get(header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|h| h.split(';').any(|part| part.trim() == expected));
    if !has_cookie || !matches!(input.decision.as_str(), "allow" | "deny") {
        return error(StatusCode::FORBIDDEN, "invalid_request");
    }
    if input.decision == "allow" {
        match registry
            .password_login(input.username.clone(), input.password)
            .await
        {
            Ok(()) => {}
            Err(PasswordLoginError::Throttled(seconds)) => {
                return hardened(crate::registry::login_throttled(seconds))
            }
            Err(PasswordLoginError::Unavailable) => {
                return error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
            }
            Err(PasswordLoginError::InvalidCredentials) => {
                return form(
                    &input.request_id,
                    &pending,
                    "Sign-in failed. Check your username and password.",
                    &input.username,
                    input.remember_me,
                )
            }
        }
    }
    let Ok(mut store) = registry.oauth.inner.lock() else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    };
    store.prune();
    let Some(pending) = store.forms.remove(&input.request_id) else {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let mut redirect = Url::parse(&pending.request.redirect_uri).expect("registered redirect");
    redirect
        .query_pairs_mut()
        .append_pair("state", &pending.request.state);
    if input.decision == "deny" {
        redirect
            .query_pairs_mut()
            .append_pair("error", "access_denied");
    } else {
        let permissions = match registry.auth.grants(&input.username) {
            Ok(p) => p,
            Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
        };
        let code = random();
        redirect.query_pairs_mut().append_pair("code", &code);
        store.codes.insert(
            code,
            Code {
                permissions,
                request: pending.request,
                user: input.username,
                expires: now() + CODE_SECONDS,
                remember: input.remember_me,
            },
        );
    }
    let mut response = hardened(Redirect::to(redirect.as_str()));
    response.headers_mut().insert(
        header::SET_COOKIE,
        format!(
            "ifcx_oauth_{}=; HttpOnly; SameSite=Strict; Path=/oauth/authorize; Max-Age=0{}",
            input.request_id,
            if registry.secure_cookies() {
                "; Secure"
            } else {
                ""
            }
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
    #[serde(default)]
    redirect_uri: String,
    #[serde(default)]
    code: String,
    #[serde(default)]
    code_verifier: String,
    #[serde(default)]
    refresh_token: Option<String>,
}

async fn exchange(
    State(registry): State<std::sync::Arc<Registry>>,
    headers: HeaderMap,
    Form(input): Form<Exchange>,
) -> Response {
    if input.grant_type == "refresh_token" {
        if !input.code.is_empty()
            || !input.code_verifier.is_empty()
            || !input.redirect_uri.is_empty()
        {
            return error(StatusCode::BAD_REQUEST, "invalid_request");
        }
        return session::refresh(&registry, &headers, &input);
    }
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
        || input.refresh_token.is_some()
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
    session::initial(&registry, &headers, code, &requested)
}

#[cfg(test)]
#[path = "oauth_tests.rs"]
mod tests;
