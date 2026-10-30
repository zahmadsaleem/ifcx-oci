//! Refresh, remembered browser cookies and session revocation.
use std::sync::Arc;

use axum::{
    extract::{Form, State},
    http::{header, HeaderMap, StatusCode},
    response::Response,
    Json,
};
use reqwest::Url;
use serde::Deserialize;
use serde_json::json;

use super::{error, hardened, Code, Exchange, EXPLORER_CLIENT};
use crate::{
    auth::{now, RefreshSession, SessionTokens},
    registry::Registry,
};

pub(super) const COOKIE: &str = "oci_registry_refresh";

pub(super) fn cookie_name_for(client: &str, default_client: &str) -> String {
    if client == default_client || client == EXPLORER_CLIENT {
        COOKIE.into()
    } else {
        format!("{COOKIE}_{}", hex::encode(client.as_bytes()))
    }
}

fn cookie_name(registry: &Registry, client: &str) -> String {
    let store = registry.oauth.inner.lock().expect("OAuth store lock");
    cookie_name_for(client, &store.client_id)
}

fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, ()> {
    let mut values = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|header| header.to_str().ok())
        .flat_map(|h| h.split(';'))
        .filter_map(|part| part.trim().strip_prefix(&format!("{name}=")));
    let Some(token) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() || token.is_empty() {
        Err(())
    } else {
        Ok(Some(token))
    }
}

fn same_origin(headers: &HeaderMap, redirect: &str) -> bool {
    Url::parse(redirect).is_ok_and(|url| {
        headers.get(header::ORIGIN).and_then(|h| h.to_str().ok())
            == Some(url.origin().ascii_serialization().as_str())
    })
}

fn binding(
    registry: &Registry,
    session: &RefreshSession,
    client_id: &str,
    cookie_mode: bool,
    headers: &HeaderMap,
) -> bool {
    registry.oauth.inner.lock().is_ok_and(|store| {
        store.registered(client_id, &session.redirect_uri, &registry.public_origin())
            && session.client_id == client_id
            && session.remember == cookie_mode
            && (!cookie_mode || same_origin(headers, &session.redirect_uri))
    })
}

fn registered_origin(registry: &Registry, client_id: &str, headers: &HeaderMap) -> bool {
    registry.oauth.inner.lock().is_ok_and(|store| {
        store.clients.get(client_id).is_some_and(|redirects| {
            redirects
                .iter()
                .any(|redirect| same_origin(headers, redirect))
        })
    })
}

fn clear_cookie(response: &mut Response, secure: bool, name: &str) {
    response.headers_mut().insert(
        header::SET_COOKIE,
        format!(
            "{name}=; Path=/oauth/; HttpOnly; SameSite=Strict; Max-Age=0{}",
            if secure { "; Secure" } else { "" }
        )
        .parse()
        .expect("static cookie"),
    );
}

fn secure(session: &RefreshSession) -> bool {
    Url::parse(&session.redirect_uri).is_ok_and(|url| url.scheme() == "https")
}

fn token_value(tokens: &SessionTokens) -> serde_json::Value {
    let remaining = tokens.session.expires.saturating_sub(now());
    let subject = tokens
        .claims
        .share_id
        .as_ref()
        .map(|id| format!("share:{id}"))
        .unwrap_or_else(|| tokens.claims.sub.clone());
    let mut value = json!({"token":tokens.access_token,"access_token":tokens.access_token,
        "token_type":"Bearer","expires_in":tokens.claims.exp.saturating_sub(tokens.claims.iat),
        "subject":subject,"access":tokens.claims.access,
        "permissions":tokens.permissions,"authorization_type":if tokens.claims.share_id.is_some() {"share"} else if tokens.session.root {"session"} else {"access"},
        "remember_me":tokens.session.remember,"session_expires_at":tokens.session.expires,
        "session_expires_in":remaining,"publication_headers":crate::registry::publication_headers()});
    if !tokens.session.remember {
        value["refresh_token"] = tokens.refresh_token.clone().into();
    }
    if let Some(id) = &tokens.claims.share_id {
        value["share_id"] = id.clone().into();
    }
    value
}

fn reply(tokens: SessionTokens, clear_previous: bool, name: &str) -> Response {
    let remaining = tokens.session.expires.saturating_sub(now());
    let value = token_value(&tokens);
    let mut response = hardened(Json(value));
    if tokens.session.remember {
        response.headers_mut().insert(
            header::SET_COOKIE,
            format!(
                "{name}={}; Path=/oauth/; HttpOnly; SameSite=Strict; Max-Age={remaining}{}",
                tokens.refresh_token,
                if secure(&tokens.session) {
                    "; Secure"
                } else {
                    ""
                }
            )
            .parse()
            .expect("generated refresh cookie"),
        );
    } else if clear_previous {
        clear_cookie(&mut response, secure(&tokens.session), name);
    }
    response
}

pub(super) fn initial(
    registry: &Registry,
    headers: &HeaderMap,
    mut code: Code,
    requested: &[String],
) -> Response {
    let name = cookie_name(registry, &code.request.client_id);
    if let Some(launch) = code.launch.take() {
        return match registry.launch_session(
            launch,
            &code.request.client_id,
            &code.request.redirect_uri,
        ) {
            Ok((tokens, artifact)) => {
                let mut value = token_value(&tokens);
                value["open_artifact"] = serde_json::to_value(artifact).expect("launch context");
                hardened(Json(value))
            }
            Err(_) => error(StatusCode::BAD_REQUEST, "invalid_grant"),
        };
    }
    if code.remember && !same_origin(headers, &code.request.redirect_uri) {
        return error(StatusCode::FORBIDDEN, "invalid_request");
    }
    let explorer = code.request.client_id == EXPLORER_CLIENT;
    // Tab-only explorer sessions leave other applications' remembered cookies intact.
    let previous = if explorer {
        None
    } else {
        match cookie(headers, &name) {
            Ok(value) => value,
            Err(()) => return error(StatusCode::BAD_REQUEST, "invalid_request"),
        }
    };
    if let Some(previous) = previous {
        if !same_origin(headers, &code.request.redirect_uri) {
            return error(StatusCode::FORBIDDEN, "invalid_request");
        }
        if registry
            .auth
            .revoke_session(previous, &code.request.client_id)
            .is_err()
        {
            return error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    }
    match registry.auth.start_approved_session(
        (&code.user, code.permissions),
        requested,
        &code.request.client_id,
        &code.request.redirect_uri,
        code.remember,
    ) {
        Ok(tokens) => reply(tokens, !explorer, &name),
        Err(_) => error(StatusCode::BAD_REQUEST, "invalid_grant"),
    }
}

pub(super) fn refresh(registry: &Registry, headers: &HeaderMap, input: &Exchange) -> Response {
    let name = cookie_name(registry, &input.client_id);
    let cookie_mode = input.refresh_token.is_none();
    // Reject unknown origins before consuming a token or mutating browser cookies.
    if cookie_mode && !registered_origin(registry, &input.client_id, headers) {
        return error(StatusCode::FORBIDDEN, "invalid_request");
    }
    let token = match input.refresh_token.as_deref() {
        Some(value) => Some(value),
        None => match cookie(headers, &name) {
            Ok(value) => value,
            Err(()) => return error(StatusCode::BAD_REQUEST, "invalid_request"),
        },
    };
    let Some(token) = token else {
        return error(StatusCode::BAD_REQUEST, "invalid_grant");
    };
    let session = match registry.auth.refresh_session(token) {
        Ok(Some(session)) => session,
        Ok(None) => {
            let mut response = error(StatusCode::BAD_REQUEST, "invalid_grant");
            if cookie_mode {
                clear_cookie(
                    &mut response,
                    headers
                        .get(header::ORIGIN)
                        .and_then(|h| h.to_str().ok())
                        .is_some_and(|o| o.starts_with("https://")),
                    &name,
                );
            }
            return response;
        }
        Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    };
    if !binding(registry, &session, &input.client_id, cookie_mode, headers) {
        return error(StatusCode::BAD_REQUEST, "invalid_grant");
    }
    match registry.auth.rotate_session(token, &input.client_id) {
        Ok(tokens) => reply(tokens, false, &name),
        Err(problem) => {
            if problem.downcast_ref::<rusqlite::Error>().is_some() {
                return error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
            }
            let mut response = error(StatusCode::BAD_REQUEST, "invalid_grant");
            if cookie_mode {
                clear_cookie(&mut response, secure(&session), &name);
            }
            response
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Revocation {
    client_id: String,
    #[serde(default)]
    token: Option<String>,
}

pub(super) async fn revoke(
    State(registry): State<Arc<Registry>>,
    headers: HeaderMap,
    Form(input): Form<Revocation>,
) -> Response {
    let name = cookie_name(&registry, &input.client_id);
    let cookie_mode = input.token.is_none();
    if cookie_mode && !registered_origin(&registry, &input.client_id, &headers) {
        return error(StatusCode::FORBIDDEN, "invalid_request");
    }
    let token = match input.token.as_deref() {
        Some(value) => Some(value),
        None => match cookie(&headers, &name) {
            Ok(value) => value,
            Err(()) => return error(StatusCode::BAD_REQUEST, "invalid_request"),
        },
    };
    let secure_origin = headers
        .get(header::ORIGIN)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|o| o.starts_with("https://"));
    if let Some(token) = token {
        let session = match registry.auth.refresh_session(token) {
            Ok(session) => session,
            Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
        };
        if let Some(session) = session {
            if !binding(&registry, &session, &input.client_id, cookie_mode, &headers) {
                return error(StatusCode::BAD_REQUEST, "invalid_grant");
            }
            if registry
                .auth
                .revoke_session(token, &input.client_id)
                .is_err()
            {
                return error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
            }
        }
    }
    let mut response = hardened(StatusCode::OK);
    if cookie_mode {
        clear_cookie(&mut response, secure_origin, &name);
    }
    response
}
