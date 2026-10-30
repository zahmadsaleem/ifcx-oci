//! Independent, HttpOnly browser proof used with an active account session.
use crate::{auth::BrowserBinding, registry::Registry};
use anyhow::{ensure, Result};
use axum::http::{header, HeaderMap, HeaderValue};

const COOKIE: &str = "subsoil_browser";

pub(crate) fn binding(registry: &Registry, headers: &HeaderMap) -> Result<Option<BrowserBinding>> {
    let prefix = format!("{COOKIE}=");
    let mut cookies = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|v| v.trim().strip_prefix(&prefix));
    let token = cookies.next();
    ensure!(cookies.next().is_none(), "Ambiguous browser binding");
    Ok(token.and_then(|token| registry.auth.browser_binding(token).ok()))
}

pub(crate) fn cookie(registry: &Registry, token: &str) -> HeaderValue {
    // A session cookie; the signed absolute expiry also bounds browser restoration.
    format!(
        "{COOKIE}={token}; HttpOnly; SameSite=Lax; Path=/{}",
        if registry.secure_cookies() {
            "; Secure"
        } else {
            ""
        }
    )
    .parse()
    .expect("generated browser binding")
}
