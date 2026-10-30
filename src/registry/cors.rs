//! Opt-in browser access to registry APIs. Credential pages remain registry-owned.
use axum::http::{header, HeaderValue, Method};
use reqwest::Url;
use tower_http::cors::{AllowOrigin, CorsLayer};

use super::*;

impl Registry {
    /// Configure exact application origins before building the router or serving.
    /// An empty list disables CORS. OAuth callback registration is independent.
    pub fn set_cors_origins(&self, origins: &[String]) -> Result<()> {
        let mut allowed = Vec::new();
        for origin in origins {
            let url = Url::parse(origin)?;
            let host = url.host_str().unwrap_or("").trim_matches(['[', ']']);
            let loopback = host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback());
            ensure!(
                !origin.chars().any(|c| c.is_whitespace() || c.is_control())
                    && !origin.contains('\\')
                    && (url.scheme() == "https" || (url.scheme() == "http" && loopback))
                    && url.host_str().is_some()
                    && !host.contains('*')
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.path() == "/"
                    && url.query().is_none()
                    && url.fragment().is_none(),
                "CORS origin must be an exact HTTPS origin (or loopback HTTP) without credentials, path, query or fragment"
            );
            allowed.push(HeaderValue::from_str(&url.origin().ascii_serialization())?);
        }
        let cors = (!allowed.is_empty()).then(|| {
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(allowed))
                .allow_credentials(true)
                .allow_methods([
                    Method::GET,
                    Method::HEAD,
                    Method::POST,
                    Method::PUT,
                    Method::PATCH,
                    Method::DELETE,
                    Method::OPTIONS,
                ])
                .allow_headers([
                    header::AUTHORIZATION,
                    header::ACCEPT,
                    header::CONTENT_TYPE,
                    header::CONTENT_RANGE,
                    header::RANGE,
                ])
                .expose_headers([
                    header::WWW_AUTHENTICATE,
                    header::LOCATION,
                    header::LINK,
                    header::RANGE,
                    header::CONTENT_RANGE,
                    header::RETRY_AFTER,
                    header::HeaderName::from_static("docker-content-digest"),
                    header::HeaderName::from_static("docker-distribution-api-version"),
                    header::HeaderName::from_static("docker-upload-uuid"),
                    header::HeaderName::from_static("subsoil-registry-publisher"),
                    header::HeaderName::from_static("subsoil-registry-share-id"),
                    header::HeaderName::from_static("subsoil-registry-created-by"),
                    header::HeaderName::from_static("subsoil-registry-pushed-at"),
                ])
        });
        *self
            .cors
            .write()
            .map_err(|_| anyhow::anyhow!("CORS configuration lock failed"))? = cors;
        Ok(())
    }
}
