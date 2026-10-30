//! Small, same-origin registry explorer; artifact access uses the existing API.
use super::*;
use axum::response::Html;

pub(super) fn router() -> Router<Arc<Registry>> {
    Router::new()
        .route("/explore", get(page))
        .route("/explore/app.js", get(script))
        .route("/explore/style.css", get(style))
}

fn hardened(body: impl IntoResponse) -> Response {
    let mut response = body.into_response();
    for (name, value) in [
        ("cache-control", "no-store"),
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("content-security-policy", "default-src 'none'; img-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"),
    ] {
        response.headers_mut().insert(name, value.parse().expect("static header"));
    }
    response
}

async fn page() -> Response {
    hardened(Html(include_str!("explorer.html")))
}

async fn script() -> Response {
    hardened((
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("explorer.js"),
    ))
}

async fn style() -> Response {
    hardened((
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("explorer.css"),
    ))
}
