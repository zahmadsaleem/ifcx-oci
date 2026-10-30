//! Public, embedded brand assets shared by the registry's browser pages.
use super::*;

pub(super) fn router() -> Router<Arc<Registry>> {
    Router::new()
        .route("/brand/logo.svg", get(logo))
        .route("/brand/symbol.svg", get(symbol))
}

fn svg(body: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, "image/svg+xml"),
            (header::CACHE_CONTROL, "no-cache"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        body,
    )
        .into_response()
}

async fn logo() -> Response {
    svg(include_str!("../../assets/brand/subsoil-logo.svg"))
}

async fn symbol() -> Response {
    svg(include_str!("../../assets/brand/subsoil-symbol.svg"))
}
