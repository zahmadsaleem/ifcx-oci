//! Registry-owned sign-in page and browser navigation policy.
use axum::response::{Html, Response};
use reqwest::Url;

use super::{hardened, Pending};

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub(super) fn form(id: &str, pending: &Pending, message: &str, username: &str) -> Response {
    let callback_origin = Url::parse(&pending.request.redirect_uri)
        .expect("registered redirect")
        .origin()
        .ascii_serialization();
    let actions: Vec<_> = pending
        .request
        .scope
        .split_whitespace()
        .flat_map(|scope| {
            if scope == "registry:catalog:read" {
                vec!["pull", "push"]
            } else {
                scope.rsplit(':').next().unwrap_or("").split(',').collect()
            }
        })
        .collect();
    let access = match (actions.contains(&"pull"), actions.contains(&"push")) {
        (true, true) => "View models and publish updates",
        (true, false) => "View your models",
        (false, true) => "Publish model updates",
        _ => "Connect your account",
    };
    let html = include_str!("login.html")
        .replace("{{client}}", &escape(&pending.request.client_id))
        .replace("{{access}}", access)
        .replace("{{error}}", &escape(message))
        .replace("{{request_id}}", &escape(id))
        .replace(
            "{{destination}}",
            &escape(callback_origin.split_once("://").expect("HTTP origin").1),
        )
        .replace("{{username}}", &escape(username));
    let mut response = hardened(Html(html));
    // no-referrer makes navigation POSTs serialize Origin as null. Keep Origin
    // on our same-origin form while omitting referrers on the callback hop.
    response.headers_mut().insert(
        "referrer-policy",
        "same-origin".parse().expect("static header"),
    );
    // Chromium applies form-action to the 303 destination too. Allow only this
    // registered callback's origin in addition to our own credential endpoint.
    response.headers_mut().insert("content-security-policy", format!(
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' {callback_origin}; frame-ancestors 'none'; base-uri 'none'"
    ).parse().expect("validated callback origin"));
    response
}
