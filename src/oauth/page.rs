//! Registry-owned sign-in page and browser navigation policy.
use axum::response::{Html, Response};
use reqwest::Url;

use super::{hardened, Pending, EXPLORER_CLIENT};

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub(super) fn form(
    id: &str,
    pending: &Pending,
    message: &str,
    username: &str,
    remember: bool,
) -> Response {
    let callback_origin = Url::parse(&pending.request.redirect_uri)
        .expect("registered redirect")
        .origin()
        .ascii_serialization();
    let actions: Vec<_> = pending
        .request
        .scope
        .split_whitespace()
        .flat_map(|scope| {
            if scope == crate::auth::SESSION_SCOPE {
                vec!["session"]
            } else {
                scope.rsplit(':').next().unwrap_or("").split(',').collect()
            }
        })
        .collect();
    let access = match (actions.contains(&"pull"), actions.contains(&"push")) {
        (true, true) => "View files and add new versions",
        (true, false) => "View the files shared with you",
        (false, true) => "Add files and new versions",
        _ => "Connect your account",
    };
    let explorer = pending.request.client_id == EXPLORER_CLIENT;
    let access = if explorer {
        "Browse your files without making changes."
    } else if actions.contains(&"session") {
        "This app can view and add files where your account already allows it, including new folders covered by your current access. You'll be asked again before it can do more."
    } else {
        access
    };
    let html = include_str!("login.html")
        .replace("{{remember_hidden}}", if explorer { "hidden" } else { "" })
        .replace(
            "{{remember_disabled}}",
            if explorer { "disabled" } else { "" },
        )
        .replace(
            "{{remember_checked}}",
            if remember { "checked" } else { "" },
        )
        .replace(
            "{{client}}",
            &escape(if explorer {
                "your files"
            } else {
                &pending.request.client_id
            }),
        )
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
        "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; form-action 'self' {callback_origin}; frame-ancestors 'none'; base-uri 'none'"
    ).parse().expect("validated callback origin"));
    response
}
