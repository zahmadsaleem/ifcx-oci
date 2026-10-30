//! Authorized Distribution catalog discovery; no global repository listing.
use super::*;

/// Optional name filtering is a Subsoil extension; n/last use Distribution cursors.
pub(super) fn page(
    mut entries: Vec<String>,
    query: &HashMap<String, String>,
    default_limit: usize,
    endpoint: &str,
) -> std::result::Result<(Vec<String>, Option<String>), ApiError> {
    let limit = query
        .get("n")
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(ApiError::bad)?
        .unwrap_or(default_limit);
    if limit == 0 || (query.contains_key("n") && limit > 1000) {
        return Err(ApiError::bad("Page size must be between 1 and 1000"));
    }
    let after = query.get("last").map(String::as_str).unwrap_or("");
    let filter = query
        .get("q")
        .map(|q| q.to_ascii_lowercase())
        .unwrap_or_default();
    entries.retain(|entry| entry.as_str() > after && entry.to_ascii_lowercase().contains(&filter));
    entries.sort();
    entries.dedup();
    let more = entries.len() > limit;
    entries.truncate(limit);
    let next = if more {
        let mut url = reqwest::Url::parse("http://local").expect("static URL");
        url.set_path(endpoint);
        url.query_pairs_mut()
            .append_pair("n", &limit.to_string())
            .append_pair("last", entries.last().expect("nonempty page"));
        if !filter.is_empty() {
            url.query_pairs_mut().append_pair("q", &filter);
        }
        Some(format!(
            "<{}?{}>; rel=\"next\"",
            url.path(),
            url.query().expect("page query")
        ))
    } else {
        None
    };
    Ok((entries, next))
}

pub(super) fn listing(body: Value, next: Option<String>) -> Response {
    let mut response = Json(body).into_response();
    if let Some(next) = next {
        response
            .headers_mut()
            .insert(header::LINK, next.parse().expect("encoded pagination link"));
    }
    response
}

pub(super) async fn catalog(
    State(registry): State<Arc<Registry>>,
    Query(query): Query<HashMap<String, String>>,
    method: Method,
    headers: HeaderMap,
) -> std::result::Result<Response, ApiError> {
    let claims = match authorization(&registry, &headers, None) {
        Ok(claims) => claims,
        Err(response) => return Ok(*response),
    };
    if !claims.access.iter().any(|access| {
        access.kind == "registry"
            && access.name == "catalog"
            && access.actions.iter().any(|action| action == "read")
    }) {
        return Ok(challenge(&registry, None, true));
    }
    if method != Method::GET {
        return Err(ApiError(
            StatusCode::METHOD_NOT_ALLOWED,
            "UNSUPPORTED",
            "Use GET for repository listing".into(),
        ));
    }
    let mut repositories = Vec::new();
    let layers = registry.auth.limits(&claims)?;
    for repo in registry.repositories()? {
        if !registry.visible_roots(&layers, &repo)?.is_empty() {
            repositories.push(repo);
        }
    }
    let (repositories, next) = page(repositories, &query, 100, "/v2/_catalog")?;
    Ok(listing(json!({"repositories":repositories}), next))
}
