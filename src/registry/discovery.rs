//! Authorized standard OCI catalog discovery; no global repository listing.
use super::*;

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
            "Use GET for model listing".into(),
        ));
    }
    let limit = query
        .get("n")
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(ApiError::bad)?
        .unwrap_or(100);
    if limit == 0 || limit > 1000 {
        return Err(ApiError::bad(
            "Catalog page size must be between 1 and 1000",
        ));
    }
    let after = query.get("last").map(String::as_str).unwrap_or("");
    let mut repositories = Vec::new();
    for access in &claims.access {
        if access.kind == "repository"
            && access.name.as_str() > after
            && registry.auth.permits(&claims, &access.name, "pull")?
        {
            let manifests = registry.repo(&access.name).join("manifests");
            if manifests.is_dir() && fs::read_dir(manifests)?.next().transpose()?.is_some() {
                repositories.push(access.name.clone());
            }
        }
    }
    repositories.sort();
    repositories.dedup();
    let more = repositories.len() > limit;
    repositories.truncate(limit);
    let mut response = Json(json!({"repositories":repositories})).into_response();
    if more {
        let last = repositories.last().expect("nonempty catalog page");
        response.headers_mut().insert(
            header::LINK,
            format!("</v2/_catalog?n={limit}&last={last}>; rel=\"next\"")
                .parse()
                .expect("validated catalog link"),
        );
    }
    Ok(response)
}
