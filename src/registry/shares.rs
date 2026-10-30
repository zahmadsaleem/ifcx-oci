//! Sharing API: fragment secrets are redeemed over POST and never persisted in cleartext.
use super::*;
use crate::{
    auth::{Claims, ShareBinding, ShareCreated, ShareSpec},
    policy::{self, GrantSet},
};
use axum::routing::post;
use serde::Deserialize;

pub(super) fn router() -> Router<Arc<Registry>> {
    Router::new()
        .route("/shares", get(list).post(create))
        .route("/shares/redeem", post(redeem))
        .route("/shares/{id}/revoke", post(revoke))
        .layer(DefaultBodyLimit::max(256 * 1024))
}

fn no_store(value: Value) -> Response {
    let mut response = Json(value).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        "no-store".parse().expect("static header"),
    );
    response.headers_mut().insert(
        "referrer-policy",
        "no-referrer".parse().expect("static header"),
    );
    response
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u32,
    registry: String,
    grants: Vec<policy::Grant>,
    ttl: u64,
    #[serde(default)]
    binding: ShareBinding,
}

impl Registry {
    /// Local operator equivalent of POST /shares. Snapshot resolution is serialized with publication.
    pub async fn create_share(
        &self,
        user: &str,
        policy: &GrantSet,
        ttl: u64,
        binding: ShareBinding,
    ) -> Result<ShareCreated> {
        ensure!(policy.version == 1, "Unsupported grant version");
        self.auth
            .validate_registry(&policy::registry_name(&policy.registry)?)?;
        let _guard = self.mutation.lock().await;
        let limits = vec![self.auth.grants(user)?];
        self.resolve_share(
            user,
            ShareSpec {
                grants: policy.grants.clone(),
                ttl,
                binding,
            },
            limits,
        )
    }
    fn resolve_share(
        &self,
        user: &str,
        spec: ShareSpec,
        limits: Vec<Vec<policy::Grant>>,
    ) -> Result<ShareCreated> {
        policy::validate(&spec.grants, false)?;
        ensure!(
            limits.iter().all(|p| policy::delegates(p, &spec.grants)),
            "Share exceeds approved permissions"
        );
        let snapshot = if spec.binding == ShareBinding::Snapshot {
            Some(self.snapshot(limits.clone(), &spec.grants)?)
        } else {
            None
        };
        self.auth.create_share(
            user,
            spec,
            limits,
            snapshot,
            self.share_max_age
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    }
}

fn owner(registry: &Registry, headers: &HeaderMap) -> std::result::Result<Claims, Box<Response>> {
    let claims = authorization(registry, headers, None)?;
    if claims.share_id.is_some() || !claims.root || claims.sid.is_none() {
        return Err(Box::new(challenge(registry, None, true)));
    }
    Ok(claims)
}

async fn create(
    State(registry): State<Arc<Registry>>,
    headers: HeaderMap,
    Json(request): Json<Request>,
) -> std::result::Result<Response, ApiError> {
    let claims = match owner(&registry, &headers) {
        Ok(c) => c,
        Err(r) => return Ok(*r),
    };
    let origin = reqwest::Url::parse(&registry.public_origin()).map_err(ApiError::bad)?;
    let host = origin.authority();
    if request.version != 1 || policy::registry_name(&request.registry)? != host {
        return Err(ApiError::bad(
            "Grant registry/version does not match this endpoint",
        ));
    }
    let limits = registry.auth.delegation_limits(&claims)?;
    let _guard = registry.mutation.lock().await;
    let created = registry.resolve_share(
        &claims.sub,
        ShareSpec {
            grants: request.grants,
            ttl: request.ttl,
            binding: request.binding,
        },
        limits,
    )?;
    let mut value = serde_json::to_value(&created).map_err(ApiError::bad)?;
    value["url"] = format!(
        "{}/share#secret={}",
        registry.public_origin(),
        created.secret
    )
    .into();
    Ok(no_store(value))
}

async fn list(
    State(registry): State<Arc<Registry>>,
    headers: HeaderMap,
) -> std::result::Result<Response, ApiError> {
    let claims = match owner(&registry, &headers) {
        Ok(c) => c,
        Err(r) => return Ok(*r),
    };
    Ok(no_store(
        json!({"shares":registry.auth.list_shares(&claims.sub)?}),
    ))
}

async fn revoke(
    State(registry): State<Arc<Registry>>,
    RoutePath(id): RoutePath<String>,
    headers: HeaderMap,
) -> std::result::Result<Response, ApiError> {
    let claims = match owner(&registry, &headers) {
        Ok(c) => c,
        Err(r) => return Ok(*r),
    };
    registry.auth.revoke_share(&claims.sub, &id)?;
    Ok(no_store(json!({"revoked":true})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Redemption {
    secret: String,
}

async fn redeem(
    State(registry): State<Arc<Registry>>,
    Json(request): Json<Redemption>,
) -> Response {
    match registry.auth.redeem_share(&request.secret) {
        Ok((token, claims, share)) => no_store(
            json!({"token":token,"access_token":token,"token_type":"Bearer",
            "subject":format!("share:{}",share.id),"share_id":share.id,"authorization_type":"share","access":claims.access,"permissions":share.grants,
            "expires_in":claims.exp.saturating_sub(claims.iat),"remember_me":false,"publication_headers":super::publication_headers(),
            "session_expires_at":share.expires_at,"session_expires_in":share.expires_at.saturating_sub(crate::auth::now())}),
        ),
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            no_store(json!({"error":"invalid_grant"})),
        )
            .into_response(),
    }
}

pub(super) async fn landing() -> Response {
    let mut response = axum::response::Html(include_str!("share.html")).into_response();
    for (name,value) in [("cache-control","no-store"),("referrer-policy","no-referrer"),("x-content-type-options","nosniff"),("content-security-policy","default-src 'none'; img-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")] {
        response.headers_mut().insert(header::HeaderName::from_static(name),value.parse().expect("static header"));
    }
    response
}
