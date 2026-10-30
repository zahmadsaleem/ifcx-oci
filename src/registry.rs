//! Persistent single-server registry implementing the OCI artifact push/pull path.
use std::{
    collections::HashMap,
    fs,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{ensure, Context, Result};
use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Path as RoutePath, Query, RawQuery, State},
    http::{header, HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{any, get},
    Json, Router,
};
use base64::Engine;
use bytes::Bytes;
use serde_json::{json, Value};
use sha2::Digest;
use tokio::{net::TcpListener, sync::Mutex};
use uuid::Uuid;

use crate::auth::{Auth, PasswordLoginError, TOKEN_SECONDS};
use crate::release::{digest, digest_hex};
mod access;
mod brand;
mod cors;
mod discovery;
mod explorer;
pub(crate) mod open_artifact;
mod public_url;
mod publication;
mod shares;

/// Optional metadata for browser clients; publication headers are a Subsoil extension.
pub(crate) fn publication_headers() -> serde_json::Value {
    json!({"publisher":publication::PUBLISHER_HEADER,"pushed_at":publication::PUSHED_AT_HEADER})
}

pub const MANIFEST_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const MAX_BLOB: usize = 512 * 1024 * 1024;

pub struct Registry {
    root: PathBuf,
    pub auth: Auth,
    pub oauth: crate::oauth::OAuth,
    applications: std::sync::RwLock<crate::applications::Applications>,
    launches: std::sync::Mutex<HashMap<String, open_artifact::Launch>>,
    public_url: std::sync::RwLock<Option<reqwest::Url>>,
    cors: std::sync::RwLock<Option<tower_http::cors::CorsLayer>>,
    mutation: Mutex<()>,
    pub share_max_age: std::sync::atomic::AtomicU64,
}

impl Registry {
    pub fn open(root: impl AsRef<Path>) -> Result<Arc<Self>> {
        let root = root.as_ref();
        if root.exists() && !root.join("registry.json").exists() {
            ensure!(
                root.is_dir() && fs::read_dir(root)?.next().is_none(),
                "Registry storage must be new, empty, or an existing registry store"
            );
        }
        fs::create_dir_all(root)?;
        if root.join("registry.json").exists() {
            let marker: Value = serde_json::from_slice(&fs::read(root.join("registry.json"))?)?;
            ensure!(
                marker["format"] == "subsoil-registry/2",
                "Unknown registry store format"
            );
        } else {
            atomic_write(
                &root.join("registry.json"),
                b"{\"format\":\"subsoil-registry/2\"}\n",
            )?;
        }
        fs::create_dir_all(root.join("blobs/sha256"))?;
        fs::create_dir_all(root.join("repositories"))?;
        Ok(Arc::new(Self {
            root: root.into(),
            auth: Auth::open(root)?,
            oauth: crate::oauth::OAuth::default(),
            applications: std::sync::RwLock::new(crate::applications::Applications::default()),
            launches: std::sync::Mutex::new(HashMap::new()),
            public_url: std::sync::RwLock::new(None),
            cors: std::sync::RwLock::new(None),
            mutation: Mutex::new(()),
            share_max_age: std::sync::atomic::AtomicU64::new(
                crate::auth::DEFAULT_SHARE_MAX_SECONDS,
            ),
        }))
    }
    pub fn oauth_authorization_endpoint(&self) -> String {
        format!("{}/oauth/authorize", self.public_origin())
    }
    fn repo(&self, repo: &str) -> PathBuf {
        self.root
            .join("repositories")
            .join(hex::encode(repo.as_bytes()))
    }
    fn blob(&self, value: &str) -> Result<PathBuf> {
        Ok(self.root.join("blobs/sha256").join(digest_hex(value)?))
    }
    fn membership(&self, repo: &str, value: &str) -> Result<PathBuf> {
        Ok(self.repo(repo).join("blobs").join(digest_hex(value)?))
    }
    fn upload(&self, repo: &str, id: &str) -> Result<PathBuf> {
        Uuid::parse_str(id).context("Invalid upload ID")?;
        Ok(self.repo(repo).join("uploads").join(id))
    }
}

pub fn router(registry: Arc<Registry>) -> Router {
    let cors = registry
        .cors
        .read()
        .expect("CORS configuration lock")
        .clone();
    let mut api = Router::new()
        .merge(shares::router())
        .merge(open_artifact::router())
        .route("/token", any(token))
        .route("/v2/", any(base))
        .route("/v2", any(base))
        .route("/v2/_catalog", any(discovery::catalog))
        .route("/v2/{*path}", any(endpoint));
    if let Some(cors) = &cors {
        api = api.layer(cors.clone());
    }
    api.merge(crate::oauth::router_with_cors(cors))
        .merge(brand::router())
        .merge(explorer::router())
        .route("/share", get(shares::landing))
        .route("/healthz", get(|| async { StatusCode::OK }))
        .route("/readyz", get(ready))
        .layer(DefaultBodyLimit::max(MAX_BLOB))
        .with_state(registry)
}

pub async fn serve(listener: TcpListener, registry: Arc<Registry>) -> Result<()> {
    serve_with_shutdown(listener, registry, std::future::pending()).await
}

pub async fn serve_with_shutdown(
    listener: TcpListener,
    registry: Arc<Registry>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    registry.configure_listener(listener.local_addr()?)?;
    axum::serve(listener, router(registry))
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}

pub async fn bind(address: SocketAddr) -> Result<TcpListener> {
    Ok(TcpListener::bind(address).await?)
}

async fn ready(State(registry): State<Arc<Registry>>) -> StatusCode {
    let ready = tokio::task::spawn_blocking(move || -> Result<()> {
        registry.auth.check_ready()?;
        // Probe the mounted filesystem, including the artifact locations, with
        // real I/O. Temporary files disappear even when a probe fails.
        fs::read(registry.root.join("registry.json"))?;
        for directory in [
            registry.root.clone(),
            registry.root.join("blobs/sha256"),
            registry.root.join("repositories"),
        ] {
            let mut probe = tempfile::NamedTempFile::new_in(directory)?;
            probe.write_all(b"ready")?;
            probe.as_file().sync_all()?;
            ensure!(fs::read(probe.path())? == b"ready", "Storage probe failed");
        }
        Ok(())
    })
    .await;
    if matches!(ready, Ok(Ok(()))) {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("Missing storage parent")?;
    fs::create_dir_all(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|error| error.error)?;
    Ok(())
}

#[derive(Debug)]
struct ApiError(StatusCode, &'static str, String);
impl ApiError {
    fn bad(message: impl ToString) -> Self {
        Self(StatusCode::BAD_REQUEST, "NAME_INVALID", message.to_string())
    }
    fn missing(code: &'static str) -> Self {
        Self(
            StatusCode::NOT_FOUND,
            code,
            "Requested registry object was not found".into(),
        )
    }
}
impl From<anyhow::Error> for ApiError {
    fn from(error: anyhow::Error) -> Self {
        Self::bad(error)
    }
}
impl From<std::io::Error> for ApiError {
    fn from(error: std::io::Error) -> Self {
        Self(
            StatusCode::INTERNAL_SERVER_ERROR,
            "UNKNOWN",
            error.kind().to_string(),
        )
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (
            self.0,
            Json(json!({"errors":[{"code":self.1,"message":self.2}]})),
        )
            .into_response();
        response.headers_mut().insert(
            "docker-distribution-api-version",
            "registry/2.0".parse().expect("static header"),
        );
        response
    }
}

fn challenge(registry: &Registry, scope: Option<(&str, &str)>, denied: bool) -> Response {
    let status = if denied {
        StatusCode::FORBIDDEN
    } else {
        StatusCode::UNAUTHORIZED
    };
    let code = if denied { "DENIED" } else { "UNAUTHORIZED" };
    let mut response = ApiError(
        status,
        code,
        if denied {
            "Token does not grant this repository/action"
        } else {
            "A valid registry bearer token is required"
        }
        .into(),
    )
    .into_response();
    let realm = format!("{}/token", registry.public_origin());
    let mut header = format!(
        "Bearer realm=\"{realm}\",service=\"{}\"",
        registry.auth.service
    );
    if let Some((repo, action)) = scope {
        header.push_str(&format!(",scope=\"repository:{repo}:{action}\""));
    }
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        header.parse().expect("local auth header"),
    );
    response
}

fn authorization(
    registry: &Registry,
    headers: &HeaderMap,
    scope: Option<(&str, &str)>,
) -> std::result::Result<crate::auth::Claims, Box<Response>> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let Some(claims) = token.and_then(|t| registry.auth.validate(t).ok()) else {
        return Err(Box::new(challenge(registry, scope, false)));
    };
    if let Some((repo, action)) = scope {
        if !registry
            .auth
            .permits(&claims, repo, action)
            .unwrap_or(false)
        {
            return Err(Box::new(challenge(registry, scope, true)));
        }
    }
    Ok(claims)
}

fn token_reply(token: String, claims: crate::auth::Claims) -> Response {
    let mut response=Json(json!({"token":token,"access_token":token,"expires_in":claims.exp.saturating_sub(claims.iat),"subject":claims.sub,"access":claims.access})).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        "no-store".parse().expect("static header"),
    );
    response
}

async fn token(
    State(registry): State<Arc<Registry>>,
    RawQuery(query): RawQuery,
    method: Method,
    headers: HeaderMap,
) -> std::result::Result<Response, ApiError> {
    if method != Method::GET {
        return Err(ApiError(
            StatusCode::METHOD_NOT_ALLOWED,
            "UNSUPPORTED",
            "Use GET for the token endpoint".into(),
        ));
    }
    let parsed = reqwest::Url::parse(&format!("http://local/?{}", query.unwrap_or_default()))
        .map_err(ApiError::bad)?;
    let mut scopes = Vec::new();
    for (key, value) in parsed.query_pairs() {
        if key == "service" && value != registry.auth.service {
            return Err(ApiError::bad("Wrong token audience/service"));
        }
        if key == "scope" {
            scopes.push(value.into_owned());
        }
    }
    if let Some(bearer) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        let issued = registry
            .auth
            .validate(bearer)
            .and_then(|root| registry.auth.exchange(&root, &scopes));
        return match issued {
            Ok((token, claims)) => Ok(token_reply(token, claims)),
            Err(_) => Ok(ApiError(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "Session cannot issue the requested token".into(),
            )
            .into_response()),
        };
    }
    let credentials = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|v| base64::engine::general_purpose::STANDARD.decode(v).ok())
        .and_then(|v| String::from_utf8(v).ok());
    let user = credentials.as_deref().and_then(|v| v.split_once(':'));
    if let Some((user, password)) = user {
        match registry.password_login(user.into(), password.into()).await {
            Ok(()) => {
                let (token, claims) = registry.auth.issue(user, &scopes, TOKEN_SECONDS)?;
                return Ok(token_reply(token, claims));
            }
            Err(PasswordLoginError::Throttled(seconds)) => return Ok(login_throttled(seconds)),
            Err(PasswordLoginError::Unavailable) => {
                return Ok(StatusCode::SERVICE_UNAVAILABLE.into_response())
            }
            Err(PasswordLoginError::InvalidCredentials) => {}
        }
    }
    let mut response = ApiError(
        StatusCode::UNAUTHORIZED,
        "UNAUTHORIZED",
        "Invalid credentials".into(),
    )
    .into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        "Basic realm=\"subsoil\"".parse().expect("static header"),
    );
    Ok(response)
}

pub(crate) fn login_throttled(seconds: u64) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [
            (header::RETRY_AFTER, seconds.to_string()),
            (header::CACHE_CONTROL, "no-store".into()),
        ],
    )
        .into_response()
}

fn response(status: StatusCode, body: impl Into<Body>, headers: &[(&str, String)]) -> Response {
    let mut response = (status, body.into()).into_response();
    response.headers_mut().insert(
        "docker-distribution-api-version",
        "registry/2.0".parse().expect("static header"),
    );
    for (name, value) in headers {
        response.headers_mut().insert(
            header::HeaderName::from_bytes(name.as_bytes()).expect("static header name"),
            value.parse().expect("validated header value"),
        );
    }
    response
}

async fn base(
    State(registry): State<Arc<Registry>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = authorization(&registry, &headers, None) {
        return *response;
    }
    if method != Method::GET && method != Method::HEAD {
        return ApiError(
            StatusCode::METHOD_NOT_ALLOWED,
            "UNSUPPORTED",
            "Use GET or HEAD".into(),
        )
        .into_response();
    }
    response(
        StatusCode::OK,
        if method == Method::HEAD { "" } else { "{}" },
        &[("content-type", "application/json".into())],
    )
}

pub(crate) fn valid_repo(repo: &str) -> Result<()> {
    ensure!(
        !repo.is_empty()
            && repo.len() <= 255
            && repo.split('/').all(|part| !part.is_empty()
                && (part.as_bytes()[0].is_ascii_lowercase()
                    || part.as_bytes()[0].is_ascii_digit())),
        "Invalid repository name"
    );
    ensure!(
        repo.split('/').all(|part| part
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-".contains(&c))),
        "Invalid repository name"
    );
    Ok(())
}

fn valid_tag(tag: &str) -> Result<()> {
    ensure!(
        !tag.is_empty()
            && tag.len() <= 128
            && tag
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
            && !tag.starts_with(['.', '-']),
        "Invalid artifact tag"
    );
    Ok(())
}

async fn endpoint(
    State(registry): State<Arc<Registry>>,
    RoutePath(path): RoutePath<String>,
    Query(query): Query<HashMap<String, String>>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> std::result::Result<Response, ApiError> {
    // Repository components may themselves be named blobs, manifests, or tags.
    // Resolve the last resource delimiter once and use it for both auth and dispatch.
    let mut routes: Vec<_> = ["/blobs/", "/manifests/"]
        .into_iter()
        .filter_map(|marker| path.rfind(marker).map(|at| (at, marker)))
        .collect();
    if path.ends_with("/tags/list") {
        routes.push((path.len() - 10, "/tags/list"));
    }
    let (at, marker) = routes
        .into_iter()
        .max_by_key(|(at, _)| *at)
        .ok_or_else(|| ApiError::missing("NAME_UNKNOWN"))?;
    let repo = &path[..at];
    valid_repo(repo)?;
    let reference = &path[at + marker.len()..];
    let upload_path = marker == "/blobs/" && reference.starts_with("uploads/");
    let action = if !upload_path && (method == Method::GET || method == Method::HEAD) {
        "pull"
    } else {
        "push"
    };
    let claims = match authorization(&registry, &headers, Some((repo, action))) {
        Ok(claims) => claims,
        Err(response) => {
            // A write-only client may probe for deduplication without learning
            // whether an unreadable blob already exists.
            if method == Method::HEAD && path.contains("/blobs/") && !upload_path {
                if let Ok(claims) = authorization(&registry, &headers, Some((repo, "push"))) {
                    if registry.auth.permits(&claims, repo, "push")? {
                        return Err(ApiError::missing("BLOB_UNKNOWN"));
                    }
                }
            }
            return Ok(*response);
        }
    };
    if upload_path && reference == "uploads/" {
        valid_repo(repo)?;
        if method == Method::POST {
            let _guard = registry.mutation.lock().await;
            let id = Uuid::new_v4().to_string();
            let upload = registry.upload(repo, &id)?;
            atomic_write(
                &upload.with_extension("owner"),
                Registry::upload_owner(&claims).as_bytes(),
            )?;
            atomic_write(&upload, &body)?;
            if let Some(value) = query.get("digest") {
                return finish_upload(&registry, repo, &id, value);
            }
            return Ok(upload_response(repo, &id, body.len() as u64));
        }
    } else if upload_path {
        let id = reference.strip_prefix("uploads/").expect("upload route");
        valid_repo(repo)?;
        let _guard = registry.mutation.lock().await;
        let upload = registry.upload(repo, id)?;
        if !registry.check_upload_owner(repo, id, &claims)? {
            return Ok(challenge(&registry, Some((repo, "push")), true));
        }
        if !upload.is_file() {
            return Err(ApiError::missing("BLOB_UPLOAD_UNKNOWN"));
        }
        let length = upload.metadata()?.len();
        if method == Method::DELETE {
            fs::remove_file(upload.with_extension("owner"))?;
            fs::remove_file(upload)?;
            return Ok(response(StatusCode::NO_CONTENT, Body::empty(), &[]));
        }
        if method == Method::GET {
            return Ok(upload_response(repo, id, length));
        }
        if method == Method::PATCH || method == Method::PUT {
            if let Some(range) = headers
                .get(header::CONTENT_RANGE)
                .and_then(|v| v.to_str().ok())
            {
                let start = range
                    .strip_prefix("bytes ")
                    .unwrap_or(range)
                    .split('-')
                    .next()
                    .and_then(|v| v.parse::<u64>().ok());
                if start != Some(length) {
                    return Err(ApiError(
                        StatusCode::RANGE_NOT_SATISFIABLE,
                        "RANGE_INVALID",
                        "Upload chunks must be contiguous".into(),
                    ));
                }
            }
            if length.saturating_add(body.len() as u64) > MAX_BLOB as u64 {
                return Err(ApiError(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "SIZE_INVALID",
                    "Blob exceeds the local registry limit".into(),
                ));
            }
            fs::OpenOptions::new()
                .append(true)
                .open(&upload)?
                .write_all(&body)?;
            if method == Method::PUT {
                let value = query
                    .get("digest")
                    .ok_or_else(|| ApiError::bad("Upload completion needs a digest"))?;
                return finish_upload(&registry, repo, id, value);
            }
            return Ok(upload_response(repo, id, length + body.len() as u64));
        }
    } else if marker == "/blobs/" {
        let value = reference;
        valid_repo(repo)?;
        digest_hex(value)?;
        if method == Method::GET || method == Method::HEAD {
            if !registry.can_blob(&claims, repo, value)? {
                if method == Method::HEAD && registry.auth.permits(&claims, repo, "push")? {
                    return Err(ApiError::missing("BLOB_UNKNOWN"));
                }
                return Ok(challenge(&registry, Some((repo, "pull")), true));
            }
            let file = registry.blob(value)?;
            if !registry.membership(repo, value)?.is_file() || !file.is_file() {
                return Err(ApiError::missing("BLOB_UNKNOWN"));
            }
            let size = file.metadata()?.len();
            let data = if method == Method::HEAD {
                Vec::new()
            } else {
                fs::read(file)?
            };
            return Ok(response(
                StatusCode::OK,
                data,
                &[
                    ("content-type", "application/octet-stream".into()),
                    ("content-length", size.to_string()),
                    ("docker-content-digest", value.into()),
                ],
            ));
        }
    } else if marker == "/manifests/" {
        valid_repo(repo)?;
        let _guard = registry.mutation.lock().await;
        if reference.starts_with("sha256:") {
            digest_hex(reference)?;
        } else {
            valid_tag(reference)?;
        }
        if !registry.can_manifest(&claims, repo, reference, action)? {
            return Ok(challenge(&registry, Some((repo, action)), true));
        }
        if method == Method::PUT {
            if body.len() > 1024 * 1024 {
                return Err(ApiError(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "SIZE_INVALID",
                    "Manifest exceeds 1 MiB".into(),
                ));
            }
            let manifest: Value = serde_json::from_slice(&body).map_err(ApiError::bad)?;
            if manifest["schemaVersion"] != 2 || manifest["mediaType"] != MANIFEST_TYPE {
                return Err(ApiError(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "MANIFEST_INVALID",
                    "This server accepts OCI image manifests, including non-executable artifacts"
                        .into(),
                ));
            }
            let value = digest(&body);
            if reference.starts_with("sha256:") {
                if reference != value {
                    return Err(ApiError::bad("Manifest digest mismatch"));
                }
            } else {
                valid_tag(reference)?;
            }
            let manifest_path = registry
                .repo(repo)
                .join("manifests")
                .join(digest_hex(&value)?);
            let tag_path = registry.repo(repo).join("tags").join(reference);
            if !reference.starts_with("sha256:") && tag_path.exists() {
                if fs::read_to_string(&tag_path)? != value {
                    return Err(ApiError(
                        StatusCode::CONFLICT,
                        "DENIED",
                        "Tags are immutable; publish a new version name".into(),
                    ));
                }
                return Ok(response(
                    StatusCode::CREATED,
                    Body::empty(),
                    &[
                        ("location", format!("/v2/{repo}/manifests/{value}")),
                        ("docker-content-digest", value),
                    ],
                ));
            }
            if reference.starts_with("sha256:") && manifest_path.exists() {
                if fs::read(&manifest_path)? != body {
                    return Err(ApiError::bad("Stored manifest integrity failure"));
                }
                return Ok(response(
                    StatusCode::CREATED,
                    Body::empty(),
                    &[
                        ("location", format!("/v2/{repo}/manifests/{value}")),
                        ("docker-content-digest", value),
                    ],
                ));
            }
            let config = manifest
                .get("config")
                .context("Missing config descriptor")?;
            let layers = manifest["layers"]
                .as_array()
                .context("Missing layer descriptors")?;
            for descriptor in std::iter::once(config).chain(layers) {
                let value = descriptor["digest"]
                    .as_str()
                    .context("Missing descriptor digest")?;
                let size = descriptor["size"]
                    .as_u64()
                    .context("Missing descriptor size")?;
                let file = registry.blob(value)?;
                if (!registry.can_blob(&claims, repo, value)?
                    && !registry.uploaded_by(&claims, repo, value)?)
                    || !registry.membership(repo, value)?.is_file()
                    || !file.is_file()
                    || file.metadata()?.len() != size
                {
                    return Err(ApiError(
                        StatusCode::BAD_REQUEST,
                        "MANIFEST_BLOB_UNKNOWN",
                        "Upload every described blob before its manifest".into(),
                    ));
                }
            }
            atomic_write(
                &registry
                    .repo(repo)
                    .join("manifests")
                    .join(digest_hex(&value)?),
                &body,
            )?;
            publication::record(&registry, repo, reference, &value, &claims)?;
            if !reference.starts_with("sha256:") {
                atomic_write(
                    &registry.repo(repo).join("tags").join(reference),
                    value.as_bytes(),
                )?;
            }
            return Ok(response(
                StatusCode::CREATED,
                Body::empty(),
                &[
                    ("location", format!("/v2/{repo}/manifests/{value}")),
                    ("docker-content-digest", value),
                ],
            ));
        }
        if method == Method::GET || method == Method::HEAD {
            let value = if reference.starts_with("sha256:") {
                digest_hex(reference)?;
                reference.into()
            } else {
                valid_tag(reference)?;
                fs::read_to_string(registry.repo(repo).join("tags").join(reference))
                    .map_err(|_| ApiError::missing("MANIFEST_UNKNOWN"))?
            };
            let file = registry
                .repo(repo)
                .join("manifests")
                .join(digest_hex(&value)?);
            if !file.is_file() {
                return Err(ApiError::missing("MANIFEST_UNKNOWN"));
            }
            let size = file.metadata()?.len();
            let bytes = if method == Method::HEAD {
                Vec::new()
            } else {
                fs::read(file)?
            };
            let mut metadata = publication::headers(&registry, repo, reference, &value)?;
            metadata.extend([
                ("content-type", MANIFEST_TYPE.into()),
                ("content-length", size.to_string()),
                ("docker-content-digest", value),
            ]);
            return Ok(response(StatusCode::OK, bytes, &metadata));
        }
    } else if marker == "/tags/list" {
        valid_repo(repo)?;
        if method == Method::GET {
            let folder = registry.repo(repo).join("tags");
            let layers = registry.auth.limits(&claims)?;
            let visible: std::collections::HashSet<_> = registry
                .visible_roots(&layers, repo)?
                .into_iter()
                .filter_map(|(tag, _)| tag)
                .collect();
            let mut tags = if folder.exists() {
                fs::read_dir(folder)?
                    .filter_map(|v| v.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            tags.retain(|tag| visible.contains(tag));
            // Preserve the unpaged response for callers that do not request n.
            let (tags, next) =
                discovery::page(tags, &query, usize::MAX, &format!("/v2/{repo}/tags/list"))?;
            return Ok(discovery::listing(json!({"name":repo,"tags":tags}), next));
        }
    } else {
        return Err(ApiError::missing("NAME_UNKNOWN"));
    }
    Err(ApiError(
        StatusCode::METHOD_NOT_ALLOWED,
        "UNSUPPORTED",
        "Operation is outside this local server's implemented API".into(),
    ))
}

fn upload_response(repo: &str, id: &str, size: u64) -> Response {
    response(
        StatusCode::ACCEPTED,
        Body::empty(),
        &[
            ("location", format!("/v2/{repo}/blobs/uploads/{id}")),
            ("docker-upload-uuid", id.into()),
            ("range", format!("0-{}", size.saturating_sub(1))),
        ],
    )
}

fn finish_upload(
    registry: &Registry,
    repo: &str,
    id: &str,
    value: &str,
) -> std::result::Result<Response, ApiError> {
    digest_hex(value)?;
    let upload = registry.upload(repo, id)?;
    let bytes = fs::read(&upload)?;
    if digest(&bytes) != value {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "DIGEST_INVALID",
            "Uploaded bytes do not match the expected digest".into(),
        ));
    }
    let path = registry.blob(value)?;
    if path.exists() {
        if digest(&fs::read(&path)?) != value {
            return Err(ApiError::bad("Stored blob integrity failure"));
        }
    } else {
        atomic_write(&path, &bytes)?;
    }
    atomic_write(&registry.membership(repo, value)?, b"")?;
    let owner = fs::read_to_string(upload.with_extension("owner"))?;
    atomic_write(
        &registry
            .repo(repo)
            .join("staged")
            .join(digest_hex(value)?)
            .join(hex::encode(sha2::Sha256::digest(owner.as_bytes()))),
        b"",
    )?;
    fs::remove_file(upload.with_extension("owner"))?;
    fs::remove_file(upload)?;
    Ok(response(
        StatusCode::CREATED,
        Body::empty(),
        &[
            ("location", format!("/v2/{repo}/blobs/{value}")),
            ("docker-content-digest", value.into()),
        ],
    ))
}
