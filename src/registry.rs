//! Persistent loopback registry implementing the OCI artifact push/pull path.
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
    routing::any,
    Json, Router,
};
use base64::Engine;
use bytes::Bytes;
use serde_json::{json, Value};
use tokio::{net::TcpListener, sync::Mutex};
use uuid::Uuid;

use crate::auth::{Auth, TOKEN_SECONDS};
use crate::release::{digest, digest_hex};
mod discovery;
mod publication;

pub const MANIFEST_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const MAX_BLOB: usize = 512 * 1024 * 1024;

pub struct Registry {
    root: PathBuf,
    pub auth: Auth,
    realm: std::sync::RwLock<String>,
    mutation: Mutex<()>,
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
                marker["format"] == "ifcx-oci-registry/1",
                "Unknown registry store format"
            );
        } else {
            atomic_write(
                &root.join("registry.json"),
                b"{\"format\":\"ifcx-oci-registry/1\"}\n",
            )?;
        }
        Ok(Arc::new(Self {
            root: root.into(),
            auth: Auth::open(root)?,
            realm: std::sync::RwLock::new(String::new()),
            mutation: Mutex::new(()),
        }))
    }
    fn repo(&self, repo: &str) -> PathBuf {
        self.root.join("repositories").join(repo)
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
    Router::new()
        .route("/token", any(token))
        .route("/v2/", any(base))
        .route("/v2", any(base))
        .route("/v2/_catalog", any(discovery::catalog))
        .route("/v2/{*path}", any(endpoint))
        .layer(DefaultBodyLimit::max(MAX_BLOB))
        .with_state(registry)
}

pub async fn serve(listener: TcpListener, registry: Arc<Registry>) -> Result<()> {
    ensure!(
        listener.local_addr()?.ip().is_loopback(),
        "This experimental registry binds only to loopback"
    );
    *registry
        .realm
        .write()
        .map_err(|_| anyhow::anyhow!("Realm lock failed"))? =
        format!("http://{}/token", listener.local_addr()?);
    axum::serve(listener, router(registry)).await?;
    Ok(())
}

pub async fn bind(address: SocketAddr) -> Result<TcpListener> {
    ensure!(
        address.ip().is_loopback(),
        "This experimental registry binds only to loopback"
    );
    Ok(TcpListener::bind(address).await?)
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
    let realm = registry.realm.read().expect("realm lock");
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
    let credentials = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|v| base64::engine::general_purpose::STANDARD.decode(v).ok())
        .and_then(|v| String::from_utf8(v).ok());
    let user = credentials
        .as_deref()
        .and_then(|v| v.split_once(':'))
        .filter(|(u, p)| registry.auth.authenticate(u, p).is_ok());
    let Some((user, _)) = user else {
        let mut response = ApiError(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Invalid credentials".into(),
        )
        .into_response();
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            "Basic realm=\"ifcx-oci\"".parse().expect("static header"),
        );
        return Ok(response);
    };
    let (token, claims) = registry.auth.issue(user, &scopes, TOKEN_SECONDS)?;
    Ok(Json(json!({"token":token,"access_token":token,"expires_in":TOKEN_SECONDS,"subject":claims.sub,"access":claims.access})).into_response())
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
    let repo = path
        .rsplit_once("/blobs/")
        .or_else(|| path.rsplit_once("/manifests/"))
        .map(|(repo, _)| repo)
        .or_else(|| path.strip_suffix("/tags/list"))
        .ok_or_else(|| ApiError::missing("NAME_UNKNOWN"))?;
    valid_repo(repo)?;
    let action = if method == Method::GET || method == Method::HEAD {
        "pull"
    } else {
        "push"
    };
    let claims = match authorization(&registry, &headers, Some((repo, action))) {
        Ok(claims) => claims,
        Err(response) => return Ok(*response),
    };
    if let Some(repo) = path.strip_suffix("/blobs/uploads/") {
        valid_repo(repo)?;
        if method == Method::POST {
            let _guard = registry.mutation.lock().await;
            let id = Uuid::new_v4().to_string();
            let upload = registry.upload(repo, &id)?;
            atomic_write(&upload, &body)?;
            if let Some(value) = query.get("digest") {
                return finish_upload(&registry, repo, &id, value);
            }
            return Ok(upload_response(repo, &id, body.len() as u64));
        }
    } else if let Some((repo, id)) = path.rsplit_once("/blobs/uploads/") {
        valid_repo(repo)?;
        let _guard = registry.mutation.lock().await;
        let upload = registry.upload(repo, id)?;
        if !upload.is_file() {
            return Err(ApiError::missing("BLOB_UPLOAD_UNKNOWN"));
        }
        let length = upload.metadata()?.len();
        if method == Method::DELETE {
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
    } else if let Some((repo, value)) = path.rsplit_once("/blobs/") {
        valid_repo(repo)?;
        digest_hex(value)?;
        if method == Method::GET || method == Method::HEAD {
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
    } else if let Some((repo, reference)) = path.rsplit_once("/manifests/") {
        valid_repo(repo)?;
        let _guard = registry.mutation.lock().await;
        if method == Method::PUT {
            let manifest: Value = serde_json::from_slice(&body).map_err(ApiError::bad)?;
            if manifest["schemaVersion"] != 2 || manifest["mediaType"] != MANIFEST_TYPE {
                return Err(ApiError(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "MANIFEST_INVALID",
                    "This server accepts OCI image manifests, including non-executable artifacts"
                        .into(),
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
                if !registry.membership(repo, value)?.is_file()
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
            let value = digest(&body);
            if reference.starts_with("sha256:") {
                if reference != value {
                    return Err(ApiError::bad("Manifest digest mismatch"));
                }
            } else {
                valid_tag(reference)?;
            }
            atomic_write(
                &registry
                    .repo(repo)
                    .join("manifests")
                    .join(digest_hex(&value)?),
                &body,
            )?;
            publication::record(&registry, repo, reference, &value, &claims.sub)?;
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
    } else if let Some(repo) = path.strip_suffix("/tags/list") {
        valid_repo(repo)?;
        if method == Method::GET {
            let folder = registry.repo(repo).join("tags");
            let mut tags = if folder.exists() {
                fs::read_dir(folder)?
                    .filter_map(|v| v.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            tags.sort();
            return Ok(Json(json!({"name":repo,"tags":tags})).into_response());
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
