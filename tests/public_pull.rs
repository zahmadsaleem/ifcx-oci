use anyhow::Result;
use axum::{
    body::Body,
    extract::{Path, Query},
    http::{HeaderMap, Method, Response, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
};
use subsoil::{
    client::Client,
    registry::{self, MANIFEST_TYPE},
    release::digest,
};

const IFC: &[u8] = b"ISO-10303-21; public model";

struct Server {
    host: String,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Server {
    async fn start(app: Router) -> Result<Self> {
        let listener = registry::bind("127.0.0.1:0".parse()?).await?;
        let host = listener.local_addr()?.to_string();
        let task = tokio::spawn(async move { axum::serve(listener, app).await });
        Ok(Self { host, task })
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn manifest() -> serde_json::Value {
    json!({
        "schemaVersion": 2, "mediaType": MANIFEST_TYPE,
        "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": digest(b"{}"), "size": 2},
        "layers": [{"mediaType": "application/x-step", "digest": digest(IFC), "size": IFC.len(),
            "annotations": {"org.opencontainers.image.title": "model.ifc"}}]
    })
}

#[tokio::test]
async fn anonymous_pull_caches_per_repository_refreshes_and_never_saves_tokens() -> Result<()> {
    let generation = Arc::new(AtomicUsize::new(1));
    let denied = Arc::new(AtomicBool::new(false));
    let exchanges = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route(
            "/token",
            get({
                let generation = generation.clone();
                let exchanges = exchanges.clone();
                move |headers: HeaderMap, Query(query): Query<BTreeMap<String, String>>| {
                    let generation = generation.clone();
                    let exchanges = exchanges.clone();
                    async move {
                        assert!(!headers.contains_key("authorization"));
                        assert_eq!(query["service"], "mock-registry");
                        assert_eq!(query["preserved"], "yes");
                        assert_eq!(query.len(), 3);
                        let scope = &query["scope"];
                        assert!(matches!(scope.as_str(), "repository:project/one:pull" | "repository:project/two:pull"));
                        exchanges.fetch_add(1, Ordering::SeqCst);
                        let token = format!("{scope}-{}", generation.load(Ordering::SeqCst));
                        // Exercise either standard token field, with no expiry metadata.
                        if scope.contains("/one:") {
                            Json(json!({"token": token}))
                        } else {
                            Json(json!({"access_token": token}))
                        }
                    }
                }
            }),
        )
        .route(
            "/v2/{*path}",
            get({
                let generation = generation.clone();
                let denied = denied.clone();
                move |Path(path): Path<String>, headers: HeaderMap| {
                    let generation = generation.clone();
                    let denied = denied.clone();
                    async move {
                        let repo = if path.starts_with("project/one/") { "project/one" } else { "project/two" };
                        let expected = format!("Bearer repository:{repo}:pull-{}", generation.load(Ordering::SeqCst));
                        if denied.load(Ordering::SeqCst) || headers.get("authorization").and_then(|v| v.to_str().ok()) != Some(&expected) {
                            return Response::builder()
                                .status(StatusCode::UNAUTHORIZED)
                                .header("www-authenticate", format!(
                                    "bEaReR realm = \"http://{}/token?preserved=yes&scope=wrong&service=wrong\", service=\"mock-registry\", scope=\"repository:{repo}:pull,push\"",
                                    headers["host"].to_str().unwrap()
                                ))
                                .body(Body::empty()).unwrap();
                        }
                        if path.contains("/manifests/") {
                            Json(manifest()).into_response()
                        } else if path.ends_with(&digest(IFC)) {
                            IFC.into_response()
                        } else if path.ends_with(&digest(b"{}")) {
                            b"{}".as_slice().into_response()
                        } else {
                            StatusCode::NOT_FOUND.into_response()
                        }
                    }
                }
            }),
        );
    let server = Server::start(app).await?;
    let temp = tempfile::tempdir()?;
    let auth = temp.path().join("missing-parent/auth.json");
    let client = Client::new(&auth, true)?;
    for (number, repo) in ["one", "one", "two", "one"].iter().enumerate() {
        let output = temp.path().join(format!("pull-{number}"));
        client
            .pull(&format!("{}/project/{repo}:v1", server.host), &output)
            .await?;
        assert_eq!(fs::read(output.join("model.ifc"))?, IFC);
    }
    assert_eq!(exchanges.load(Ordering::SeqCst), 2);
    generation.store(2, Ordering::SeqCst);
    let source = format!("{}/project/one:v1", server.host);
    client.pull(&source, &temp.path().join("refreshed")).await?;
    assert_eq!(exchanges.load(Ordering::SeqCst), 3);
    assert_eq!(
        client
            .fetch_blob(&format!("{}/project/one@{}", server.host, digest(IFC)))
            .await?,
        IFC
    );
    assert_eq!(exchanges.load(Ordering::SeqCst), 3);

    denied.store(true, Ordering::SeqCst);
    let output = temp.path().join("denied");
    assert!(client
        .pull(&source, &output)
        .await
        .unwrap_err()
        .to_string()
        .contains("authentication failed"));
    assert_eq!(
        exchanges.load(Ordering::SeqCst),
        4,
        "only one token retry per read"
    );
    assert!(!output.exists());
    assert!(!auth.parent().unwrap().exists());
    Ok(())
}

#[tokio::test]
async fn invalid_challenges_and_rejected_stored_logins_do_not_exchange_tokens() -> Result<()> {
    for (challenge, stored, expected) in [
        (
            "Basic realm=\"private\"",
            false,
            "did not return a Bearer challenge",
        ),
        ("Bearer service=\"mock\"", false, "missing realm"),
        (
            "Bearer realm=\"http://registry.example/token\"",
            false,
            "unsafe token endpoint",
        ),
        (
            "Bearer realm=\"https://user:secret@registry.example/token\"",
            false,
            "unsafe token endpoint",
        ),
        (
            "Bearer realm=\"https://registry.example/token#fragment\"",
            false,
            "unsafe token endpoint",
        ),
        (
            "Bearer realm=\"https://registry.example/token\"",
            true,
            "authentication failed",
        ),
    ] {
        let requests = Arc::new(AtomicUsize::new(0));
        let server = Server::start(Router::new().fallback(get({
            let requests = requests.clone();
            move |headers: HeaderMap| {
                let requests = requests.clone();
                async move {
                    requests.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(headers.contains_key("authorization"), stored);
                    Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .header("www-authenticate", challenge)
                        .body(Body::empty())
                        .unwrap()
                }
            }
        })))
        .await?;
        let temp = tempfile::tempdir()?;
        let auth = temp.path().join("auth.json");
        if stored {
            fs::write(
                &auth,
                serde_json::to_vec(&json!({"tokens": {&server.host: "stored-secret"}}))?,
            )?;
        }
        let client = Client::new(&auth, true)?;
        let error = client
            .resolve(&format!("{}/project/model:v1", server.host))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{challenge}: {error}");
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        assert_eq!(auth.exists(), stored);
    }
    Ok(())
}

#[tokio::test]
async fn blob_redirects_keep_same_origin_auth_and_strip_it_for_every_foreign_hop() -> Result<()> {
    let downloads = Arc::new(AtomicUsize::new(0));
    let cdn = Server::start(Router::new().route(
        "/download",
        get({
            let downloads = downloads.clone();
            move |headers: HeaderMap,
                  method: Method,
                  Query(query): Query<BTreeMap<String, String>>| {
                let downloads = downloads.clone();
                async move {
                    assert!(!headers.contains_key("authorization"));
                    assert!(!headers.contains_key("cookie"));
                    downloads.fetch_add(1, Ordering::SeqCst);
                    // Return to the registry to check auth stays stripped after crossing origins.
                    Response::builder()
                        .status(StatusCode::TEMPORARY_REDIRECT)
                        .header(
                            "location",
                            format!("http://{}/returned/{}", query["registry"], method),
                        )
                        .body(Body::empty())
                        .unwrap()
                }
            }
        }),
    ))
    .await?;
    let app = Router::new()
        .route(
            "/v2/{*path}",
            get({
                let cdn = cdn.host.clone();
                move |headers: HeaderMap| {
                    let cdn = cdn.clone();
                    async move {
                        assert_eq!(headers["authorization"], "Bearer stored-secret");
                        Response::builder()
                            .status(StatusCode::FOUND)
                            .header("location", format!("/same-origin?cdn={cdn}"))
                            .body(Body::empty())
                            .unwrap()
                    }
                }
            }),
        )
        .route(
            "/same-origin",
            get(
                |headers: HeaderMap, Query(query): Query<BTreeMap<String, String>>| async move {
                    assert_eq!(headers["authorization"], "Bearer stored-secret");
                    Response::builder()
                        .status(StatusCode::TEMPORARY_REDIRECT)
                        .header(
                            "location",
                            format!(
                                "http://{}/download?registry={}",
                                query["cdn"],
                                headers["host"].to_str().unwrap()
                            ),
                        )
                        .body(Body::empty())
                        .unwrap()
                },
            ),
        )
        .route(
            "/returned/{method}",
            get(
                |headers: HeaderMap, method: Method, Path(expected): Path<String>| async move {
                    assert_eq!(method.as_str(), expected);
                    assert!(!headers.contains_key("authorization"));
                    IFC.into_response()
                },
            ),
        );
    let registry = Server::start(app).await?;
    let temp = tempfile::tempdir()?;
    let auth = temp.path().join("auth.json");
    fs::write(
        &auth,
        serde_json::to_vec(&json!({"tokens": {&registry.host: "stored-secret"}}))?,
    )?;
    let client = Client::new(&auth, true)?;
    assert_eq!(
        client
            .fetch_blob(&format!("{}/project/model@{}", registry.host, digest(IFC)))
            .await?,
        IFC
    );
    assert_eq!(
        downloads.load(Ordering::SeqCst),
        2,
        "HEAD and GET both follow redirects"
    );
    Ok(())
}

#[tokio::test]
async fn redirect_loops_and_invalid_payloads_fail_without_publishing_output() -> Result<()> {
    for case in [
        "loop",
        "corrupt",
        "oversized",
        "missing-location",
        "cdn-denied",
    ] {
        let requests = Arc::new(AtomicUsize::new(0));
        let cdn = Server::start(Router::new().route(
            "/download",
            get({
                let requests = requests.clone();
                move |headers: HeaderMap| {
                    let requests = requests.clone();
                    async move {
                        assert!(!headers.contains_key("authorization"));
                        requests.fetch_add(1, Ordering::SeqCst);
                        match case {
                            "loop" => Response::builder()
                                .status(StatusCode::TEMPORARY_REDIRECT)
                                .header("location", "/download")
                                .body(Body::empty())
                                .unwrap(),
                            "corrupt" => vec![b'x'; IFC.len()].into_response(),
                            "oversized" => vec![b'x'; IFC.len() + 1].into_response(),
                            "cdn-denied" => Response::builder()
                                .status(StatusCode::UNAUTHORIZED)
                                .header(
                                    "www-authenticate",
                                    "Bearer realm=\"http://127.0.0.1:1/unexpected\"",
                                )
                                .body(Body::empty())
                                .unwrap(),
                            _ => Response::builder()
                                .status(StatusCode::TEMPORARY_REDIRECT)
                                .body(Body::empty())
                                .unwrap(),
                        }
                    }
                }
            }),
        ))
        .await?;
        let cdn_host = cdn.host.clone();
        let registry = Server::start(Router::new().route(
            "/v2/{*path}",
            get(move |Path(path): Path<String>| {
                let cdn = cdn_host.clone();
                async move {
                    if path.contains("/manifests/") {
                        Json(manifest()).into_response()
                    } else {
                        Response::builder()
                            .status(StatusCode::TEMPORARY_REDIRECT)
                            .header("location", format!("http://{cdn}/download"))
                            .body(Body::empty())
                            .unwrap()
                    }
                }
            }),
        ))
        .await?;
        let temp = tempfile::tempdir()?;
        let client = Client::new(temp.path().join("auth.json"), true)?;
        let output = temp.path().join("output");
        let error = client
            .pull(&format!("{}/project/model:v1", registry.host), &output)
            .await
            .unwrap_err()
            .to_string();
        let expected = match case {
            "loop" => "Too many blob redirects",
            "corrupt" => "Blob integrity failure",
            "oversized" => "Blob exceeds advertised size",
            "cdn-denied" => "authentication failed",
            _ => "Blob redirect has no location",
        };
        assert!(error.contains(expected), "{case}: {error}");
        assert!(requests.load(Ordering::SeqCst) <= 5);
        assert!(!output.exists());
        assert!(fs::read_dir(temp.path())?.next().is_none());
    }
    Ok(())
}
