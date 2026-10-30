use anyhow::Result;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    process::{Command, Output},
};
use subsoil::{
    client::{Client, Descriptor, Manifest},
    registry::{self, Registry},
    release::{digest, digest_hex, ARTIFACT_TYPE},
};
use tokio::task::JoinHandle;

const GEOMETRY: &[u8] = b"\0glTF\xff\r\n";
const PROPERTIES: &[u8] = b"PAR1properties";

struct Fixture {
    temp: tempfile::TempDir,
    client: Client,
    http: reqwest::Client,
    host: String,
    token: String,
    manifest: Manifest,
    server: JoinHandle<Result<()>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Fixture {
    async fn new() -> Result<Self> {
        let temp = tempfile::tempdir()?;
        let registry = Registry::open(temp.path().join("registry"))?;
        registry.auth.add_user(
            "reader",
            "fetch-test-password",
            &["project/model:pull,push".into()],
        )?;
        let listener = registry::bind("127.0.0.1:0".parse()?).await?;
        let host = listener.local_addr()?.to_string();
        let server = tokio::spawn(registry::serve(listener, registry));
        let mut client = Client::new(temp.path().join("auth.json"), true)?;
        client
            .login(
                &host,
                "reader",
                "fetch-test-password",
                &["project/model:pull,push".into()],
            )
            .await?;
        let auth: Value = serde_json::from_slice(&fs::read(temp.path().join("auth.json"))?)?;
        let mut fixture = Self {
            token: auth["tokens"][&host].as_str().unwrap().into(),
            temp,
            client,
            http: reqwest::Client::new(),
            host,
            server,
            manifest: Manifest {
                schema_version: 2,
                media_type: registry::MANIFEST_TYPE.into(),
                artifact_type: Some(ARTIFACT_TYPE.into()),
                config: descriptor(b"{}", ""),
                layers: vec![
                    descriptor(GEOMETRY, "geometry/model.glb"),
                    descriptor(PROPERTIES, "data/properties.parquet"),
                    descriptor(b"index", "index.json"),
                ],
                annotations: BTreeMap::new(),
            },
        };
        for bytes in [b"{}".as_slice(), GEOMETRY, PROPERTIES, b"index"] {
            let start = fixture
                .http
                .post(format!(
                    "http://{}/v2/project/model/blobs/uploads/",
                    fixture.host
                ))
                .bearer_auth(&fixture.token)
                .send()
                .await?
                .error_for_status()?;
            fixture
                .http
                .put(format!(
                    "http://{}{}",
                    fixture.host,
                    start.headers()["location"].to_str()?
                ))
                .bearer_auth(&fixture.token)
                .query(&[("digest", digest(bytes))])
                .body(bytes.to_vec())
                .send()
                .await?
                .error_for_status()?;
        }
        fixture.publish().await?;
        // Subsequent downloads use a token with pull permission only.
        fixture
            .client
            .login(
                &fixture.host,
                "reader",
                "fetch-test-password",
                &["project/model:pull".into()],
            )
            .await?;
        Ok(fixture)
    }

    fn source(&self) -> String {
        format!("{}/project/model:issued", self.host)
    }

    fn blob_path(&self, descriptor: &Descriptor) -> Result<PathBuf> {
        Ok(self
            .temp
            .path()
            .join("registry/blobs/sha256")
            .join(digest_hex(&descriptor.digest)?))
    }

    async fn publish(&self) -> Result<String> {
        let bytes = serde_json::to_vec(&self.manifest)?;
        self.publish_bytes(&bytes, "issued").await
    }

    async fn publish_bytes(&self, bytes: &[u8], tag: &str) -> Result<String> {
        self.http
            .put(format!(
                "http://{}/v2/project/model/manifests/{tag}",
                self.host
            ))
            .bearer_auth(&self.token)
            .body(bytes.to_vec())
            .send()
            .await?
            .error_for_status()?;
        Ok(digest(bytes))
    }

    async fn publish_revision(&self) -> Result<String> {
        let raw = serde_json::to_vec(&self.manifest)?;
        let digest = self.publish_bytes(&raw, &digest(&raw)).await?;
        Ok(format!("{}/project/model@{digest}", self.host))
    }

    fn cli(&self, arguments: &[&str]) -> Result<Output> {
        Ok(Command::new(env!("CARGO_BIN_EXE_subsoil"))
            .arg("--plain-http")
            .arg("--auth-file")
            .arg(self.temp.path().join("auth.json"))
            .args(arguments)
            .current_dir(self.temp.path())
            .output()?)
    }
}

fn descriptor(bytes: &[u8], title: &str) -> Descriptor {
    Descriptor {
        media_type: "application/octet-stream".into(),
        digest: digest(bytes),
        size: bytes.len() as u64,
        annotations: BTreeMap::from([("org.opencontainers.image.title".into(), title.into())]),
    }
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn failure(output: &Output, message: &str) {
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(message),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cli_fetches_individual_blobs_and_only_selected_layers() -> Result<()> {
    let fixture = Fixture::new().await?;
    let source = fixture.source();
    let blob = format!("{}/project/model@{}", fixture.host, digest(GEOMETRY));
    // Missing config and index prove neither command fetches unrelated blobs.
    fs::remove_file(fixture.blob_path(&fixture.manifest.config)?)?;
    fs::remove_file(fixture.blob_path(&fixture.manifest.layers[2])?)?;

    let output = fixture.cli(&["blob", "fetch", &blob, "--output", "model.glb"])?;
    success(&output);
    assert_eq!(fs::read(fixture.temp.path().join("model.glb"))?, GEOMETRY);
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout)?["digest"],
        digest(GEOMETRY)
    );
    let output = fixture.cli(&["blob", "fetch", &blob, "-o", "-"])?;
    success(&output);
    assert_eq!(output.stdout, GEOMETRY);
    failure(
        &fixture.cli(&["blob", "fetch", &blob, "-o", "model.glb"])?,
        "must not already exist",
    );
    assert_eq!(fs::read(fixture.temp.path().join("model.glb"))?, GEOMETRY);

    let output = fixture.cli(&[
        "pull",
        &source,
        "--layer",
        "geometry/model.glb",
        "--output",
        "single",
    ])?;
    success(&output);
    assert_eq!(
        fs::read(fixture.temp.path().join("single/geometry/model.glb"))?,
        GEOMETRY
    );
    assert!(!fixture.temp.path().join("single/data").exists());
    let output = fixture.cli(&[
        "pull",
        &source,
        "--layer",
        "geometry/model.glb",
        "--layer",
        "data/properties.parquet",
        "--layer",
        "geometry/model.glb",
        "--output",
        "selected",
    ])?;
    success(&output);
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["layers"].as_array().unwrap().len(), 2);
    assert!(report.get("verification").is_none());
    assert_eq!(
        fs::read(fixture.temp.path().join("selected/data/properties.parquet"))?,
        PROPERTIES
    );
    assert_eq!(
        fs::read(fixture.temp.path().join("selected/geometry/model.glb"))?,
        GEOMETRY
    );
    assert!(!fixture.temp.path().join("selected/index.json").exists());
    failure(
        &fixture.cli(&[
            "pull",
            &source,
            "--layer",
            "geometry/model.glb",
            "--output",
            "selected",
        ])?,
        "must not already exist",
    );

    failure(
        &fixture.cli(&["blob", "fetch", &source, "-o", "invalid"])?,
        "Blob fetch requires",
    );
    let missing = format!("{}/project/model@{}", fixture.host, digest(b"missing"));
    failure(
        &fixture.cli(&["blob", "fetch", &missing, "-o", "missing"])?,
        "404",
    );
    let forbidden = format!("{}/private/model@{}", fixture.host, digest(GEOMETRY));
    failure(
        &fixture.cli(&["blob", "fetch", &forbidden, "-o", "forbidden"])?,
        "403",
    );
    for path in ["invalid", "missing", "forbidden"] {
        assert!(!fixture.temp.path().join(path).exists());
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn selection_errors_and_corruption_leave_no_partial_output() -> Result<()> {
    let mut fixture = Fixture::new().await?;
    let mut source = fixture.source();
    let output = fixture.temp.path().join("failed");
    let missing = fixture
        .client
        .pull_layers(
            &source,
            &output,
            &["geometry/model.glb".into(), "missing".into()],
        )
        .await;
    assert!(missing
        .unwrap_err()
        .to_string()
        .contains("Layer not found: missing"));
    assert!(!output.exists());

    fixture
        .manifest
        .layers
        .push(fixture.manifest.layers[0].clone());
    source = fixture.publish_revision().await?;
    assert!(fixture
        .client
        .pull_layers(&source, &output, &["geometry/model.glb".into()])
        .await
        .unwrap_err()
        .to_string()
        .contains("Ambiguous layer title"));
    fixture.manifest.layers.pop();
    for title in ["../escape", "/absolute", "data\\escape", "data/../escape"] {
        fixture.manifest.layers[0]
            .annotations
            .insert("org.opencontainers.image.title".into(), title.into());
        source = fixture.publish_revision().await?;
        assert!(fixture
            .client
            .pull_layers(&source, &output, &[title.into()])
            .await
            .is_err());
        assert!(!output.exists());
    }
    fixture.manifest.layers[0].annotations.insert(
        "org.opencontainers.image.title".into(),
        "geometry/model.glb".into(),
    );
    source = fixture.publish_revision().await?;
    fs::write(
        fixture.blob_path(&fixture.manifest.layers[0])?,
        vec![b'x'; GEOMETRY.len()],
    )?;
    let blob = format!("{}/project/model@{}", fixture.host, digest(GEOMETRY));
    failure(
        &fixture.cli(&["blob", "fetch", &blob, "-o", "failed"])?,
        "Blob integrity failure",
    );
    failure(
        &fixture.cli(&["blob", "fetch", &blob, "-o", "-"])?,
        "Blob integrity failure",
    );
    failure(
        &fixture.cli(&[
            "pull",
            &source,
            "--layer",
            "data/properties.parquet",
            "--layer",
            "geometry/model.glb",
            "--output",
            "failed",
        ])?,
        "Blob integrity failure",
    );
    assert!(!output.exists());
    assert!(!fs::read_dir(fixture.temp.path())?.any(|entry| entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".subsoil-pull-")));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cli_inspects_resolves_and_browses_before_downloading_payloads() -> Result<()> {
    let mut fixture = Fixture::new().await?;
    let source = format!("{}/project/model:inspected", fixture.host);
    let repository = format!("{}/project/model", fixture.host);
    let mut manifest = serde_json::to_value(&fixture.manifest)?;
    manifest["x-test-extension"] = serde_json::json!({"preserve": true});
    let raw = serde_json::to_vec(&manifest)?;
    let expected = fixture.publish_bytes(&raw, "inspected").await?;
    fixture.publish_bytes(&raw, "reviewed").await?;
    for descriptor in std::iter::once(&fixture.manifest.config).chain(&fixture.manifest.layers) {
        fs::remove_file(fixture.blob_path(descriptor)?)?;
    }

    let output = fixture.cli(&["manifest", "fetch", &source])?;
    success(&output);
    assert_eq!(output.stdout, raw);
    let output = fixture.cli(&["manifest", "fetch", &source, "--pretty"])?;
    success(&output);
    assert_eq!(serde_json::from_slice::<Value>(&output.stdout)?, manifest);
    let output = fixture.cli(&["manifest", "fetch", &source, "-o", "manifest.json"])?;
    success(&output);
    assert!(output.stdout.is_empty());
    assert_eq!(fs::read(fixture.temp.path().join("manifest.json"))?, raw);
    failure(
        &fixture.cli(&["manifest", "fetch", &source, "-o", "manifest.json"])?,
        "must not already exist",
    );

    let pinned = format!("{repository}@{expected}");
    for reference in [&source, &pinned] {
        let output = fixture.cli(&["resolve", reference])?;
        success(&output);
        assert_eq!(String::from_utf8(output.stdout)?, format!("{expected}\n"));
    }
    let output = fixture.cli(&["resolve", &source, "--full-reference"])?;
    success(&output);
    assert_eq!(String::from_utf8(output.stdout)?, format!("{pinned}\n"));
    let output = fixture.cli(&["manifest", "fetch", &pinned, "-o", "-"])?;
    success(&output);
    assert_eq!(output.stdout, raw);

    // Repository-only login can inspect known releases, but cannot browse the catalog.
    failure(&fixture.cli(&["repo", "ls", &fixture.host])?, "403");
    let output = fixture.cli(&["repo", "tags", &repository])?;
    success(&output);
    assert_eq!(output.stdout, b"inspected\nissued\nreviewed\n");
    let output = fixture.cli(&[
        "repo",
        "tags",
        &repository,
        "--last",
        "issued",
        "--format",
        "json",
    ])?;
    success(&output);
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout)?,
        serde_json::json!({"name":"project/model","tags":["reviewed"]})
    );

    fixture
        .client
        .login(
            &fixture.host,
            "reader",
            "fetch-test-password",
            &["registry:catalog:read".into()],
        )
        .await?;
    let output = fixture.cli(&["repo", "ls", &fixture.host])?;
    success(&output);
    assert_eq!(output.stdout, b"project/model\n");
    let output = fixture.cli(&["repo", "ls", &fixture.host, "--format", "json"])?;
    success(&output);
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout)?,
        serde_json::json!({"repositories":["project/model"]})
    );
    let output = fixture.cli(&["repo", "ls", &fixture.host, "--last", "project/model"])?;
    success(&output);
    assert!(output.stdout.is_empty());
    let private = format!("{}/private/model", fixture.host);
    failure(&fixture.cli(&["repo", "tags", &private])?, "403");
    failure(
        &fixture.cli(&["manifest", "fetch", &format!("{private}:issued")])?,
        "403",
    );
    failure(
        &fixture.cli(&["resolve", &format!("{private}:issued")])?,
        "403",
    );
    Ok(())
}

#[tokio::test]
async fn listings_follow_pagination_and_reject_loops_and_foreign_links() -> Result<()> {
    use axum::{extract::Query, http::HeaderMap, routing::get, Json, Router};
    let app = Router::new()
        .route("/v2/_catalog", get(|Query(query): Query<BTreeMap<String, String>>| async move {
            let mut headers = HeaderMap::new();
            let (names, next) = match query.get("last").map(String::as_str) {
                None => (vec!["project/one"], Some("</v2/_catalog?last=before>; rel=\"prev\", </v2/_catalog?last=project%2Fone>; rel=\"next\"")),
                Some("project/one") => (vec!["project/two"], None),
                Some("loop") => (vec![], Some("</v2/_catalog?n=100&last=loop>; rel=\"next\"")),
                Some("foreign") => (vec![], Some("<https://example.invalid/v2/_catalog>; rel=\"next\"")),
                Some("different-path") => (vec![], Some("</token>; rel=\"next\"")),
                _ => (vec![], None),
            };
            if let Some(next) = next { headers.insert("link", next.parse().unwrap()); }
            (headers, Json(serde_json::json!({"repositories": names})))
        }))
        .route("/v2/project/model/tags/list", get(|Query(query): Query<BTreeMap<String, String>>| async move {
            let mut headers = HeaderMap::new();
            let tags = match query.get("last").map(String::as_str) {
                None => {
                    headers.insert("link", "<?last=issued>; rel=\"next\"".parse().unwrap());
                    serde_json::json!(["issued"])
                }
                Some("issued") => serde_json::json!(["reviewed"]),
                _ => Value::Null,
            };
            (headers, Json(serde_json::json!({"name":"project/model", "tags": tags})))
        }));
    let listener = registry::bind("127.0.0.1:0".parse()?).await?;
    let host = listener.local_addr()?.to_string();
    let server = tokio::spawn(async move { axum::serve(listener, app).await });
    let temp = tempfile::tempdir()?;
    let client = Client::new(temp.path().join("auth.json"), true)?;
    assert_eq!(
        client.repositories(&host, None).await?,
        ["project/one", "project/two"]
    );
    let repository = format!("{host}/project/model");
    assert_eq!(
        client.tags(&repository, None).await?,
        ["issued", "reviewed"]
    );
    assert!(client.tags(&repository, Some("zzzz")).await?.is_empty());
    let error = client.repositories(&host, Some("loop")).await.unwrap_err();
    assert!(error.to_string().contains("pagination loop"));
    for cursor in ["foreign", "different-path"] {
        let error = client.repositories(&host, Some(cursor)).await.unwrap_err();
        assert!(error.to_string().contains("Refusing a pagination link"));
    }
    server.abort();
    Ok(())
}

#[tokio::test]
async fn blob_fetch_rejects_oversized_head_before_get() -> Result<()> {
    use axum::{body::Body, http::Response, routing::get, Router};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    let gets = Arc::new(AtomicUsize::new(0));
    let count = gets.clone();
    let app = Router::new().route(
        "/v2/{*path}",
        get(move || async move {
            count.fetch_add(1, Ordering::SeqCst);
            "unexpected GET"
        })
        .head(|| async {
            Response::builder()
                .header("content-length", 512 * 1024 * 1024 + 1)
                .body(Body::empty())
                .unwrap()
        }),
    );
    let listener = registry::bind("127.0.0.1:0".parse()?).await?;
    let host = listener.local_addr()?;
    let server = tokio::spawn(async move { axum::serve(listener, app).await });
    let temp = tempfile::tempdir()?;
    let client = Client::new(temp.path().join("auth.json"), true)?;
    let error = client
        .fetch_blob(&format!("{host}/project/model@{}", digest(b"anything")))
        .await
        .unwrap_err();
    server.abort();
    assert!(error.to_string().contains("512 MiB limit"));
    assert_eq!(gets.load(Ordering::SeqCst), 0);
    Ok(())
}
