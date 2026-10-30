use anyhow::Result;
use serde_json::json;
use std::{fs, path::PathBuf};
use subsoil::{
    client::{Client, Reference},
    registry::{self, Registry},
    release,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_two_registry_showcase_and_scope_denials() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let oras = std::env::var_os("SUBSOIL_TEST_ORAS").map(PathBuf::from);
    let report = subsoil::demo::run(&temp.path().join("showcase"), oras.as_deref()).await?;
    assert_eq!(report["valid"], true);
    assert_eq!(report["authorization"]["readerPushDenied"], true);
    assert_eq!(report["authorization"]["crossRepositoryDenied"], true);
    assert_eq!(report["authorization"]["expiredTokenDenied"], true);
    if oras.is_some() {
        assert_eq!(report["independentClient"]["authenticatedPush"], true);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn registry_validates_uploads_references_membership_and_survives_restart() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let store = temp.path().join("registry");
    let registry = Registry::open(&store)?;
    registry.auth.add_user(
        "writer",
        "test-only-long-password",
        &["project/demo:pull,push".into()],
    )?;
    let listener = registry::bind("127.0.0.1:0".parse()?).await?;
    let host = listener.local_addr()?.to_string();
    let running = tokio::spawn(registry::serve(listener, registry.clone()));
    let mut client = Client::new(temp.path().join("client-auth.json"), true)?;
    client
        .login(
            &host,
            "writer",
            "test-only-long-password",
            &["project/demo:pull,push".into()],
        )
        .await?;
    let auth: serde_json::Value =
        serde_json::from_slice(&fs::read(temp.path().join("client-auth.json"))?)?;
    let token = auth["tokens"][&host].as_str().unwrap();
    let http = reqwest::Client::new();
    let base = format!("http://{host}/v2/project/demo");
    let start = http
        .post(format!("{base}/blobs/uploads/"))
        .bearer_auth(token)
        .send()
        .await?;
    assert_eq!(start.status(), 202);
    let upload = format!("http://{host}{}", start.headers()["location"].to_str()?);
    assert_eq!(
        http.put(&upload)
            .query(&[("digest", release::digest(b"expected"))])
            .bearer_auth(token)
            .body("wrong")
            .send()
            .await?
            .status(),
        400
    );
    let missing = release::digest(b"{}");
    let invalid = json!({"schemaVersion":2,"mediaType":registry::MANIFEST_TYPE,"config":{"mediaType":"application/vnd.oci.empty.v1+json","digest":missing,"size":2},"layers":[]});
    assert_eq!(
        http.put(format!("{base}/manifests/issued"))
            .bearer_auth(token)
            .json(&invalid)
            .send()
            .await?
            .status(),
        400
    );
    let start = http
        .post(format!("{base}/blobs/uploads/"))
        .bearer_auth(token)
        .send()
        .await?;
    let upload = format!("http://{host}{}", start.headers()["location"].to_str()?);
    assert_eq!(
        http.patch(&upload)
            .bearer_auth(token)
            .header("Content-Range", "0-0")
            .body("{")
            .send()
            .await?
            .status(),
        202
    );
    assert_eq!(
        http.put(&upload)
            .query(&[("digest", missing.clone())])
            .bearer_auth(token)
            .header("Content-Range", "1-1")
            .body("}")
            .send()
            .await?
            .status(),
        201
    );
    let raw = serde_json::to_vec(&invalid)?;
    let manifest_digest = release::digest(&raw);
    assert_eq!(
        http.put(format!("{base}/manifests/issued"))
            .bearer_auth(token)
            .body(raw)
            .send()
            .await?
            .status(),
        201
    );
    let reference = Reference::parse(&format!("{host}/project/demo:issued"), true)?;
    assert_eq!(
        release::digest(&client.manifest(&reference).await?.0),
        manifest_digest
    );
    assert_eq!(
        http.get(format!("http://{host}/v2/private/demo/blobs/{missing}"))
            .bearer_auth(token)
            .send()
            .await?
            .status(),
        403
    );
    running.abort();
    let _ = running.await;
    drop(registry);
    let reopened = Registry::open(&store)?;
    let listener = registry::bind("127.0.0.1:0".parse()?).await?;
    let host = listener.local_addr()?.to_string();
    let running = tokio::spawn(registry::serve(listener, reopened));
    let received = http
        .get(format!(
            "http://{host}/v2/project/demo/manifests/{manifest_digest}"
        ))
        .bearer_auth(token)
        .send()
        .await?;
    assert_eq!(received.status(), 200);
    assert_eq!(release::digest(&received.bytes().await?), manifest_digest);
    running.abort();
    Ok(())
}
