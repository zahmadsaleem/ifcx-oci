use anyhow::Result;
use ifcx_oci::{
    auth::now,
    registry::{self, Registry},
    release::digest,
};
use reqwest::Client;
use serde_json::{json, Value};

async fn sign_in(http: &Client, host: &str, user: &str, scope: &str) -> Result<Value> {
    let response = http
        .get(format!("http://{host}/token"))
        .basic_auth(user, Some("discovery-test-password"))
        .query(&[("scope", scope)])
        .send()
        .await?;
    assert_eq!(response.status(), 200);
    Ok(response.json().await?)
}

async fn publish(http: &Client, host: &str, token: &str, repo: &str) -> Result<(String, Vec<u8>)> {
    let start = http
        .post(format!("http://{host}/v2/{repo}/blobs/uploads/"))
        .bearer_auth(token)
        .send()
        .await?;
    assert_eq!(start.status(), 202);
    let location = start.headers()["location"].to_str()?;
    assert_eq!(
        http.put(format!("http://{host}{location}"))
            .query(&[("digest", digest(b"{}"))])
            .bearer_auth(token)
            .body("{}")
            .send()
            .await?
            .status(),
        201
    );
    let manifest = serde_json::to_vec(&json!({
        "schemaVersion":2,"mediaType":registry::MANIFEST_TYPE,
        "config":{"mediaType":"application/vnd.oci.empty.v1+json","digest":digest(b"{}"),"size":2},
        "layers":[],"annotations":{"org.opencontainers.image.title":"Review model",
        "org.opencontainers.image.authors":"Unverified declared author","org.opencontainers.image.created":"2000-01-01T00:00:00Z"}
    }))?;
    let response = http
        .put(format!("http://{host}/v2/{repo}/manifests/issued"))
        .bearer_auth(token)
        .body(manifest.clone())
        .send()
        .await?;
    assert_eq!(response.status(), 201);
    assert_eq!(
        response.headers()["docker-content-digest"],
        digest(&manifest)
    );
    Ok((digest(&manifest), manifest))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_catalog_exact_grants_and_persistent_publication_provenance() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let store = temp.path().join("registry");
    let registry = Registry::open(&store)?;
    registry.auth.add_user(
        "writer",
        "discovery-test-password",
        &[
            "public/one:pull,push".into(),
            "public/two:pull,push".into(),
            "private/secret:pull,push".into(),
        ],
    )?;
    registry.auth.add_user(
        "reader",
        "discovery-test-password",
        &["public/one:pull".into()],
    )?;
    registry
        .auth
        .add_user("empty", "discovery-test-password", &[])?;
    registry.auth.add_user(
        "reviewer",
        "discovery-test-password",
        &["public/one:pull,push".into()],
    )?;
    let listener = registry::bind("127.0.0.1:0".parse()?).await?;
    let host = listener.local_addr()?.to_string();
    let running = tokio::spawn(registry::serve(listener, registry.clone()));
    let http = Client::new();
    let writer = sign_in(&http, &host, "writer", "registry:catalog:read").await?;
    assert_eq!(writer["subject"], "writer");
    for access in writer["access"].as_array().unwrap() {
        assert!(!access["name"].as_str().unwrap().contains('*'));
        assert!(!access["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|action| action == "*"));
    }
    let writer_token = writer["token"].as_str().unwrap();
    let before = now();
    let (manifest_digest, raw) = publish(&http, &host, writer_token, "public/one").await?;
    publish(&http, &host, writer_token, "public/two").await?;
    publish(&http, &host, writer_token, "private/secret").await?;
    assert_eq!(
        http.get(format!("http://{host}/v2/_catalog"))
            .send()
            .await?
            .status(),
        401
    );
    let reader = sign_in(&http, &host, "reader", "registry:catalog:read").await?;
    let reader_token = reader["token"].as_str().unwrap();
    let catalog: Value = http
        .get(format!("http://{host}/v2/_catalog"))
        .bearer_auth(reader_token)
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(catalog, json!({"repositories":["public/one"]}));
    assert!(!reader.to_string().contains("private/secret"));
    let page = http
        .get(format!("http://{host}/v2/_catalog?n=1"))
        .bearer_auth(writer_token)
        .send()
        .await?;
    assert!(page.headers()["link"].to_str()?.contains("rel=\"next\""));
    assert_eq!(
        page.json::<Value>().await?["repositories"],
        json!(["private/secret"])
    );
    let empty = sign_in(&http, &host, "empty", "registry:catalog:read").await?;
    assert_eq!(
        http.get(format!("http://{host}/v2/_catalog"))
            .bearer_auth(empty["token"].as_str().unwrap())
            .send()
            .await?
            .json::<Value>()
            .await?["repositories"],
        json!([])
    );
    let narrow = sign_in(&http, &host, "reader", "repository:public/one:pull").await?;
    assert_eq!(
        http.get(format!("http://{host}/v2/_catalog"))
            .bearer_auth(narrow["token"].as_str().unwrap())
            .send()
            .await?
            .status(),
        403
    );
    for resource in [
        "tags/list".to_string(),
        format!("manifests/{manifest_digest}"),
    ] {
        assert_eq!(
            http.get(format!("http://{host}/v2/private/secret/{resource}"))
                .bearer_auth(reader_token)
                .send()
                .await?
                .status(),
            403
        );
    }
    let received = http
        .get(format!("http://{host}/v2/public/one/manifests/issued"))
        .bearer_auth(reader_token)
        .send()
        .await?;
    assert_eq!(received.headers()["ifcx-registry-publisher"], "writer");
    let pushed_at = received.headers()["ifcx-registry-pushed-at"]
        .to_str()?
        .to_string();
    assert!((before..=now()).contains(&pushed_at.parse::<u64>()?));
    assert_eq!(received.bytes().await?.as_ref(), raw.as_slice());
    let reviewer = sign_in(&http, &host, "reviewer", "registry:catalog:read").await?;
    publish(
        &http,
        &host,
        reviewer["token"].as_str().unwrap(),
        "public/one",
    )
    .await?;
    assert_eq!(
        http.head(format!("http://{host}/v2/public/one/manifests/issued"))
            .bearer_auth(reader_token)
            .send()
            .await?
            .headers()["ifcx-registry-publisher"],
        "reviewer"
    );
    let original = http
        .get(format!(
            "http://{host}/v2/public/one/manifests/{manifest_digest}"
        ))
        .bearer_auth(reader_token)
        .send()
        .await?;
    assert_eq!(original.headers()["ifcx-registry-publisher"], "writer");
    assert_eq!(original.headers()["ifcx-registry-pushed-at"], pushed_at);
    assert_eq!(digest(&original.bytes().await?), manifest_digest);
    running.abort();
    let _ = running.await;
    drop(registry);
    let reopened = Registry::open(&store)?;
    let listener = registry::bind("127.0.0.1:0".parse()?).await?;
    let new_host = listener.local_addr()?.to_string();
    let running = tokio::spawn(registry::serve(listener, reopened));
    let received = http
        .head(format!(
            "http://{new_host}/v2/public/one/manifests/{manifest_digest}"
        ))
        .bearer_auth(reader_token)
        .send()
        .await?;
    assert_eq!(received.status(), 200);
    assert_eq!(received.headers()["ifcx-registry-publisher"], "writer");
    assert_eq!(received.headers()["ifcx-registry-pushed-at"], pushed_at);
    let db = rusqlite::Connection::open(store.join("auth.sqlite"))?;
    db.execute("DELETE FROM grants WHERE user='reader'", [])?;
    assert_eq!(
        http.get(format!("http://{new_host}/v2/_catalog"))
            .bearer_auth(reader_token)
            .send()
            .await?
            .json::<Value>()
            .await?["repositories"],
        json!([])
    );
    assert_eq!(
        http.head(format!("http://{new_host}/v2/public/one/manifests/issued"))
            .bearer_auth(reader_token)
            .send()
            .await?
            .status(),
        403
    );
    running.abort();
    Ok(())
}
