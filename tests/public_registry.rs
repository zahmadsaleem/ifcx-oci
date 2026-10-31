use anyhow::Result;
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};
use std::{fs, process::Command, sync::Arc};
use subsoil::{
    client,
    policy::{Grant, GrantSet},
    registry::{self, Registry},
    release::digest,
};

struct Fixture {
    temp: tempfile::TempDir,
    registry: Arc<Registry>,
    http: Client,
    host: String,
    writer: String,
    server: tokio::task::JoinHandle<Result<()>>,
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
        registry
            .auth
            .add_user("writer", "public-test-password", &[])?;
        registry.auth.add_rule(
            "writer",
            &Grant::exact("**".into(), vec!["pull".into(), "push".into()]),
        )?;
        let writer = registry
            .auth
            .issue(
                "writer",
                &[
                    "repository:samples/model:pull,push".into(),
                    "repository:private/model:pull,push".into(),
                ],
                900,
            )?
            .0;
        let listener = registry::bind("127.0.0.1:0".parse()?).await?;
        let host = listener.local_addr()?.to_string();
        registry.set_public_url(&format!("http://{host}"))?;
        let server = tokio::spawn(registry::serve(listener, registry.clone()));
        Ok(Self {
            temp,
            registry,
            http: Client::new(),
            host,
            writer,
            server,
        })
    }

    fn policy(&self, tags: Option<Vec<String>>) -> GrantSet {
        GrantSet {
            version: 1,
            registry: self.host.clone(),
            grants: vec![Grant {
                repositories: vec!["samples/**".into()],
                tags,
                actions: vec!["pull".into()],
                digests: None,
            }],
        }
    }

    async fn upload(&self, repo: &str, bytes: &[u8]) -> Result<()> {
        let response = self
            .http
            .post(format!("http://{}/v2/{repo}/blobs/uploads/", self.host))
            .bearer_auth(&self.writer)
            .query(&[("digest", digest(bytes))])
            .body(bytes.to_vec())
            .send()
            .await?;
        assert_eq!(response.status(), 201);
        Ok(())
    }

    async fn publish(&self, repo: &str, tag: &str, bytes: &[u8]) -> Result<String> {
        self.upload(repo, b"{}").await?;
        self.upload(repo, bytes).await?;
        let manifest = serde_json::to_vec(&json!({
            "schemaVersion": 2, "mediaType": registry::MANIFEST_TYPE,
            "artifactType": "application/vnd.example.artifact",
            "config": {"mediaType": "application/vnd.oci.empty.v1+json", "size": 2, "digest": digest(b"{}")},
            "layers": [{"mediaType": "application/octet-stream", "size": bytes.len(), "digest": digest(bytes),
                "annotations": {"org.opencontainers.image.title": "files/example.txt"}}]
        }))?;
        let response = self
            .http
            .put(format!("http://{}/v2/{repo}/manifests/{tag}", self.host))
            .bearer_auth(&self.writer)
            .body(manifest.clone())
            .send()
            .await?;
        assert_eq!(response.status(), 201);
        Ok(digest(&manifest))
    }

    async fn token(&self, scopes: &[&str]) -> Result<Value> {
        let query: Vec<_> = scopes.iter().map(|scope| ("scope", *scope)).collect();
        let response = self
            .http
            .get(format!("http://{}/token", self.host))
            .query(&query)
            .send()
            .await?;
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let value: Value = response.json().await?;
        assert_eq!(value["authorization_type"], "public");
        Ok(value)
    }

    async fn get(&self, path: &str, token: &str) -> Result<reqwest::Response> {
        Ok(self
            .http
            .get(format!("http://{}{path}", self.host))
            .bearer_auth(token)
            .send()
            .await?)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_hosting_exposes_only_selected_published_versions_and_their_files() -> Result<()> {
    let f = Fixture::new().await?;
    let public = f.publish("samples/model", "issued", b"public file").await?;
    let hidden = f
        .publish("samples/model", "draft", b"private draft")
        .await?;
    f.publish("private/model", "issued", b"another private file")
        .await?;
    f.upload("samples/model", b"unpublished upload").await?;
    assert_eq!(
        f.http
            .get(format!("http://{}/token", f.host))
            .send()
            .await?
            .status(),
        401
    );
    f.registry
        .auth
        .set_public_grants(&f.policy(Some(vec!["issued".into()])))?;
    let root = f.token(&["registry:catalog:*"]).await?;
    assert_eq!(root["access"][0]["actions"], json!(["read"]));
    let root = root["token"].as_str().unwrap();
    let catalog: Value = f.get("/v2/_catalog", root).await?.json().await?;
    assert_eq!(catalog["repositories"], json!(["samples/model"]));
    let access = f
        .token(&[
            "repository:samples/model:pull,push",
            "repository:private/model:pull",
        ])
        .await?;
    assert_eq!(access["access"][0]["actions"], json!(["pull"]));
    assert_eq!(access["access"][1]["actions"], json!([]));
    let access = access["access_token"].as_str().unwrap();
    let tags: Value = f
        .get("/v2/samples/model/tags/list", access)
        .await?
        .json()
        .await?;
    assert_eq!(tags["tags"], json!(["issued"]));
    assert_eq!(
        f.get(&format!("/v2/samples/model/manifests/{public}"), access)
            .await?
            .status(),
        200
    );
    for resource in [
        format!("manifests/{hidden}"),
        "manifests/draft".into(),
        format!("blobs/{}", digest(b"private draft")),
        format!("blobs/{}", digest(b"unpublished upload")),
        format!("blobs/{}", digest(b"another private file")),
    ] {
        for method in [reqwest::Method::GET, reqwest::Method::HEAD] {
            let response = f
                .http
                .request(
                    method,
                    format!("http://{}/v2/samples/model/{resource}", f.host),
                )
                .bearer_auth(access)
                .send()
                .await?;
            assert_eq!(response.status(), 403, "{resource}");
        }
    }
    assert_eq!(
        f.get("/v2/private/model/manifests/issued", access)
            .await?
            .status(),
        403
    );
    assert_eq!(
        f.http
            .post(format!("http://{}/v2/samples/model/blobs/uploads/", f.host))
            .bearer_auth(access)
            .body("forbidden")
            .send()
            .await?
            .status(),
        403
    );
    assert_eq!(
        f.http
            .put(format!("http://{}/v2/samples/model/manifests/new", f.host))
            .bearer_auth(access)
            .body("{}")
            .send()
            .await?
            .status(),
        403
    );
    assert_eq!(
        f.http
            .post(format!("http://{}/shares", f.host))
            .bearer_auth(access)
            .json(&json!({"version":1,"registry":f.host,"grants":[],"ttl":3600}))
            .send()
            .await?
            .status(),
        403
    );
    assert_eq!(
        f.http
            .get(format!("http://{}/token?scope=subsoil:session", f.host))
            .send()
            .await?
            .status(),
        400
    );
    assert_eq!(
        f.http
            .get(format!(
                "http://{}/token?scope=registry:catalog:read",
                f.host
            ))
            .bearer_auth("invalid")
            .send()
            .await?
            .status(),
        401
    );
    assert_eq!(
        f.http
            .get(format!("http://{}/token", f.host))
            .basic_auth("@public", Some("public-test-password"))
            .send()
            .await?
            .status(),
        401
    );

    let client = client::Client::new(f.temp.path().join("no-login/auth.json"), true)?;
    assert_eq!(client.repositories(&f.host, None).await?, ["samples/model"]);
    assert_eq!(
        client
            .tags(&format!("{}/samples/model", f.host), None)
            .await?,
        ["issued"]
    );
    let output = f.temp.path().join("download");
    client
        .pull(&format!("{}/samples/model:issued", f.host), &output)
        .await?;
    assert_eq!(fs::read(output.join("files/example.txt"))?, b"public file");
    assert!(!f.temp.path().join("no-login").exists());
    if let Ok(binary) = std::env::var("SUBSOIL_TEST_ORAS") {
        let auth = f.temp.path().join("oras-no-login.json");
        let oras = |arguments: &[&str]| {
            Command::new(&binary)
                .args(arguments)
                .arg("--plain-http")
                .arg("--registry-config")
                .arg(&auth)
                .output()
        };
        let repositories = oras(&["repo", "ls", &f.host])?;
        assert!(
            repositories.status.success(),
            "{}",
            String::from_utf8_lossy(&repositories.stderr)
        );
        assert_eq!(
            String::from_utf8(repositories.stdout)?.trim(),
            "samples/model"
        );
        let repository = format!("{}/samples/model", f.host);
        let tags = oras(&["repo", "tags", &repository])?;
        assert!(
            tags.status.success(),
            "{}",
            String::from_utf8_lossy(&tags.stderr)
        );
        assert_eq!(String::from_utf8(tags.stdout)?.trim(), "issued");
        let received = f.temp.path().join("oras-download");
        let pulled = oras(&[
            "pull",
            &format!("{repository}:issued"),
            "--output",
            received.to_str().unwrap(),
        ])?;
        assert!(
            pulled.status.success(),
            "{}",
            String::from_utf8_lossy(&pulled.stderr)
        );
        assert_eq!(
            fs::read(received.join("files/example.txt"))?,
            b"public file"
        );
        assert!(!auth.exists());
    }
    // The browser's no-login path uses the same catalog and repository endpoints.
    assert_eq!(
        f.get("/v2/samples/model/manifests/issued", access)
            .await?
            .status(),
        200
    );
    assert_eq!(
        f.get(
            &format!("/v2/samples/model/blobs/{}", digest(b"public file")),
            access
        )
        .await?
        .bytes()
        .await?
        .as_ref(),
        b"public file"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_policy_replacement_and_clear_apply_to_existing_tokens_and_survive_restart(
) -> Result<()> {
    let f = Fixture::new().await?;
    f.publish("samples/model", "issued", b"public file").await?;
    f.publish("samples/model", "draft", b"draft file").await?;
    f.upload("samples/model", b"staged file").await?;
    f.registry.auth.set_public_grants(&f.policy(None))?;
    let token = f.token(&["repository:samples/model:pull"]).await?;
    let token = token["token"].as_str().unwrap();
    assert_eq!(
        f.get("/v2/samples/model/manifests/draft", token)
            .await?
            .status(),
        200
    );
    assert_eq!(
        f.get(
            &format!("/v2/samples/model/blobs/{}", digest(b"staged file")),
            token
        )
        .await?
        .status(),
        403
    );
    let reopened = Registry::open(f.temp.path().join("registry"))?;
    assert_eq!(reopened.auth.public_grants()?.len(), 1);
    reopened.auth.validate(token)?;
    reopened
        .auth
        .set_public_grants(&f.policy(Some(vec!["issued".into()])))?;
    assert_eq!(
        f.get("/v2/samples/model/manifests/draft", token)
            .await?
            .status(),
        403
    );
    assert_eq!(
        f.get("/v2/samples/model/manifests/issued", token)
            .await?
            .status(),
        200
    );
    reopened.auth.clear_public_grants()?;
    assert_eq!(
        f.get("/v2/samples/model/manifests/issued", token)
            .await?
            .status(),
        403
    );
    assert_eq!(
        f.http
            .get(format!("http://{}/token", f.host))
            .send()
            .await?
            .status(),
        401
    );
    assert_eq!(
        f.get("/v2/samples/model/manifests/issued", &f.writer)
            .await?
            .status(),
        200
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_cli_validates_policies_and_updates_a_running_store_atomically() -> Result<()> {
    let f = Fixture::new().await?;
    f.publish("samples/model", "issued", b"public file").await?;
    let data = f.temp.path().join("registry");
    let file = f.temp.path().join("public.json");
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_subsoil"))
            .args(["public"])
            .args(args)
            .arg("--data")
            .arg(&data)
            .output()
    };
    fs::write(
        &file,
        serde_json::to_vec(&f.policy(Some(vec!["issued".into()])))?,
    )?;
    let result = run(&["set", file.to_str().unwrap()])?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result = run(&["list"])?;
    assert!(result.status.success());
    let listed: Value = serde_json::from_slice(&result.stdout)?;
    assert_eq!(listed[0]["tags"], json!(["issued"]));
    let token = f.token(&["repository:samples/model:pull"]).await?;
    let token = token["token"].as_str().unwrap();
    let mut invalid = f.policy(None);
    invalid.grants[0].actions.push("push".into());
    fs::write(&file, serde_json::to_vec(&invalid)?)?;
    assert!(!run(&["set", file.to_str().unwrap()])?.status.success());
    invalid = f.policy(None);
    invalid.registry = "different.example".into();
    fs::write(&file, serde_json::to_vec(&invalid)?)?;
    assert!(!run(&["set", file.to_str().unwrap()])?.status.success());
    assert_eq!(
        f.registry.auth.public_grants()?[0].grant.tags,
        Some(vec!["issued".into()])
    );
    assert!(f
        .registry
        .auth
        .grant("@public", "samples/model:push")
        .is_err());
    assert!(f
        .registry
        .auth
        .authenticate("@public", "any-password")
        .is_err());
    let result = run(&["clear"])?;
    assert!(result.status.success());
    assert!(f.registry.auth.public_grants()?.is_empty());
    assert_eq!(
        f.get("/v2/samples/model/manifests/issued", token)
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    Ok(())
}
