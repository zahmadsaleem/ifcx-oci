use anyhow::Result;
use ifcx_oci::{
    registry::{self, Registry},
    release::digest,
};
use reqwest::{header::HeaderMap, Client, Method, Response};
use serde_json::Value;

const APP: &str = "https://app.example.com";

struct Server {
    origin: String,
    task: tokio::task::JoinHandle<Result<()>>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn start(registry: std::sync::Arc<Registry>) -> Result<Server> {
    let listener = registry::bind("127.0.0.1:0".parse()?).await?;
    Ok(Server {
        origin: format!("http://{}", listener.local_addr()?),
        task: tokio::spawn(registry::serve(listener, registry)),
    })
}
fn contains(headers: &HeaderMap, name: &str, value: &str) -> bool {
    headers.get_all(name).iter().any(|header| {
        header
            .to_str()
            .unwrap()
            .split(',')
            .any(|part| part.trim().eq_ignore_ascii_case(value))
    })
}
fn accessible(response: &Response, origin: &str) {
    assert_eq!(response.headers()["access-control-allow-origin"], origin);
    assert_eq!(
        response.headers()["access-control-allow-credentials"],
        "true"
    );
    assert!(contains(response.headers(), "vary", "origin"));
}

#[tokio::test]
async fn cors_is_opt_in_and_validates_exact_origins() -> Result<()> {
    let root = tempfile::tempdir()?;
    let registry = Registry::open(root.path())?;
    for origin in [
        "*",
        "null",
        "https://*.example.com",
        "http://app.example.com",
        "https://user:pass@app.example.com",
        "https://app.example.com/path",
        "https://app.example.com/?query=1",
        "https://app.example.com/#fragment",
        "https://app.example.com\n",
        "https:\\app.example.com",
        "file:///tmp/test",
    ] {
        assert!(
            registry.set_cors_origins(&[origin.into()]).is_err(),
            "{origin}"
        );
    }
    // Callback registration alone must not turn on CORS.
    registry
        .oauth
        .configure("app", &[format!("{APP}/oauth/callback")])?;
    let server = start(registry.clone()).await?;
    let http = Client::new();
    for method in [Method::GET, Method::OPTIONS] {
        let response = http
            .request(method, format!("{}/v2/", server.origin))
            .header("Origin", APP)
            .header("Access-Control-Request-Method", "GET")
            .header("Access-Control-Request-Headers", "authorization")
            .send()
            .await?;
        assert_eq!(response.status(), 401);
        assert!(!response
            .headers()
            .contains_key("access-control-allow-origin"));
    }
    registry.set_cors_origins(&[APP.into()])?;
    registry.set_cors_origins(&[])?;
    let server = start(registry).await?;
    let response = http
        .get(format!("{}/oauth/config", server.origin))
        .header("Origin", APP)
        .send()
        .await?;
    assert_eq!(response.status(), 200);
    assert!(!response
        .headers()
        .contains_key("access-control-allow-origin"));
    Ok(())
}

#[tokio::test]
async fn cors_preflights_and_denied_origins_keep_credential_pages_isolated() -> Result<()> {
    let root = tempfile::tempdir()?;
    let registry = Registry::open(root.path())?;
    registry.set_cors_origins(&[
        "https://APP.example.com:443/".into(),
        "http://localhost:3000".into(),
        "http://[::1]:3000".into(),
    ])?;
    let server = start(registry).await?;
    let http = Client::new();
    for origin in [APP, "http://localhost:3000", "http://[::1]:3000"] {
        for method in ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"] {
            let response = http
                .request(
                    Method::OPTIONS,
                    format!("{}/v2/project/model/blobs/uploads/", server.origin),
                )
                .header("Origin", origin)
                .header("Access-Control-Request-Method", method)
                .header(
                    "Access-Control-Request-Headers",
                    "authorization,content-type,content-range,range,accept",
                )
                .send()
                .await?;
            assert!(response.status().is_success());
            accessible(&response, origin);
            assert!(contains(
                response.headers(),
                "access-control-allow-methods",
                method
            ));
            for name in [
                "authorization",
                "content-type",
                "content-range",
                "range",
                "accept",
            ] {
                assert!(contains(
                    response.headers(),
                    "access-control-allow-headers",
                    name
                ));
            }
            assert!(!contains(
                response.headers(),
                "access-control-allow-methods",
                "TRACE"
            ));
            assert!(!contains(
                response.headers(),
                "access-control-allow-headers",
                "x-untrusted"
            ));
            for name in [
                "access-control-request-method",
                "access-control-request-headers",
            ] {
                assert!(contains(response.headers(), "vary", name));
            }
        }
    }
    for origin in [
        "https://other.example.com",
        "https://app.example.com.evil.test",
        "https://app.example.com:444",
        "null",
    ] {
        for method in [Method::GET, Method::OPTIONS] {
            let response = http
                .request(method, format!("{}/v2/", server.origin))
                .header("Origin", origin)
                .header("Access-Control-Request-Method", "GET")
                .send()
                .await?;
            assert!(!response
                .headers()
                .contains_key("access-control-allow-origin"));
            assert!(contains(response.headers(), "vary", "origin"));
        }
    }
    for (path, method) in [
        ("token", "GET"),
        ("oauth/config", "GET"),
        ("oauth/token", "POST"),
        ("oauth/revoke", "POST"),
    ] {
        let response = http
            .request(Method::OPTIONS, format!("{}/{path}", server.origin))
            .header("Origin", APP)
            .header("Access-Control-Request-Method", method)
            .send()
            .await?;
        assert!(response.status().is_success());
        accessible(&response, APP);
    }
    for path in ["oauth/authorize", "healthz", "readyz"] {
        for method in [Method::GET, Method::OPTIONS] {
            let response = http
                .request(method, format!("{}/{path}", server.origin))
                .header("Origin", APP)
                .header("Access-Control-Request-Method", "POST")
                .send()
                .await?;
            assert!(
                !response
                    .headers()
                    .contains_key("access-control-allow-origin"),
                "{path}"
            );
        }
    }
    for path in ["oauth/token", "oauth/revoke"] {
        let response = http
            .post(format!("{}/{path}", server.origin))
            .header("Origin", APP)
            .form(&[("client_id", "unregistered")])
            .send()
            .await?;
        assert!(response.status().is_client_error());
        accessible(&response, APP);
    }
    Ok(())
}

#[tokio::test]
async fn cors_covers_authentication_errors_and_authenticated_blob_uploads() -> Result<()> {
    let root = tempfile::tempdir()?;
    let registry = Registry::open(root.path())?;
    registry.auth.add_user(
        "writer",
        "test-registry-password",
        &["project/model:pull,push".into()],
    )?;
    registry.set_cors_origins(&[APP.into()])?;
    let server = start(registry).await?;
    let http = Client::new();
    let response = http
        .get(format!("{}/v2/", server.origin))
        .header("Origin", APP)
        .send()
        .await?;
    assert_eq!(response.status(), 401);
    accessible(&response, APP);
    for name in [
        "www-authenticate",
        "docker-content-digest",
        "docker-upload-uuid",
        "docker-distribution-api-version",
        "location",
        "link",
        "range",
        "content-range",
        "retry-after",
        "ifcx-registry-publisher",
        "ifcx-registry-pushed-at",
    ] {
        assert!(
            contains(response.headers(), "access-control-expose-headers", name),
            "{name}"
        );
    }
    assert!(!contains(
        response.headers(),
        "access-control-expose-headers",
        "set-cookie"
    ));
    let response = http
        .get(format!("{}/token", server.origin))
        .header("Origin", APP)
        .basic_auth("writer", Some("test-registry-password"))
        .query(&[("scope", "repository:project/model:pull,push")])
        .send()
        .await?;
    assert_eq!(response.status(), 200);
    accessible(&response, APP);
    let reply: Value = response.json().await?;
    let token = reply["token"].as_str().unwrap();
    let body = b"browser-upload";
    let response = http
        .post(format!("{}/v2/project/model/blobs/uploads/", server.origin))
        .header("Origin", APP)
        .bearer_auth(token)
        .send()
        .await?;
    assert_eq!(response.status(), 202);
    accessible(&response, APP);
    let upload = format!(
        "{}{}",
        server.origin,
        response.headers()["location"].to_str()?
    );
    let response = http
        .patch(&upload)
        .header("Origin", APP)
        .header("Content-Type", "application/octet-stream")
        .header("Content-Range", format!("0-{}", body.len() - 1))
        .bearer_auth(token)
        .body(body.to_vec())
        .send()
        .await?;
    assert_eq!(response.status(), 202);
    accessible(&response, APP);
    let value = digest(body);
    let response = http
        .put(&upload)
        .query(&[("digest", &value)])
        .header("Origin", APP)
        .bearer_auth(token)
        .send()
        .await?;
    assert_eq!(response.status(), 201);
    accessible(&response, APP);
    assert_eq!(response.headers()["docker-content-digest"], value);
    let response = http
        .get(format!("{}/v2/project/model/blobs/{value}", server.origin))
        .header("Origin", APP)
        .bearer_auth(token)
        .send()
        .await?;
    assert_eq!(response.status(), 200);
    accessible(&response, APP);
    assert_eq!(response.bytes().await?.as_ref(), body);
    Ok(())
}
