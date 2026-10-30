use anyhow::Result;
use reqwest::{Client, Url};
use serde_json::{json, Value};
use std::sync::Arc;
use subsoil::{
    auth::{SESSION_SCOPE, SESSION_SECONDS},
    oauth::challenge,
    policy::Grant,
    registry::{self, Registry},
    release::digest,
};

const CLIENT: &str = "subsoil-explorer";
const PASSWORD: &str = "explorer-test-password";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

struct Fixture {
    _temp: tempfile::TempDir,
    registry: Arc<Registry>,
    http: Client,
    origin: String,
    running: tokio::task::JoinHandle<Result<()>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.running.abort();
    }
}

impl Fixture {
    async fn new() -> Result<Self> {
        let temp = tempfile::tempdir()?;
        let registry = Registry::open(temp.path())?;
        registry.auth.add_user("editor", PASSWORD, &[])?;
        registry.auth.add_rule(
            "editor",
            &Grant {
                repositories: vec!["project/*".into()],
                tags: Some(vec!["issued".into()]),
                actions: vec!["pull".into(), "push".into()],
                digests: None,
            },
        )?;
        registry.auth.add_user(
            "publisher",
            PASSWORD,
            &[
                "project/model:pull,push".into(),
                "private/secret:pull,push".into(),
            ],
        )?;
        let listener = registry::bind("127.0.0.1:0".parse()?).await?;
        let origin = format!("http://{}", listener.local_addr()?);
        registry.set_public_url(&origin)?;
        let running = tokio::spawn(registry::serve(listener, registry.clone()));
        Ok(Self {
            _temp: temp,
            registry,
            http: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            origin,
            running,
        })
    }

    async fn authorize(&self, callback: &str, scope: &str) -> Result<reqwest::Response> {
        Ok(self
            .http
            .get(format!("{}/oauth/authorize", self.origin))
            .query(&[
                ("response_type", "code"),
                ("client_id", CLIENT),
                ("redirect_uri", callback),
                ("scope", scope),
                ("state", "explorer-test-state"),
                ("code_challenge", &challenge(VERIFIER)),
                ("code_challenge_method", "S256"),
            ])
            .send()
            .await?)
    }

    async fn login(&self, other_cookie: &str) -> Result<Value> {
        let callback = format!("{}/explore", self.origin);
        let page = self.authorize(&callback, SESSION_SCOPE).await?;
        assert_eq!(page.status(), 200);
        let cookie = page.headers()["set-cookie"]
            .to_str()?
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let html = page.text().await?;
        assert!(html.contains("Browse artifacts with read-only access for this tab."));
        assert!(html.contains("class=\"remember\" hidden"));
        let id = html
            .split("name=\"request_id\" value=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        let consent = self
            .http
            .post(format!("{}/oauth/authorize", self.origin))
            .header("Origin", &self.origin)
            .header("Cookie", cookie)
            .form(&[
                ("request_id", id),
                ("username", "editor"),
                ("password", PASSWORD),
                ("decision", "allow"),
                ("remember_me", "true"),
            ])
            .send()
            .await?;
        assert_eq!(consent.status(), 303);
        let redirect = Url::parse(consent.headers()["location"].to_str()?)?;
        assert_eq!(redirect.path(), "/explore");
        let code = redirect
            .query_pairs()
            .find(|(key, _)| key == "code")
            .unwrap()
            .1
            .into_owned();
        let response = self
            .http
            .post(format!("{}/oauth/token", self.origin))
            .header("Origin", &self.origin)
            .header("Cookie", other_cookie)
            .form(&[
                ("grant_type", "authorization_code"),
                ("client_id", CLIENT),
                ("redirect_uri", &callback),
                ("code", &code),
                ("code_verifier", VERIFIER),
            ])
            .send()
            .await?;
        assert_eq!(response.status(), 200);
        assert!(!response.headers().contains_key("set-cookie"));
        let session: Value = response.json().await?;
        assert_eq!(session["remember_me"], false);
        assert!(session["session_expires_in"].as_u64().unwrap() <= SESSION_SECONDS);
        assert_eq!(session["permissions"][0]["actions"], json!(["pull"]));
        Ok(session)
    }

    async fn publish(&self, repo: &str, tag: &str) -> Result<String> {
        let token = self
            .registry
            .auth
            .issue("publisher", &[format!("repository:{repo}:pull,push")], 900)?
            .0;
        let blob = digest(b"{}");
        let response = self
            .http
            .post(format!("{}/v2/{repo}/blobs/uploads/", self.origin))
            .query(&[("digest", &blob)])
            .bearer_auth(&token)
            .body("{}")
            .send()
            .await?;
        assert_eq!(response.status(), 201);
        let manifest = serde_json::to_vec(&json!({
            "schemaVersion": 2, "mediaType": registry::MANIFEST_TYPE,
            "artifactType": "application/vnd.example.model",
            "config": {"mediaType": "application/json", "digest": blob, "size": 2},
            "layers": [], "annotations": {"org.opencontainers.image.title": "Example model"}
        }))?;
        let response = self
            .http
            .put(format!("{}/v2/{repo}/manifests/{tag}", self.origin))
            .bearer_auth(token)
            .body(manifest.clone())
            .send()
            .await?;
        assert_eq!(response.status(), 201);
        Ok(digest(&manifest))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn embedded_explorer_is_available_without_oauth_configuration() -> Result<()> {
    let fixture = Fixture::new().await?;
    for (path, content_type) in [
        ("/explore", "text/html"),
        ("/explore/app.js", "text/javascript"),
        ("/explore/style.css", "text/css"),
    ] {
        let response = fixture
            .http
            .get(format!("{}{path}", fixture.origin))
            .send()
            .await?;
        assert_eq!(response.status(), 200);
        assert!(response.headers()["content-type"]
            .to_str()?
            .starts_with(content_type));
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["x-frame-options"], "DENY");
        assert!(response.headers()["content-security-policy"]
            .to_str()?
            .contains("script-src 'self'"));
        assert!(!response.text().await?.is_empty());
        assert_eq!(
            fixture
                .http
                .post(format!("{}{path}", fixture.origin))
                .send()
                .await?
                .status(),
            405
        );
    }
    assert_eq!(
        fixture
            .http
            .get(format!("{}/v2/_catalog", fixture.origin))
            .send()
            .await?
            .status(),
        401
    );
    fixture.login("").await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn explorer_is_pull_only_filters_discovery_and_coexists_with_external_login() -> Result<()> {
    let fixture = Fixture::new().await?;
    let callback = "http://localhost:3000/oauth/callback";
    fixture
        .registry
        .oauth
        .configure("model-client", &[callback.into()])?;
    assert!(fixture
        .registry
        .oauth
        .configure(CLIENT, &[callback.into()])
        .is_err());
    let other = fixture.registry.auth.start_session(
        "editor",
        &[SESSION_SCOPE.into()],
        "model-client",
        callback,
        true,
    )?;
    for (redirect, scope) in [
        (callback.to_string(), SESSION_SCOPE),
        (format!("{}/explore/other", fixture.origin), SESSION_SCOPE),
        (
            format!("{}/explore", fixture.origin),
            "repository:project/model:pull,push",
        ),
    ] {
        let response = fixture.authorize(&redirect, scope).await?;
        assert_eq!(response.status(), 400);
        assert!(!response.headers().contains_key("location"));
    }
    let digest = fixture.publish("project/model", "issued").await?;
    fixture.publish("project/model", "draft").await?;
    fixture.publish("private/secret", "issued").await?;
    let session = fixture
        .login(&format!("oci_registry_refresh={}", other.refresh_token))
        .await?;
    fixture.registry.auth.validate(&other.access_token)?;
    let config: Value = fixture
        .http
        .get(format!("{}/oauth/config", fixture.origin))
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(config["client_id"], "model-client");
    assert_eq!(config["redirect_uris"], json!([callback]));
    let root = session["access_token"].as_str().unwrap();
    let catalog: Value = fixture
        .http
        .get(format!("{}/v2/_catalog", fixture.origin))
        .bearer_auth(root)
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(catalog["repositories"], json!(["project/model"]));
    let scoped: Value = fixture
        .http
        .get(format!("{}/token", fixture.origin))
        .query(&[("scope", "repository:project/model:pull,push")])
        .bearer_auth(root)
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(scoped["access"][0]["actions"], json!(["pull"]));
    let access = scoped["access_token"].as_str().unwrap();
    let tags: Value = fixture
        .http
        .get(format!("{}/v2/project/model/tags/list", fixture.origin))
        .bearer_auth(access)
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(tags["tags"], json!(["issued"]));
    let manifest = fixture
        .http
        .get(format!(
            "{}/v2/project/model/manifests/issued",
            fixture.origin
        ))
        .bearer_auth(access)
        .send()
        .await?;
    assert_eq!(manifest.status(), 200);
    assert_eq!(manifest.headers()["docker-content-digest"], digest);
    assert_eq!(
        manifest.headers()["subsoil-registry-publisher"],
        "publisher"
    );
    assert_eq!(
        fixture
            .http
            .post(format!(
                "{}/v2/project/model/blobs/uploads/",
                fixture.origin
            ))
            .bearer_auth(access)
            .send()
            .await?
            .status(),
        403
    );
    assert_eq!(
        fixture
            .http
            .get(format!(
                "{}/v2/project/model/manifests/draft",
                fixture.origin
            ))
            .bearer_auth(access)
            .send()
            .await?
            .status(),
        403
    );
    let refreshed = fixture
        .http
        .post(format!("{}/oauth/token", fixture.origin))
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", CLIENT),
            ("refresh_token", session["refresh_token"].as_str().unwrap()),
        ])
        .send()
        .await?;
    assert_eq!(refreshed.status(), 200);
    let refreshed: Value = refreshed.json().await?;
    assert_eq!(refreshed["permissions"][0]["actions"], json!(["pull"]));
    assert_eq!(
        fixture
            .http
            .post(format!("{}/oauth/revoke", fixture.origin))
            .form(&[
                ("client_id", CLIENT),
                ("token", refreshed["refresh_token"].as_str().unwrap())
            ])
            .send()
            .await?
            .status(),
        200
    );
    assert_eq!(
        fixture
            .http
            .get(format!("{}/v2/_catalog", fixture.origin))
            .bearer_auth(root)
            .send()
            .await?
            .status(),
        401
    );
    fixture.registry.auth.validate(&other.access_token)?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repository_and_tag_pagination_filter_before_paging_and_preserve_authorization(
) -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.registry.auth.add_rule(
        "editor",
        &Grant {
            repositories: vec!["project/*".into()],
            tags: Some(vec!["visible-*".into()]),
            actions: vec!["pull".into()],
            digests: None,
        },
    )?;
    for (repo, tag) in [
        ("project/alpha", "issued"),
        ("project/beta", "issued"),
        ("project/hidden", "draft"),
        ("private/secret", "issued"),
    ] {
        fixture
            .registry
            .auth
            .grant("publisher", &format!("{repo}:pull,push"))?;
        fixture.publish(repo, tag).await?;
    }
    for tag in ["hidden-a", "visible-a", "visible-b", "visible-c", "issued"] {
        fixture.publish("project/model", tag).await?;
    }
    let session = fixture.login("").await?;
    let root = session["access_token"].as_str().unwrap();
    let scoped: Value = fixture
        .http
        .get(format!("{}/token", fixture.origin))
        .query(&[("scope", "repository:project/model:pull")])
        .bearer_auth(root)
        .send()
        .await?
        .json()
        .await?;
    let token = scoped["access_token"].as_str().unwrap();
    for (endpoint, field, token, filter, expected) in [
        (
            "/v2/_catalog",
            "repositories",
            root,
            "PROJECT",
            vec!["project/alpha", "project/beta", "project/model"],
        ),
        (
            "/v2/project/model/tags/list",
            "tags",
            token,
            "VISIBLE-",
            vec!["visible-a", "visible-b", "visible-c"],
        ),
    ] {
        let mut url = Url::parse(&format!("{}{endpoint}", fixture.origin))?;
        url.query_pairs_mut()
            .append_pair("n", "2")
            .append_pair("q", filter);
        let first = fixture
            .http
            .get(url.clone())
            .bearer_auth(token)
            .send()
            .await?;
        assert_eq!(first.status(), 200);
        let next = first.headers()["link"]
            .to_str()?
            .split('<')
            .nth(1)
            .unwrap()
            .split('>')
            .next()
            .unwrap()
            .to_string();
        let first: Value = first.json().await?;
        assert_eq!(first[field], json!(expected[..2]));
        let next = Url::parse(&fixture.origin)?.join(&next)?;
        assert_eq!(next.path(), endpoint);
        assert!(next
            .query_pairs()
            .any(|(key, value)| key == "q" && value == filter.to_ascii_lowercase()));
        let last = fixture.http.get(next).bearer_auth(token).send().await?;
        assert_eq!(last.status(), 200);
        assert!(!last.headers().contains_key("link"));
        let last: Value = last.json().await?;
        assert_eq!(last[field], json!(expected[2..]));
        for invalid in ["0", "1001", "invalid"] {
            let response = fixture
                .http
                .get(format!("{}{endpoint}", fixture.origin))
                .query(&[("n", invalid)])
                .bearer_auth(token)
                .send()
                .await?;
            assert_eq!(response.status(), 400);
        }
        let empty: Value = fixture
            .http
            .get(format!("{}{endpoint}", fixture.origin))
            .query(&[("n", "2"), ("q", "no-match")])
            .bearer_auth(token)
            .send()
            .await?
            .json()
            .await?;
        assert_eq!(empty[field], json!([]));
    }
    // Unpaged tag requests remain compatible, and last applies even without n.
    let all: Value = fixture
        .http
        .get(format!("{}/v2/project/model/tags/list", fixture.origin))
        .bearer_auth(token)
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(
        all["tags"],
        json!(["issued", "visible-a", "visible-b", "visible-c"])
    );
    let last: Value = fixture
        .http
        .get(format!("{}/v2/project/model/tags/list", fixture.origin))
        .query(&[("last", "visible-b")])
        .bearer_auth(token)
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(last["tags"], json!(["visible-c"]));
    Ok(())
}
