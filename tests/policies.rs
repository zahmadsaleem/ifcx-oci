use anyhow::Result;
use reqwest::{Client, Method, Response};
use serde_json::{json, Value};
use std::sync::Arc;
use subsoil::{
    auth::{Claims, SESSION_SCOPE},
    policy::{Grant, GrantSet},
    registry::{self, Registry},
    release::digest,
};

const REPO: &str = "hospital-a/models/architecture";
struct Fixture {
    _temp: tempfile::TempDir,
    registry: Arc<Registry>,
    host: String,
    http: Client,
    running: tokio::task::JoinHandle<Result<()>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.running.abort();
    }
}
fn rule(repo: &str, tags: Option<&[&str]>, actions: &[&str]) -> Grant {
    Grant {
        repositories: vec![repo.into()],
        tags: tags.map(|v| v.iter().map(|s| (*s).into()).collect()),
        actions: actions.iter().map(|s| (*s).into()).collect(),
        digests: None,
    }
}
impl Fixture {
    async fn new() -> Result<Self> {
        let temp = tempfile::tempdir()?;
        let registry = Registry::open(temp.path())?;
        for user in ["owner", "reader", "publisher"] {
            registry.auth.add_user(user, "policy-test-password", &[])?;
        }
        registry
            .auth
            .add_rule("owner", &rule("**", None, &["pull", "push"]))?;
        registry.auth.add_rule(
            "reader",
            &rule("hospital-a/**", Some(&["issued"]), &["pull"]),
        )?;
        registry
            .auth
            .add_rule("publisher", &rule(REPO, Some(&["review-*"]), &["push"]))?;
        let listener = registry::bind("127.0.0.1:0".parse()?).await?;
        let host = listener.local_addr()?.to_string();
        registry.set_public_url(&format!("http://{host}"))?;
        let running = tokio::spawn(registry::serve(listener, registry.clone()));
        Ok(Self {
            _temp: temp,
            registry,
            host,
            http: Client::new(),
            running,
        })
    }
    fn token(&self, user: &str, repo: &str) -> Result<String> {
        Ok(self
            .registry
            .auth
            .issue(user, &[format!("repository:{repo}:pull,push")], 900)?
            .0)
    }
    fn root(&self, user: &str) -> Result<subsoil::auth::SessionTokens> {
        self.registry.auth.start_session(
            user,
            &[SESSION_SCOPE.into()],
            "test-viewer",
            "http://localhost/callback",
            false,
        )
    }
    async fn call(
        &self,
        method: Method,
        path: &str,
        token: &str,
        body: Vec<u8>,
    ) -> Result<Response> {
        Ok(self
            .http
            .request(method, format!("http://{}{path}", self.host))
            .bearer_auth(token)
            .body(body)
            .send()
            .await?)
    }
    async fn get(&self, path: &str, token: &str) -> Result<Response> {
        self.call(Method::GET, path, token, vec![]).await
    }
    async fn upload(&self, repo: &str, token: &str, bytes: &[u8]) -> Result<String> {
        let d = digest(bytes);
        assert_eq!(
            self.call(
                Method::POST,
                &format!("/v2/{repo}/blobs/uploads/?digest={d}"),
                token,
                bytes.to_vec()
            )
            .await?
            .status(),
            201
        );
        Ok(d)
    }
    async fn publish(
        &self,
        repo: &str,
        tag: &str,
        token: &str,
        bytes: &[u8],
    ) -> Result<(String, Vec<u8>)> {
        let blob = self.upload(repo, token, bytes).await?;
        let raw = serde_json::to_vec(
            &json!({"schemaVersion":2,"mediaType":registry::MANIFEST_TYPE,"artifactType":"application/vnd.example.profile","config":{"mediaType":"application/octet-stream","digest":blob,"size":bytes.len()},"layers":[]}),
        )?;
        let result = self
            .call(
                Method::PUT,
                &format!("/v2/{repo}/manifests/{tag}"),
                token,
                raw.clone(),
            )
            .await?;
        assert_eq!(result.status(), 201, "{}", result.text().await?);
        Ok((digest(&raw), raw))
    }
    async fn share(
        &self,
        root: &str,
        grants: Vec<Grant>,
        binding: &str,
        ttl: u64,
    ) -> Result<Value> {
        let result=self.http.post(format!("http://{}/shares",self.host)).bearer_auth(root).json(&json!({"version":1,"registry":self.host,"grants":grants,"binding":binding,"ttl":ttl})).send().await?;
        assert_eq!(result.status(), 200, "{}", result.text().await?);
        Ok(result.json().await?)
    }
    async fn redeem(&self, share: &Value) -> Result<Value> {
        let result = self
            .http
            .post(format!("http://{}/shares/redeem", self.host))
            .json(&json!({"secret":share["secret"]}))
            .send()
            .await?;
        assert_eq!(result.status(), 200);
        let reply: Value = result.json().await?;
        assert_eq!(
            reply["publication_headers"],
            json!({
                "publisher":"subsoil-registry-publisher","pushed_at":"subsoil-registry-pushed-at"
            })
        );
        Ok(reply)
    }
    async fn exchange(&self, root: &str, repo: &str) -> Result<(String, Claims)> {
        let response = self
            .http
            .get(format!("http://{}/token", self.host))
            .bearer_auth(root)
            .query(&[("scope", format!("repository:{repo}:pull,push"))])
            .send()
            .await?;
        assert_eq!(response.status(), 200);
        let value: Value = response.json().await?;
        let token = value["token"].as_str().unwrap().to_string();
        let claims = self.registry.auth.validate(&token)?;
        Ok((token, claims))
    }
}

#[tokio::test]
async fn tag_policies_cover_digest_blob_listing_and_namespace_boundaries() -> Result<()> {
    let f = Fixture::new().await?;
    let owner = f.token("owner", REPO)?;
    let (issued, _) = f.publish(REPO, "issued", &owner, b"public").await?;
    let (hidden, _) = f.publish(REPO, "draft", &owner, b"secret").await?;
    let reader = f.token("reader", REPO)?;
    for suffix in [
        "manifests/issued".into(),
        format!("manifests/{issued}"),
        format!("blobs/{}", digest(b"public")),
    ] {
        assert_eq!(
            f.get(&format!("/v2/{REPO}/{suffix}"), &reader)
                .await?
                .status(),
            200
        );
    }
    for suffix in [
        "manifests/draft".into(),
        format!("manifests/{hidden}"),
        format!("blobs/{}", digest(b"secret")),
    ] {
        assert_eq!(
            f.get(&format!("/v2/{REPO}/{suffix}"), &reader)
                .await?
                .status(),
            403
        );
    }
    assert_eq!(
        f.get(&format!("/v2/{REPO}/tags/list"), &reader)
            .await?
            .json::<Value>()
            .await?["tags"],
        json!(["issued"])
    );
    // Resource tokens cannot administer account-wide shares.
    assert_eq!(f.get("/shares", &reader).await?.status(), 403);
    // Resource tokens cannot be exchanged or used on another allowed account repository.
    assert_eq!(
        f.http
            .get(format!(
                "http://{}/token?scope=repository:{REPO}:pull",
                f.host
            ))
            .bearer_auth(&reader)
            .send()
            .await?
            .status(),
        401
    );
    for repo in [
        "hospital-a/models",
        "hospital-a/models/blobs/sub",
        "hospital-a/models/manifests/sub",
    ] {
        let token = f.token("owner", repo)?;
        f.publish(repo, "issued", &token, b"other").await?;
        assert_eq!(
            f.get(&format!("/v2/{repo}/manifests/issued"), &owner)
                .await?
                .status(),
            403
        );
        assert_eq!(
            f.get(&format!("/v2/{repo}/tags/list"), &token)
                .await?
                .status(),
            200
        );
    }
    let catalog = f
        .registry
        .auth
        .issue("reader", &["registry:catalog:read".into()], 900)?;
    assert!(catalog.1.access.iter().all(|a| a.kind == "registry"));
    assert_eq!(
        f.get(&format!("/v2/{REPO}/manifests/issued"), &catalog.0)
            .await?
            .status(),
        403
    );
    assert_eq!(f.get("/v2/_catalog", &catalog.0).await?.status(), 200);
    Ok(())
}

#[tokio::test]
async fn approved_sessions_exchange_exact_scopes_and_never_gain_added_permissions() -> Result<()> {
    let f = Fixture::new().await?;
    let first = f.root("reader")?;
    assert!(first.claims.root);
    assert!(first.claims.access.iter().all(|a| a.kind == "registry"));
    let (_, resource) = f.exchange(&first.access_token, REPO).await?;
    assert_eq!(resource.access[0].name, REPO);
    assert_eq!(resource.access[0].actions, vec!["pull"]);
    f.registry
        .auth
        .add_rule("reader", &rule("bridge-b/**", None, &["pull", "push"]))?;
    f.registry
        .auth
        .add_rule("reader", &rule("hospital-a/**", None, &["push"]))?;
    let renewed = f
        .registry
        .auth
        .rotate_session(&first.refresh_token, "test-viewer")?;
    let (_, still) = f.exchange(&renewed.access_token, REPO).await?;
    assert_eq!(still.access[0].actions, vec!["pull"]);
    let (_, outside) = f.exchange(&renewed.access_token, "bridge-b/future").await?;
    assert!(outside.access[0].actions.is_empty());
    let (_, future) = f
        .exchange(&renewed.access_token, "hospital-a/next/anything")
        .await?;
    assert_eq!(future.access[0].actions, vec!["pull"]);
    let next = f.root("reader")?;
    let (_, allowed) = f.exchange(&next.access_token, "bridge-b/future").await?;
    assert_eq!(allowed.access[0].actions, vec!["pull", "push"]);
    for grant in f.registry.auth.list_grants("reader")? {
        f.registry.auth.remove_grant("reader", grant.id)?;
    }
    assert!(!f.registry.auth.permits(&resource, REPO, "pull")?);
    f.registry
        .auth
        .revoke_session(&renewed.refresh_token, "test-viewer")?;
    assert!(f
        .registry
        .auth
        .exchange(&renewed.claims, &[format!("repository:{REPO}:pull")])
        .is_err());
    Ok(())
}

#[tokio::test]
async fn immutable_publication_retries_concurrent_writes_and_upload_isolation() -> Result<()> {
    let f = Fixture::new().await?;
    let owner = f.token("owner", REPO)?;
    let publisher = f.token("publisher", REPO)?;
    let (_, secret) = f.publish(REPO, "draft", &owner, b"secret").await?;
    // Knowing a hidden descriptor cannot launder its bytes through a writable tag.
    assert_eq!(
        f.call(
            Method::PUT,
            &format!("/v2/{REPO}/manifests/review-stolen"),
            &publisher,
            secret
        )
        .await?
        .status(),
        400
    );
    let start = f
        .call(
            Method::POST,
            &format!("/v2/{REPO}/blobs/uploads/"),
            &owner,
            vec![],
        )
        .await?;
    let location = start.headers()["location"].to_str()?;
    for method in [Method::GET, Method::PATCH, Method::PUT, Method::DELETE] {
        assert_eq!(
            f.call(method, location, &publisher, vec![]).await?.status(),
            403
        );
    }
    let (_, a) = f.publish(REPO, "review-a", &publisher, b"own").await?;
    assert_eq!(
        f.get(&format!("/v2/{REPO}/manifests/review-a"), &publisher)
            .await?
            .status(),
        403
    );
    let (_, b) = f
        .publish(REPO, "review-b", &publisher, b"different")
        .await?;
    let path = format!("/v2/{REPO}/manifests/review-race");
    let (r1, r2) = tokio::join!(
        f.call(Method::PUT, &path, &publisher, a.clone()),
        f.call(Method::PUT, &path, &publisher, b)
    );
    let mut statuses = vec![r1?.status().as_u16(), r2?.status().as_u16()];
    statuses.sort();
    assert_eq!(statuses, vec![201, 409]);
    let read = f
        .get(&format!("/v2/{REPO}/manifests/review-a"), &owner)
        .await?;
    let provenance = read.headers()["subsoil-registry-pushed-at"].clone();
    assert_eq!(
        f.call(
            Method::PUT,
            &format!("/v2/{REPO}/manifests/review-a"),
            &owner,
            a
        )
        .await?
        .status(),
        201
    );
    let retry = f
        .get(&format!("/v2/{REPO}/manifests/review-a"), &owner)
        .await?;
    assert_eq!(retry.headers()["subsoil-registry-publisher"], "publisher");
    assert_eq!(retry.headers()["subsoil-registry-pushed-at"], provenance);
    assert_eq!(
        f.call(
            Method::DELETE,
            &format!("/v2/{REPO}/manifests/review-a"),
            &owner,
            vec![]
        )
        .await?
        .status(),
        405
    );
    Ok(())
}

#[tokio::test]
async fn snapshot_and_live_shares_are_bounded_independent_and_revocable() -> Result<()> {
    let f = Fixture::new().await?;
    let owner = f.token("owner", REPO)?;
    let (issued, _) = f.publish(REPO, "issued", &owner, b"issued bytes").await?;
    let root = f.root("owner")?;
    let snapshot = f
        .share(
            &root.access_token,
            vec![rule("hospital-a/**", None, &["pull"])],
            "snapshot",
            3600,
        )
        .await?;
    let live = f
        .share(
            &root.access_token,
            vec![rule("hospital-a/**", None, &["pull", "push"])],
            "live",
            3600,
        )
        .await?;
    f.registry
        .auth
        .revoke_session(&root.refresh_token, "test-viewer")?;
    let snap = f.redeem(&snapshot).await?;
    let live_auth = f.redeem(&live).await?;
    let (snap_token, claims) = f
        .exchange(snap["access_token"].as_str().unwrap(), REPO)
        .await?;
    assert!(claims.exp <= snapshot["expires_at"].as_u64().unwrap());
    assert!(claims.sid.is_none());
    assert_eq!(claims.share_id.as_deref(), snapshot["id"].as_str());
    let (live_token, _) = f
        .exchange(live_auth["access_token"].as_str().unwrap(), REPO)
        .await?;
    assert_eq!(
        f.get(&format!("/v2/{REPO}/manifests/{issued}"), &snap_token)
            .await?
            .status(),
        200
    );
    f.publish(REPO, "later", &owner, b"later bytes").await?;
    assert_eq!(
        f.get(&format!("/v2/{REPO}/manifests/later"), &snap_token)
            .await?
            .status(),
        403
    );
    assert_eq!(
        f.get(
            &format!("/v2/{REPO}/blobs/{}", digest(b"later bytes")),
            &snap_token
        )
        .await?
        .status(),
        403
    );
    let (_, raw) = f
        .publish(REPO, "guest", &live_token, b"guest bytes")
        .await?;
    let published = f
        .get(&format!("/v2/{REPO}/manifests/guest"), &owner)
        .await?;
    assert_eq!(
        published.headers()["subsoil-registry-publisher"],
        format!("share:{}", live["id"].as_str().unwrap())
    );
    assert_eq!(
        f.call(
            Method::PUT,
            &format!("/v2/{REPO}/manifests/new"),
            &snap_token,
            raw
        )
        .await?
        .status(),
        403
    );
    assert_eq!(
        f.get("/shares", live_auth["access_token"].as_str().unwrap())
            .await?
            .status(),
        403
    );
    let db = rusqlite::Connection::open(f._temp.path().join("auth.sqlite"))?;
    let hash: String = db.query_row(
        "SELECT secret_hash FROM shares WHERE id=?1",
        [snapshot["id"].as_str().unwrap()],
        |r| r.get(0),
    )?;
    assert_ne!(hash, snapshot["secret"].as_str().unwrap());
    let listed = serde_json::to_string(&f.registry.auth.list_shares("owner")?)?;
    assert!(!listed.contains(live["secret"].as_str().unwrap()));
    f.registry
        .auth
        .revoke_share("owner", snapshot["id"].as_str().unwrap())?;
    assert_eq!(
        f.get(&format!("/v2/{REPO}/manifests/issued"), &snap_token)
            .await?
            .status(),
        401
    );
    assert!(f
        .registry
        .auth
        .redeem_share(snapshot["secret"].as_str().unwrap())
        .is_err());
    db.execute(
        "UPDATE shares SET expires=0 WHERE id=?1",
        [live["id"].as_str().unwrap()],
    )?;
    assert_eq!(
        f.get(&format!("/v2/{REPO}/manifests/guest"), &live_token)
            .await?
            .status(),
        401
    );
    Ok(())
}

#[tokio::test]
async fn share_creation_rejects_widening_and_account_revocation_invalidates_live_content(
) -> Result<()> {
    let f = Fixture::new().await?;
    let owner = f.token("owner", REPO)?;
    f.publish(REPO, "issued", &owner, b"public").await?;
    let root = f.root("reader")?;
    for (grants, binding, ttl) in [
        (vec![rule(REPO, None, &["pull"])], "snapshot", 3600),
        (vec![rule(REPO, Some(&["issued"]), &["push"])], "live", 3600),
        (
            vec![rule(REPO, Some(&["issued"]), &["pull"])],
            "snapshot",
            0,
        ),
        (
            vec![rule(REPO, Some(&["issued"]), &["pull"])],
            "snapshot",
            31 * 86400,
        ),
    ] {
        assert_eq!(f.http.post(format!("http://{}/shares",f.host)).bearer_auth(&root.access_token).json(&json!({"version":1,"registry":f.host,"grants":grants,"binding":binding,"ttl":ttl})).send().await?.status(),400);
    }
    let share = f
        .share(
            &root.access_token,
            vec![rule(REPO, Some(&["issued"]), &["pull"])],
            "live",
            30,
        )
        .await?;
    let guest = f.redeem(&share).await?;
    let (token, c) = f
        .exchange(guest["access_token"].as_str().unwrap(), REPO)
        .await?;
    assert!(c.exp - c.iat <= 30);
    for grant in f.registry.auth.list_grants("reader")? {
        f.registry.auth.remove_grant("reader", grant.id)?;
    }
    assert_eq!(
        f.get(&format!("/v2/{REPO}/manifests/issued"), &token)
            .await?
            .status(),
        403
    );
    // Empty repository selectors fail closed in the JSON policy input.
    assert!(GrantSet::parse(br#"{"version":1,"registry":"registry.example.com","grants":[{"repositories":[],"actions":["pull"]}]}"#).is_err());
    Ok(())
}

#[tokio::test]
async fn catalog_extension_keeps_repository_names_within_the_approval() -> Result<()> {
    let f = Fixture::new().await?;
    f.registry
        .auth
        .add_rule("reader", &rule(REPO, Some(&["issued"]), &["pull"]))?;
    let root = f.root("reader")?;
    f.registry
        .auth
        .add_rule("reader", &rule("bridge-b/private", None, &["pull"]))?;
    f.registry
        .auth
        .add_rule("reader", &rule(REPO, None, &["push"]))?;
    let (_, claims) = f
        .registry
        .auth
        .exchange(&root.claims, &[subsoil::auth::CATALOG_GRANTS_SCOPE.into()])?;
    let repositories: Vec<_> = claims
        .access
        .iter()
        .filter(|a| a.kind == "repository")
        .collect();
    assert_eq!(repositories.len(), 1);
    assert_eq!(repositories[0].name, REPO);
    assert_eq!(repositories[0].actions, vec!["pull"]);
    Ok(())
}

#[tokio::test]
async fn rejected_share_creation_preserves_authorization_and_share_counts() -> Result<()> {
    use subsoil::auth::ShareBinding;
    let f = Fixture::new().await?;
    let policy = GrantSet {
        version: 1,
        registry: f.host.clone(),
        grants: vec![rule(REPO, None, &["pull"])],
    };
    let db = rusqlite::Connection::open(f._temp.path().join("auth.sqlite"))?;
    let counts = || -> Result<(i64, i64)> {
        Ok((
            db.query_row("SELECT COUNT(*) FROM authorizations", [], |r| r.get(0))?,
            db.query_row("SELECT COUNT(*) FROM shares", [], |r| r.get(0))?,
        ))
    };
    db.execute_batch("CREATE TRIGGER reject_share_insert BEFORE INSERT ON shares BEGIN SELECT RAISE(ABORT,'simulated storage failure'); END;")?;
    let before = counts()?;
    assert!(f
        .registry
        .create_share("owner", &policy, 3600, ShareBinding::Live)
        .await
        .is_err());
    assert_eq!(
        counts()?,
        before,
        "failed storage must roll back the complete share authorization"
    );
    db.execute_batch("DROP TRIGGER reject_share_insert;")?;
    for _ in 0..128 {
        f.registry
            .create_share("owner", &policy, 3600, ShareBinding::Live)
            .await?;
    }
    let full = counts()?;
    assert_eq!(full, (128, 128));
    for _ in 0..3 {
        let rejected = f
            .registry
            .create_share("owner", &policy, 3600, ShareBinding::Live)
            .await;
        assert!(rejected
            .err()
            .expect("quota rejection")
            .to_string()
            .contains("128 active shares"));
        assert_eq!(
            counts()?,
            full,
            "quota rejection must not persist a new authorization"
        );
    }
    let first = f.registry.auth.list_shares("owner")?.remove(0);
    f.registry.auth.revoke_share("owner", &first.id)?;
    let replacement = f
        .registry
        .create_share("owner", &policy, 3600, ShareBinding::Live)
        .await?;
    assert!(f.registry.auth.redeem_share(&replacement.secret).is_ok());
    assert_eq!(
        f.registry
            .auth
            .list_shares("owner")?
            .iter()
            .filter(|s| !s.revoked)
            .count(),
        128
    );
    Ok(())
}

#[tokio::test]
async fn oauth_catalog_scope_lists_authorized_content_without_repository_access() -> Result<()> {
    let f = Fixture::new().await?;
    let owner = f.token("owner", REPO)?;
    f.publish(REPO, "issued", &owner, b"visible").await?;
    let session = f.registry.auth.start_session(
        "reader",
        &["registry:catalog:read".into()],
        "client",
        "http://localhost/callback",
        false,
    )?;
    assert!(!session.claims.root);
    assert!(session.claims.access.iter().all(|a| a.kind == "registry"));
    assert_eq!(
        f.get("/v2/_catalog", &session.access_token)
            .await?
            .json::<Value>()
            .await?["repositories"],
        json!([REPO])
    );
    assert_eq!(
        f.get(
            &format!("/v2/{REPO}/manifests/issued"),
            &session.access_token
        )
        .await?
        .status(),
        403
    );
    assert!(f
        .registry
        .auth
        .exchange(&session.claims, &[format!("repository:{REPO}:pull")])
        .is_err());
    assert_eq!(f.get("/shares", &session.access_token).await?.status(), 403);
    Ok(())
}
