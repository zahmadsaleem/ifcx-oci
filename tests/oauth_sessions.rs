use anyhow::Result;
use ifcx_oci::{
    auth::{now, REMEMBER_SECONDS, SESSION_SECONDS},
    oauth::challenge,
    registry::{self, Registry},
};
use reqwest::{Client, Response, Url};
use serde_json::Value;
use std::sync::Arc;

const CLIENT: &str = "model-client";
const CALLBACK: &str = "http://localhost:3000/oauth/callback";
const HTTPS_CALLBACK: &str = "https://app.example/oauth/callback";
const MIXED_CASE_HTTPS_CALLBACK: &str = "HTTPS://app.example/oauth/callback";

struct Fixture {
    root: tempfile::TempDir,
    registry: Arc<Registry>,
    http: Client,
    origin: String,
    server: Option<tokio::task::JoinHandle<Result<()>>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(server) = &self.server {
            server.abort();
        }
    }
}

impl Fixture {
    async fn new() -> Result<Self> {
        let root = tempfile::tempdir()?;
        let registry = Registry::open(root.path().join("registry"))?;
        registry.auth.add_user(
            "reader",
            "test-registry-password",
            &["project/model:pull".into()],
        )?;
        let mut fixture = Self {
            root,
            registry,
            http: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            origin: String::new(),
            server: None,
        };
        fixture.listen().await?;
        Ok(fixture)
    }
    async fn listen(&mut self) -> Result<()> {
        self.registry.oauth.configure(
            CLIENT,
            &[
                CALLBACK.into(),
                HTTPS_CALLBACK.into(),
                MIXED_CASE_HTTPS_CALLBACK.into(),
            ],
        )?;
        let listener = registry::bind("127.0.0.1:0".parse()?).await?;
        self.origin = format!("http://{}", listener.local_addr()?);
        self.server = Some(tokio::spawn(registry::serve(
            listener,
            self.registry.clone(),
        )));
        Ok(())
    }
    async fn restart(&mut self) -> Result<()> {
        if let Some(server) = self.server.take() {
            server.abort();
            let _ = server.await;
        }
        self.registry = Registry::open(self.root.path().join("registry"))?;
        self.listen().await
    }
    async fn login(&self, remember: bool, callback: &str) -> Result<Response> {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let page = self
            .http
            .get(format!("{}/oauth/authorize", self.origin))
            .query(&[
                ("client_id", CLIENT),
                ("redirect_uri", callback),
                ("response_type", "code"),
                ("code_challenge_method", "S256"),
                ("code_challenge", &challenge(verifier)),
                ("state", &uuid::Uuid::new_v4().to_string()),
                ("scope", "registry:catalog:read"),
            ])
            .send()
            .await?;
        assert_eq!(page.status(), 200);
        let cookie = first_cookie(&page);
        let html = page.text().await?;
        let id = html
            .split("name=\"request_id\" value=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        let response = self
            .http
            .post(format!("{}/oauth/authorize", self.origin))
            .header("Origin", &self.origin)
            .header("Cookie", cookie)
            .form(&[
                ("request_id", id),
                ("username", "reader"),
                ("password", "test-registry-password"),
                ("decision", "allow"),
                ("remember_me", if remember { "true" } else { "false" }),
            ])
            .send()
            .await?;
        assert_eq!(response.status(), 303);
        let location = Url::parse(response.headers()["location"].to_str()?)?;
        let code = location
            .query_pairs()
            .find(|(key, _)| key == "code")
            .unwrap()
            .1
            .into_owned();
        Ok(self
            .http
            .post(format!("{}/oauth/token", self.origin))
            .header(
                "Origin",
                Url::parse(callback)?.origin().ascii_serialization(),
            )
            .form(&[
                ("grant_type", "authorization_code"),
                ("client_id", CLIENT),
                ("redirect_uri", callback),
                ("code", &code),
                ("code_verifier", verifier),
            ])
            .send()
            .await?)
    }
    async fn refresh(
        &self,
        token: Option<&str>,
        cookie: Option<&str>,
        origin: Option<&str>,
    ) -> Result<Response> {
        let mut form = vec![("grant_type", "refresh_token"), ("client_id", CLIENT)];
        if let Some(token) = token {
            form.push(("refresh_token", token));
        }
        let mut request = self
            .http
            .post(format!("{}/oauth/token", self.origin))
            .form(&form);
        if let Some(cookie) = cookie {
            request = request.header("Cookie", cookie);
        }
        if let Some(origin) = origin {
            request = request.header("Origin", origin);
        }
        Ok(request.send().await?)
    }
    async fn probe(&self, access: &str) -> Result<u16> {
        Ok(self
            .http
            .get(format!("{}/v2/", self.origin))
            .bearer_auth(access)
            .send()
            .await?
            .status()
            .as_u16())
    }
}

fn first_cookie(response: &Response) -> String {
    response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn memory_session_renews_without_persistence_and_logout_revokes_rotated_tokens() -> Result<()>
{
    let fixture = Fixture::new().await?;
    let before = now();
    let response = fixture.login(false, CALLBACK).await?;
    assert_eq!(response.status(), 200);
    assert!(response.headers()["set-cookie"]
        .to_str()?
        .contains("Max-Age=0"));
    let session: Value = response.json().await?;
    assert_eq!(session["remember_me"], false);
    let deadline = session["session_expires_at"].as_u64().unwrap();
    assert!((before + SESSION_SECONDS..=now() + SESSION_SECONDS).contains(&deadline));
    let original = session["refresh_token"].as_str().unwrap();
    assert_eq!(
        fixture
            .probe(session["access_token"].as_str().unwrap())
            .await?,
        200
    );
    let refreshed = fixture.refresh(Some(original), None, None).await?;
    assert_eq!(refreshed.status(), 200);
    assert!(refreshed.headers().get("set-cookie").is_none());
    let next: Value = refreshed.json().await?;
    assert_ne!(next["refresh_token"], original);
    assert_eq!(next["session_expires_at"], deadline);
    assert!(next["expires_in"].as_u64().unwrap() <= 900);
    assert_eq!(
        fixture
            .probe(next["access_token"].as_str().unwrap())
            .await?,
        200
    );
    let revoke = fixture
        .http
        .post(format!("{}/oauth/revoke", fixture.origin))
        .form(&[("client_id", CLIENT), ("token", original)])
        .send()
        .await?;
    assert_eq!(revoke.status(), 200);
    assert_eq!(
        fixture
            .probe(next["access_token"].as_str().unwrap())
            .await?,
        401
    );
    assert_eq!(
        fixture
            .refresh(Some(next["refresh_token"].as_str().unwrap()), None, None)
            .await?
            .status(),
        400
    );
    assert_eq!(
        fixture
            .http
            .post(format!("{}/oauth/revoke", fixture.origin))
            .form(&[("client_id", CLIENT), ("token", "unknown")])
            .send()
            .await?
            .status(),
        200
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remembered_cookie_is_30_days_origin_bound_shared_across_tabs_and_survives_restart(
) -> Result<()> {
    let mut fixture = Fixture::new().await?;
    let before = now();
    let response = fixture.login(true, CALLBACK).await?;
    assert_eq!(response.status(), 200);
    let attributes = response.headers()["set-cookie"].to_str()?.to_string();
    assert!(attributes.contains("Path=/oauth/; HttpOnly; SameSite=Strict; Max-Age="));
    assert!(!attributes.contains("Domain="));
    let cookie1 = first_cookie(&response);
    let first: Value = response.json().await?;
    assert!(first.get("refresh_token").is_none());
    assert_eq!(first["remember_me"], true);
    let deadline = first["session_expires_at"].as_u64().unwrap();
    assert!((before + REMEMBER_SECONDS..=now() + REMEMBER_SECONDS).contains(&deadline));
    for (cookie, origin, status) in [
        (cookie1.clone(), "https://attacker.example", 403),
        (
            format!("{cookie1}; {cookie1}"),
            "http://localhost:3000",
            400,
        ),
    ] {
        let rejected = fixture
            .http
            .post(format!("{}/oauth/revoke", fixture.origin))
            .header("Origin", origin)
            .header("Cookie", cookie)
            .form(&[("client_id", CLIENT)])
            .send()
            .await?;
        assert_eq!(rejected.status(), status);
        assert!(rejected.headers().get("set-cookie").is_none());
        assert_eq!(
            fixture
                .probe(first["access_token"].as_str().unwrap())
                .await?,
            200
        );
    }
    for origin in [
        None,
        Some("http://localhost:9999"),
        Some("https://attacker.example"),
    ] {
        let response = fixture.refresh(None, Some(&cookie1), origin).await?;
        assert_eq!(response.status(), 403);
        assert!(response.headers().get("set-cookie").is_none());
    }
    // A remembered cookie cannot be used as a JS-readable memory-mode refresh token.
    assert_eq!(
        fixture
            .refresh(Some(cookie1.split_once('=').unwrap().1), None, None)
            .await?
            .status(),
        400
    );
    let second = fixture
        .refresh(None, Some(&cookie1), Some("http://localhost:3000"))
        .await?;
    assert_eq!(second.status(), 200);
    let cookie2 = first_cookie(&second);
    assert_ne!(cookie1, cookie2);
    let second: Value = second.json().await?;
    assert!(second.get("refresh_token").is_none());
    fixture.restart().await?;
    // A second tab uses the cookie the browser shared after the first tab's rotation.
    let third = fixture
        .refresh(None, Some(&cookie2), Some("http://localhost:3000"))
        .await?;
    assert_eq!(third.status(), 200);
    let cookie3 = first_cookie(&third);
    let third: Value = third.json().await?;
    assert_eq!(third["session_expires_at"], deadline);
    assert!(third.get("refresh_token").is_none());
    assert_eq!(
        fixture
            .probe(third["access_token"].as_str().unwrap())
            .await?,
        200
    );
    // Sign-out may race refresh and still revoke by an older, already consumed token.
    let response = fixture
        .http
        .post(format!("{}/oauth/revoke", fixture.origin))
        .header("Origin", "http://localhost:3000")
        .header("Cookie", cookie1)
        .form(&[("client_id", CLIENT)])
        .send()
        .await?;
    assert_eq!(response.status(), 200);
    assert!(response.headers()["set-cookie"]
        .to_str()?
        .contains("Max-Age=0"));
    assert_eq!(
        fixture
            .probe(third["access_token"].as_str().unwrap())
            .await?,
        401
    );
    assert_eq!(
        fixture
            .refresh(None, Some(&cookie3), Some("http://localhost:3000"))
            .await?
            .status(),
        400
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn secure_cookie_expiry_and_replay_have_no_persistent_bearer_escape() -> Result<()> {
    let fixture = Fixture::new().await?;
    let response = fixture.login(true, MIXED_CASE_HTTPS_CALLBACK).await?;
    assert_eq!(response.status(), 200);
    assert!(response.headers()["set-cookie"]
        .to_str()?
        .ends_with("; Secure"));
    let cookie = first_cookie(&response);
    let first: Value = response.json().await?;
    let rotated = fixture
        .refresh(None, Some(&cookie), Some("https://app.example"))
        .await?;
    assert_eq!(rotated.status(), 200);
    let new_cookie = first_cookie(&rotated);
    let second: Value = rotated.json().await?;
    assert_eq!(
        fixture
            .refresh(None, Some(&cookie), Some("https://app.example"))
            .await?
            .status(),
        400
    );
    assert_eq!(
        fixture
            .probe(second["access_token"].as_str().unwrap())
            .await?,
        401
    );
    assert_eq!(
        fixture
            .refresh(None, Some(&new_cookie), Some("https://app.example"))
            .await?
            .status(),
        400
    );
    assert_eq!(
        fixture
            .probe(first["access_token"].as_str().unwrap())
            .await?,
        401
    );
    let response = fixture.login(true, HTTPS_CALLBACK).await?;
    let cookie = first_cookie(&response);
    let session: Value = response.json().await?;
    let sid = fixture
        .registry
        .auth
        .validate(session["access_token"].as_str().unwrap())?
        .sid
        .unwrap();
    let db = rusqlite::Connection::open(fixture.root.path().join("registry/auth.sqlite"))?;
    db.execute(
        "UPDATE oauth_sessions SET expires=?1 WHERE id=?2",
        rusqlite::params![i64::try_from(now())?, sid],
    )?;
    let response = fixture
        .refresh(None, Some(&cookie), Some("https://app.example"))
        .await?;
    assert_eq!(response.status(), 400);
    assert!(response.headers()["set-cookie"]
        .to_str()?
        .contains("Max-Age=0; Secure"));
    assert_eq!(
        fixture
            .probe(session["access_token"].as_str().unwrap())
            .await?,
        401
    );
    Ok(())
}
