//! Ingress-facing contracts over the private HTTP hop, plus real CLI lifecycle.
use anyhow::{ensure, Result};
use reqwest::{Client, Response, Url};
use serde_json::Value;
use std::{
    fs,
    io::{Read, Write},
    path::Path,
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};
use subsoil::{
    oauth::challenge,
    registry::{self, Registry},
    release::digest,
};

const PUBLIC: &str = "https://registry.example.com";
const CALLBACK: &str = "https://app.example/oauth/callback";
const PASSWORD: &str = "deployment-test-password";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

fn provision(data: &Path) -> Result<()> {
    let mut job = Command::new(env!("CARGO_BIN_EXE_subsoil"))
        .args(["user", "add", "--data"])
        .arg(data)
        .args(["writer", "--password-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()?;
    writeln!(job.stdin.take().unwrap(), "{PASSWORD}")?;
    ensure!(job.wait()?.success(), "user add failed");
    ensure!(
        Command::new(env!("CARGO_BIN_EXE_subsoil"))
            .args(["user", "grant", "--data"])
            .arg(data)
            .args(["writer", "project/model:pull,push"])
            .stdout(Stdio::null())
            .status()?
            .success(),
        "user grant failed"
    );
    Ok(())
}

struct Server {
    origin: String,
    registry: Arc<Registry>,
    task: tokio::task::JoinHandle<Result<()>>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Server {
    async fn start(data: &Path) -> Result<Self> {
        let registry = Registry::open(data)?;
        registry.set_public_url(PUBLIC)?;
        registry.oauth.configure("app", &[CALLBACK.into()])?;
        let listener = registry::bind("0.0.0.0:0".parse()?).await?;
        let origin = format!("http://127.0.0.1:{}", listener.local_addr()?.port());
        let task = tokio::spawn(registry::serve(listener, registry.clone()));
        Ok(Self {
            origin,
            registry,
            task,
        })
    }
}

fn cookie(response: &Response) -> String {
    response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .into()
}

async fn login_form(http: &Client, origin: &str, callback: &str) -> Result<Response> {
    Ok(http
        .get(format!("{origin}/oauth/authorize"))
        .query(&[
            ("client_id", "app"),
            ("redirect_uri", callback),
            ("response_type", "code"),
            ("code_challenge_method", "S256"),
            ("code_challenge", &challenge(VERIFIER)),
            ("state", "deployment-state"),
            ("scope", "repository:project/model:pull,push"),
        ])
        .send()
        .await?)
}

// A minimal application token proxy: forwards Origin/Cookie unchanged and
// relays Set-Cookie on the application's /oauth/ path, without exposing refresh
// credentials in JSON or introducing a permissive CORS path.
async fn application_proxy(backend: String) -> Result<ServerTask> {
    use axum::{
        body::{Body, Bytes},
        http::{HeaderMap, StatusCode},
        response::{IntoResponse, Response},
        routing::post,
        Router,
    };
    let app = Router::new().route(
        "/oauth/token",
        post(move |headers: HeaderMap, body: Bytes| {
            let backend = backend.clone();
            async move {
                let mut request = Client::new()
                    .post(format!("{backend}/oauth/token"))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(body);
                for name in ["origin", "cookie"] {
                    if let Some(value) = headers.get(name) {
                        request = request.header(name, value);
                    }
                }
                let upstream = match request.send().await {
                    Ok(r) => r,
                    Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
                };
                let status = upstream.status();
                let headers = upstream.headers().clone();
                let mut reply = Response::new(Body::from(upstream.bytes().await.unwrap()));
                *reply.status_mut() = status;
                *reply.headers_mut() = headers;
                reply
            }
        }),
    );
    let listener = registry::bind("127.0.0.1:0".parse()?).await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Ok(ServerTask { origin, task })
}
struct ServerTask {
    origin: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for ServerTask {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_origin_proxy_login_readiness_throttling_and_remembered_restart() -> Result<()> {
    let root = tempfile::tempdir()?;
    let data = root.path().join("registry");
    provision(&data)?;
    let mut server = Server::start(&data).await?;
    let http = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    for path in ["healthz", "readyz"] {
        let response = http.get(format!("{}/{path}", server.origin)).send().await?;
        assert_eq!(response.status(), 200);
        assert!(response.bytes().await?.is_empty());
    }
    for spoofed in [false, true] {
        let mut request = http.get(format!("{}/oauth/config", server.origin));
        if spoofed {
            request = request
                .header("Host", "attacker.example")
                .header("Forwarded", "host=attacker.example;proto=http")
                .header("X-Forwarded-Host", "attacker.example")
                .header("X-Forwarded-Proto", "http");
        }
        let config: Value = request.send().await?.json().await?;
        assert_eq!(
            config["authorization_endpoint"],
            format!("{PUBLIC}/oauth/authorize")
        );
    }
    let probe = http
        .get(format!("{}/v2/", server.origin))
        .header("Host", "attacker.example")
        .header("X-Forwarded-Host", "attacker.example")
        .send()
        .await?;
    assert!(probe.headers()["www-authenticate"]
        .to_str()?
        .starts_with(&format!("Bearer realm=\"{PUBLIC}/token\"")));
    for wrong in [
        "http://app.example/oauth/callback",
        "https://app.example/oauth/callback/",
        "https://other.example/oauth/callback",
    ] {
        let response = login_form(&http, &server.origin, wrong).await?;
        assert_eq!(response.status(), 400);
        assert!(response.headers().get("location").is_none());
    }
    let page = login_form(&http, &server.origin, CALLBACK).await?;
    assert!(page.headers()["set-cookie"].to_str()?.ends_with("; Secure"));
    let form_cookie = cookie(&page);
    let html = page.text().await?;
    let id = html
        .split("name=\"request_id\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let consent = [
        ("request_id", id),
        ("username", "writer"),
        ("password", PASSWORD),
        ("decision", "allow"),
        ("remember_me", "true"),
    ];
    for wrong in [
        "http://registry.example.com",
        "https://attacker.example",
        "null",
    ] {
        assert_eq!(
            http.post(format!("{}/oauth/authorize", server.origin))
                .header("Origin", wrong)
                .header("X-Forwarded-Host", "registry.example.com")
                .header("X-Forwarded-Proto", "https")
                .header("Cookie", &form_cookie)
                .form(&consent)
                .send()
                .await?
                .status(),
            403
        );
    }
    let authorized = http
        .post(format!("{}/oauth/authorize", server.origin))
        .header("Origin", PUBLIC)
        .header("Host", "private-backend")
        .header("Cookie", &form_cookie)
        .form(&consent)
        .send()
        .await?;
    assert_eq!(authorized.status(), 303);
    assert!(authorized.headers()["set-cookie"]
        .to_str()?
        .ends_with("; Secure"));
    let redirect = Url::parse(authorized.headers()["location"].to_str()?)?;
    let code = redirect
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();
    let proxy = application_proxy(server.origin.clone()).await?;
    let response = http
        .post(format!("{}/oauth/token", proxy.origin))
        .header("Origin", "https://app.example")
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", "app"),
            ("redirect_uri", CALLBACK),
            ("code", &code),
            ("code_verifier", VERIFIER),
        ])
        .send()
        .await?;
    assert_eq!(response.status(), 200);
    assert!(response.headers()["set-cookie"]
        .to_str()?
        .contains("Path=/oauth/; HttpOnly; SameSite=Strict; Max-Age="));
    assert!(response.headers()["set-cookie"]
        .to_str()?
        .ends_with("; Secure"));
    let remembered = cookie(&response);
    let session: Value = response.json().await?;
    assert!(session.get("refresh_token").is_none());
    let access = session["access_token"].as_str().unwrap();
    assert!(server.registry.auth.validate(access).is_ok());

    // Readiness detects both the actual artifact filesystem and database writes.
    fs::rename(data.join("blobs/sha256"), data.join("blobs/saved"))?;
    fs::write(data.join("blobs/sha256"), b"unavailable")?;
    let unavailable = http.get(format!("{}/readyz", server.origin)).send().await?;
    assert_eq!(unavailable.status(), 503);
    assert!(unavailable.bytes().await?.is_empty());
    assert_eq!(
        http.get(format!("{}/healthz", server.origin))
            .send()
            .await?
            .status(),
        200
    );
    fs::remove_file(data.join("blobs/sha256"))?;
    fs::rename(data.join("blobs/saved"), data.join("blobs/sha256"))?;
    let db = rusqlite::Connection::open(data.join("auth.sqlite"))?;
    db.execute("DELETE FROM settings WHERE key='id'", [])?;
    assert_eq!(
        http.get(format!("{}/readyz", server.origin))
            .send()
            .await?
            .status(),
        503
    );
    // Restore identity before replacement, to preserve the token's audience.
    let service = server
        .registry
        .auth
        .service
        .strip_prefix("subsoil:")
        .unwrap();
    db.execute("INSERT INTO settings VALUES ('id',?1)", [service])?;
    assert_eq!(
        http.get(format!("{}/readyz", server.origin))
            .send()
            .await?
            .status(),
        200
    );

    // Correct CLI logins must not spend the browser's failed-login budget (#8310).
    for _ in 0..6 {
        assert_eq!(
            http.get(format!("{}/token", server.origin))
                .basic_auth("writer", Some(PASSWORD))
                .send()
                .await?
                .status(),
            200
        );
    }
    // Browser and OCI password failures still share the account limit.
    for _ in 0..5 {
        assert_eq!(
            http.get(format!("{}/token", server.origin))
                .basic_auth("writer", Some("wrong-password"))
                .send()
                .await?
                .status(),
            401
        );
    }
    let page = login_form(&http, &server.origin, CALLBACK).await?;
    let next_cookie = cookie(&page);
    let html = page.text().await?;
    let id = html
        .split("name=\"request_id\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let throttled = http
        .post(format!("{}/oauth/authorize", server.origin))
        .header("Origin", PUBLIC)
        .header("Cookie", next_cookie)
        .form(&[
            ("request_id", id),
            ("username", "writer"),
            ("password", PASSWORD),
            ("decision", "allow"),
        ])
        .send()
        .await?;
    assert_eq!(throttled.status(), 429);
    assert!(
        throttled.headers()["retry-after"]
            .to_str()?
            .parse::<u64>()?
            > 0
    );
    assert_eq!(
        http.get(format!("{}/token", server.origin))
            .basic_auth("writer", Some(PASSWORD))
            .send()
            .await?
            .status(),
        429
    );

    let signing_key = fs::read(data.join("signing.key"))?;
    drop(proxy);
    server.task.abort();
    let _ = (&mut server.task).await;
    drop(server);
    let server = Server::start(&data).await?;
    assert_eq!(fs::read(data.join("signing.key"))?, signing_key);
    assert!(server.registry.auth.validate(access).is_ok());
    let proxy = application_proxy(server.origin.clone()).await?;
    let refreshed = http
        .post(format!("{}/oauth/token", proxy.origin))
        .header("Origin", "https://app.example")
        .header("Cookie", &remembered)
        .form(&[("grant_type", "refresh_token"), ("client_id", "app")])
        .send()
        .await?;
    assert_eq!(refreshed.status(), 200);
    assert_ne!(cookie(&refreshed), remembered);
    assert!(refreshed.headers()["set-cookie"]
        .to_str()?
        .ends_with("; Secure"));
    let renewed: Value = refreshed.json().await?;
    assert!(renewed.get("refresh_token").is_none());
    assert_eq!(renewed["session_expires_at"], session["session_expires_at"]);
    Ok(())
}

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sigterm_drains_an_inflight_oci_upload() -> Result<()> {
    use std::io::BufRead;
    let root = tempfile::tempdir()?;
    let data = root.path().join("registry");
    provision(&data)?;
    let mut process = Process(
        Command::new(env!("CARGO_BIN_EXE_subsoil"))
            .args(["serve", "--data"])
            .arg(&data)
            .args(["--listen", "127.0.0.1:0"])
            .args(["--cors-origin", "https://app.example.com"])
            .args(["--cors-origin", "http://localhost:3000"])
            .stderr(Stdio::piped())
            .spawn()?,
    );
    let mut line = String::new();
    let mut logs = std::io::BufReader::new(process.0.stderr.take().unwrap());
    logs.read_line(&mut line)?;
    let origin = line
        .split_whitespace()
        .find(|v| v.starts_with("http://"))
        .unwrap();
    let http = Client::new();
    let config = http
        .get(format!("{origin}/oauth/config"))
        .header("Origin", "https://app.example.com")
        .send()
        .await?;
    assert_eq!(
        config.headers()["access-control-allow-origin"],
        "https://app.example.com"
    );
    let config: Value = config.json().await?;
    assert_eq!(
        config["authorization_endpoint"],
        format!("{origin}/oauth/authorize")
    );
    let token: Value = http
        .get(format!("{origin}/token"))
        .basic_auth("writer", Some(PASSWORD))
        .query(&[("scope", "repository:project/model:pull,push")])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let token = token["token"].as_str().unwrap();
    let upload = http
        .post(format!("{origin}/v2/project/model/blobs/uploads/"))
        .bearer_auth(token)
        .send()
        .await?;
    assert_eq!(upload.status(), 202);
    let path = upload.headers()["location"].to_str()?;
    let address = origin.strip_prefix("http://").unwrap();
    let mut stream = std::net::TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    write!(stream, "PUT {path}?digest={} HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {token}\r\nContent-Length: 6\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n", digest(b"abcdef"))?;
    let mut interim = [0; 25];
    stream.read_exact(&mut interim)?;
    assert_eq!(&interim, b"HTTP/1.1 100 Continue\r\n\r\n");
    stream.write_all(b"abc")?;
    ensure!(
        Command::new("kill")
            .args(["-TERM", &process.0.id().to_string()])
            .status()?
            .success(),
        "SIGTERM failed"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        process.0.try_wait()?.is_none(),
        "server exited before upload drained"
    );
    stream.write_all(b"def")?;
    let mut reply = String::new();
    stream.read_to_string(&mut reply)?;
    assert!(reply.starts_with("HTTP/1.1 201"), "{reply}");
    for _ in 0..100 {
        if let Some(status) = process.0.try_wait()? {
            assert!(status.success());
            assert_eq!(
                fs::read(
                    data.join("blobs/sha256")
                        .join(digest(b"abcdef").trim_start_matches("sha256:"))
                )?,
                b"abcdef"
            );
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    anyhow::bail!("server did not finish graceful shutdown")
}
