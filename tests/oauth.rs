use anyhow::Result;
use ifcx_oci::{
    oauth::challenge,
    registry::{self, Registry},
};
use reqwest::{Client, Url};
use serde_json::Value;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn browser_consent_pkce_cookie_csrf_denial_and_scoped_registry_session() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let registry = Registry::open(temp.path().join("registry"))?;
    registry.auth.add_user(
        "reader",
        "test-registry-password",
        &["project/model:pull".into()],
    )?;
    let callback = "http://localhost:3000/oauth/registry/callback";
    registry
        .oauth
        .configure("model-client", &[callback.into()])?;
    registry.set_cors_origins(&["http://localhost:3000".into()])?;
    let listener = registry::bind("127.0.0.1:0".parse()?).await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let running = tokio::spawn(registry::serve(listener, registry.clone()));
    struct Stop(tokio::task::JoinHandle<Result<()>>);
    impl Drop for Stop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _stop = Stop(running);
    let http = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let config: Value = http
        .get(format!("{origin}/oauth/config"))
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(config["client_id"], "model-client");
    assert_eq!(
        config["authorization_endpoint"],
        format!("{origin}/oauth/authorize")
    );
    assert_eq!(config["token_endpoint"], "/oauth/token");
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let mut authorization = Url::parse(&format!("{origin}/oauth/authorize"))?;
    authorization.query_pairs_mut().extend_pairs([
        ("response_type", "code"),
        ("client_id", "model-client"),
        ("redirect_uri", callback),
        (
            "scope",
            "registry:catalog:read repository:project/model:pull,push",
        ),
        ("code_challenge", challenge(verifier).as_str()),
        ("code_challenge_method", "S256"),
        ("state", "browser-state-unguessable-per-attempt"),
    ]);
    for deny in [true, false] {
        let page = http.get(authorization.clone()).send().await?;
        assert_eq!(page.status(), 200);
        assert!(!page.headers().contains_key("access-control-allow-origin"));
        assert_eq!(page.headers()["x-frame-options"], "DENY");
        assert_eq!(page.headers()["referrer-policy"], "same-origin");
        assert!(page.headers()["content-security-policy"]
            .to_str()?
            .contains("form-action 'self' http://localhost:3000"));
        let cookie = page.headers()["set-cookie"]
            .to_str()?
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let html = page.text().await?;
        let id = html
            .split("name=\"request_id\" value=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        let form = [
            ("request_id", id),
            ("username", "reader"),
            ("password", "test-registry-password"),
            ("decision", if deny { "deny" } else { "allow" }),
        ];
        // Neither a missing cookie nor another application's origin may authorize this form.
        assert_eq!(
            http.post(format!("{origin}/oauth/authorize"))
                .header("Origin", &origin)
                .form(&form)
                .send()
                .await?
                .status(),
            403
        );
        assert_eq!(
            http.post(format!("{origin}/oauth/authorize"))
                .header("Origin", "http://localhost:3000")
                .header("Cookie", &cookie)
                .form(&form)
                .send()
                .await?
                .status(),
            403
        );
        if !deny {
            let mut wrong = form;
            wrong[2] = ("password", "wrong-password");
            let failed = http
                .post(format!("{origin}/oauth/authorize"))
                .header("Origin", &origin)
                .header("Cookie", &cookie)
                .form(&wrong)
                .send()
                .await?;
            assert!(failed.headers().get("location").is_none());
            assert!(failed.text().await?.contains("Sign-in failed"));
        }
        let response = http
            .post(format!("{origin}/oauth/authorize"))
            .header("Origin", &origin)
            .header("Cookie", &cookie)
            .form(&form)
            .send()
            .await?;
        assert_eq!(response.status(), 303);
        let redirect = Url::parse(response.headers()["location"].to_str()?)?;
        let params: std::collections::HashMap<_, _> = redirect.query_pairs().collect();
        assert_eq!(params["state"], "browser-state-unguessable-per-attempt");
        assert!(!redirect.as_str().contains("access_token"));
        // Forms, like codes, cannot be approved twice.
        assert_eq!(
            http.post(format!("{origin}/oauth/authorize"))
                .header("Origin", &origin)
                .header("Cookie", &cookie)
                .form(&form)
                .send()
                .await?
                .status(),
            400
        );
        if deny {
            assert_eq!(params["error"], "access_denied");
            assert!(!params.contains_key("code"));
            continue;
        }
        let exchange = [
            ("grant_type", "authorization_code"),
            ("client_id", "model-client"),
            ("redirect_uri", callback),
            ("code", &params["code"]),
            ("code_verifier", verifier),
        ];
        let response = http
            .post(format!("{origin}/oauth/token"))
            .header("Origin", "http://localhost:3000")
            .form(&exchange)
            .send()
            .await?;
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.headers()["access-control-allow-origin"],
            "http://localhost:3000"
        );
        assert_eq!(response.headers()["cache-control"], "no-store");
        let session: Value = response.json().await?;
        assert_eq!(session["subject"], "reader");
        assert_eq!(session["expires_in"], 900);
        let token = session["access_token"].as_str().unwrap();
        assert_eq!(
            http.get(format!("{origin}/v2/"))
                .bearer_auth(token)
                .send()
                .await?
                .status(),
            200
        );
        assert_eq!(
            http.post(format!("{origin}/v2/project/model/blobs/uploads/"))
                .bearer_auth(token)
                .send()
                .await?
                .status(),
            403
        );
        assert_eq!(
            http.get(format!("{origin}/v2/private/model/tags/list"))
                .bearer_auth(token)
                .send()
                .await?
                .status(),
            403
        );
        let claims = registry.auth.validate(token)?;
        assert!(registry.auth.permits(&claims, "project/model", "pull")?);
        assert!(!registry.auth.permits(&claims, "project/model", "push")?);
        assert_eq!(
            http.post(format!("{origin}/oauth/token"))
                .form(&exchange)
                .send()
                .await?
                .status(),
            400
        );
    }
    assert_eq!(
        http.get(format!("{origin}/oauth/token"))
            .send()
            .await?
            .status(),
        405
    );
    Ok(())
}
