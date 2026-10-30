use super::*;

fn request() -> Authorization {
    Authorization {
        response_type: "code".into(),
        client_id: "model-client".into(),
        redirect_uri: "http://localhost:3000/oauth/registry/callback".into(),
        state: random(),
        code_challenge: challenge(&"a".repeat(43)),
        code_challenge_method: "S256".into(),
        scope: "repository:project/model:pull,push".into(),
        launch_request: None,
    }
}

#[test]
fn s256_rfc7636_vector_randomness_and_redirect_policy() -> Result<()> {
    assert_eq!(
        challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
    let values: std::collections::HashSet<_> = (0..100).map(|_| random()).collect();
    assert_eq!(values.len(), 100);
    assert!(values.iter().all(|v| v.len() == 43));
    let oauth = OAuth::default();
    for id in ["", "has a space", "<script>"] {
        assert!(oauth
            .configure(id, &["http://localhost:3000/callback".into()])
            .is_err());
    }
    assert!(oauth.configure("model-client", &[]).is_err());
    for invalid in [
        "https://example.com/callback?x=y",
        "https://example.com/#fragment",
        "https://user@example.com/callback",
        "http://example.com/callback",
        "javascript:alert(1)",
    ] {
        assert!(
            oauth.configure("model-client", &[invalid.into()]).is_err(),
            "{invalid}"
        );
    }
    oauth.configure(
        "model-client",
        &[
            "https://viewer.example.com/callback".into(),
            "http://127.0.0.1:3000/callback".into(),
            "http://[::1]:3000/callback".into(),
        ],
    )?;
    Ok(())
}

#[tokio::test]
async fn code_exchange_binds_client_callback_verifier_expiry_and_is_single_use() -> Result<()> {
    let root = tempfile::tempdir()?;
    let registry = Registry::open(root.path())?;
    registry.auth.add_user(
        "reader",
        "reader-test-password",
        &["project/model:pull".into()],
    )?;
    for bad in [
        "verifier", "short", "client", "redirect", "grant", "expired", "valid",
    ] {
        let code = random();
        let req = request();
        registry.oauth.inner.lock().unwrap().codes.insert(
            code.clone(),
            Code {
                permissions: registry.auth.grants("reader")?,
                request: req.clone(),
                user: "reader".into(),
                remember: false,
                launch: None,
                expires: if bad == "expired" { now() } else { now() + 60 },
            },
        );
        let mut input = Exchange {
            grant_type: "authorization_code".into(),
            client_id: req.client_id,
            redirect_uri: req.redirect_uri,
            code: code.clone(),
            code_verifier: "a".repeat(43),
            refresh_token: None,
        };
        match bad {
            "verifier" => input.code_verifier = "b".repeat(43),
            "short" => input.code_verifier = "a".into(),
            "client" => input.client_id = "attacker".into(),
            "redirect" => input.redirect_uri.push_str("/other"),
            "grant" => input.grant_type = "password".into(),
            _ => {}
        }
        let response = exchange(State(registry.clone()), HeaderMap::new(), Form(input)).await;
        assert_eq!(
            response.status(),
            if bad == "valid" {
                StatusCode::OK
            } else {
                StatusCode::BAD_REQUEST
            },
            "{bad}"
        );
        assert_eq!(response.headers()["cache-control"], "no-store");
        if bad == "valid" {
            let bytes = axum::body::to_bytes(response.into_body(), 65536).await?;
            let reply: serde_json::Value = serde_json::from_slice(&bytes)?;
            assert_eq!(reply["access"][0]["actions"], json!(["pull"]));
            assert_eq!(reply["expires_in"], 900);
            assert_eq!(reply["subject"], "reader");
            registry
                .auth
                .validate(reply["access_token"].as_str().unwrap())?;
        }
        let replay = Exchange {
            grant_type: "authorization_code".into(),
            client_id: "model-client".into(),
            redirect_uri: request().redirect_uri,
            code,
            code_verifier: "a".repeat(43),
            refresh_token: None,
        };
        assert_eq!(
            exchange(State(registry.clone()), HeaderMap::new(), Form(replay))
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    Ok(())
}

#[tokio::test]
async fn authorization_requires_registration_s256_and_exact_redirect_without_redirecting_errors(
) -> Result<()> {
    let root = tempfile::tempdir()?;
    let registry = Registry::open(root.path())?;
    assert_eq!(
        authorize(State(registry.clone()), Query(request()))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    registry
        .oauth
        .configure("model-client", &[request().redirect_uri])?;
    for bad in [
        "client",
        "redirect",
        "plain",
        "missing_state",
        "challenge",
        "scope",
        "response",
    ] {
        let mut req = request();
        match bad {
            "client" => req.client_id = "attacker".into(),
            "redirect" => req.redirect_uri.push_str("/unregistered"),
            "plain" => req.code_challenge_method = "plain".into(),
            "missing_state" => req.state.clear(),
            "challenge" => req.code_challenge = "short".into(),
            "scope" => req.scope = "repository:project/model:admin".into(),
            "response" => req.response_type = "token".into(),
            _ => unreachable!(),
        }
        let response = authorize(State(registry.clone()), Query(req)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{bad}");
        assert!(response.headers().get("location").is_none());
    }
    let response = authorize(State(registry.clone()), Query(request())).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers()["set-cookie"]
        .to_str()?
        .contains("HttpOnly; SameSite=Strict"));
    registry
        .oauth
        .inner
        .lock()
        .unwrap()
        .forms
        .values_mut()
        .for_each(|p| p.expires = now());
    registry.oauth.inner.lock().unwrap().prune();
    assert!(registry.oauth.inner.lock().unwrap().forms.is_empty());
    Ok(())
}

#[tokio::test]
async fn login_retry_escapes_input_and_does_not_expand_user_supplied_template_fields() -> Result<()>
{
    let pending = Pending {
        request: request(),
        cookie: random(),
        expires: now() + 300,
        launch: None,
    };
    let input = "\"><img src=x onerror=alert(1)>{{request_id}}";
    let response = page::form(
        "test-form-id",
        &pending,
        "<script>alert(1)</script>",
        input,
        false,
    );
    let bytes = axum::body::to_bytes(response.into_body(), 65536).await?;
    let html = String::from_utf8(bytes.to_vec())?;
    assert_eq!(html.matches("<img ").count(), 1);
    assert!(html.contains("<img src=\"/brand/logo.svg\""));
    assert!(!html.contains("<img src=x") && !html.contains("<script>"));
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(html.contains("&quot;&gt;&lt;img src=x onerror=alert(1)&gt;{{request_id}}"));
    Ok(())
}

#[tokio::test]
async fn session_code_preserves_permissions_captured_at_consent() -> Result<()> {
    let root = tempfile::tempdir()?;
    let registry = Registry::open(root.path())?;
    registry.auth.add_user(
        "reader",
        "reader-test-password",
        &["project/model:pull".into()],
    )?;
    let approved = registry.auth.grants("reader")?;
    let mut request = request();
    request.scope = crate::auth::SESSION_SCOPE.into();
    let code = random();
    registry.oauth.inner.lock().unwrap().codes.insert(
        code.clone(),
        Code {
            permissions: approved,
            request: request.clone(),
            user: "reader".into(),
            expires: now() + 60,
            remember: false,
            launch: None,
        },
    );
    registry.auth.grant("reader", "project/model:push")?;
    registry.auth.grant("reader", "private/model:pull")?;
    let response = exchange(
        State(registry.clone()),
        HeaderMap::new(),
        Form(Exchange {
            grant_type: "authorization_code".into(),
            client_id: request.client_id,
            redirect_uri: request.redirect_uri,
            code,
            code_verifier: "a".repeat(43),
            refresh_token: None,
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 65536).await?;
    let reply: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(reply["authorization_type"], "session");
    let root = registry
        .auth
        .validate(reply["access_token"].as_str().unwrap())?;
    assert!(root.access.iter().all(|a| a.kind == "registry"));
    let (_, resource) = registry.auth.exchange(
        &root,
        &[
            "repository:project/model:pull,push".into(),
            "repository:private/model:pull".into(),
        ],
    )?;
    assert_eq!(resource.access[0].actions, vec!["pull"]);
    assert!(resource.access[1].actions.is_empty());
    Ok(())
}
