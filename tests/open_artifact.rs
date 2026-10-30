use anyhow::Result;
use reqwest::{Client, Response, Url};
use serde_json::{json, Value};
use std::sync::Arc;
use subsoil::{
    applications::Applications,
    auth::{now, SESSION_SCOPE},
    oauth::challenge,
    policy::{Grant, GrantSet},
    registry::{self, Registry},
    release::digest,
};

const REPO: &str = "project/model";
const CLIENT: &str = "model-editor";
const CALLBACK: &str = "http://localhost:3000/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const PASSWORD: &str = "launch-test-password";

fn configuration() -> Value {
    json!({"version":1,"profiles":[
        {"id":"urn:example:model:1","artifact_type":"application/vnd.example.model.v1","config_media_type":"application/json"},
        {"id":"urn:example:report:1","artifact_type":"application/vnd.example.report.v1","config_media_type":"application/json"}
    ],"applications":[
        {"id":CLIENT,"name":"Model editor","launch_url":"http://localhost:3000/open","redirect_uris":[CALLBACK],
         "cors_origins":["http://localhost:3000"],"supports":[{"profile":"urn:example:model:1","intents":["view","edit"],"publish":true}]},
        {"id":"file-viewer","name":"File viewer","launch_url":"http://localhost:4000/open","redirect_uris":["http://localhost:4000/callback"],
         "supports":[{"profile":"urn:example:model:1","intents":["view"]},{"profile":"urn:example:report:1","intents":["view"]}]}
    ]})
}

fn cookies(response: &Response) -> String {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap().to_string())
        .filter(|value| !value.ends_with('='))
        .collect::<Vec<_>>()
        .join("; ")
}

fn form_id(html: &str) -> &str {
    html.split("name=\"request_id\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
}

fn code_from(response: &Response) -> String {
    let url = Url::parse(response.headers()["location"].to_str().unwrap()).unwrap();
    url.query_pairs()
        .find(|(key, _)| key == "code")
        .unwrap()
        .1
        .into_owned()
}

struct Fixture {
    temp: tempfile::TempDir,
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
    async fn browser_login(&self, user: &str) -> Result<(Value, String)> {
        let callback = format!("{}/explore", self.origin);
        let page = self
            .http
            .get(format!("{}/oauth/authorize", self.origin))
            .query(&[
                ("response_type", "code"),
                ("client_id", "subsoil-explorer"),
                ("redirect_uri", &callback),
                ("scope", SESSION_SCOPE),
                ("state", "browser-login-state"),
                ("code_challenge_method", "S256"),
                ("code_challenge", &challenge(VERIFIER)),
            ])
            .send()
            .await?;
        assert_eq!(page.status(), 200);
        let csrf = cookies(&page);
        let html = page.text().await?;
        let consent = self
            .http
            .post(format!("{}/oauth/authorize", self.origin))
            .header("Origin", &self.origin)
            .header("Cookie", csrf)
            .form(&[
                ("request_id", form_id(&html)),
                ("username", user),
                ("password", PASSWORD),
                ("decision", "allow"),
            ])
            .send()
            .await?;
        assert_eq!(consent.status(), 303, "{}", consent.text().await?);
        let binding = cookies(&consent);
        assert!(binding.starts_with("subsoil_browser="));
        let attributes = consent
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find(|v| v.starts_with("subsoil_browser="))
            .unwrap();
        assert!(attributes.contains("HttpOnly; SameSite=Lax; Path=/"));
        assert!(!attributes.contains("Max-Age"));
        let response = self
            .http
            .post(format!("{}/oauth/token", self.origin))
            .form(&[
                ("grant_type", "authorization_code"),
                ("client_id", "subsoil-explorer"),
                ("redirect_uri", &callback),
                ("code", &code_from(&consent)),
                ("code_verifier", VERIFIER),
            ])
            .send()
            .await?;
        assert_eq!(response.status(), 200);
        Ok((response.json().await?, binding))
    }

    async fn browser_launch(
        &self,
        root: &str,
        binding: &str,
        edit: bool,
        explicit: bool,
    ) -> Result<(Value, String)> {
        let mut request = self.request(edit);
        request["ttl"] = json!(900);
        if edit {
            request["publish"]["allowed_tags"] = json!(["*"]);
        }
        if explicit {
            request["decision"] = json!("open");
        }
        let response = self
            .http
            .post(format!("{}/open-artifact/launches", self.origin))
            .header("Origin", &self.origin)
            .header("Cookie", binding)
            .bearer_auth(root)
            .json(&request)
            .send()
            .await?;
        assert_eq!(response.status(), 200, "{}", response.text().await?);
        assert!(response.headers()["set-cookie"]
            .to_str()?
            .contains("HttpOnly; SameSite=Lax; Path=/oauth/authorize"));
        let proof = cookies(&response);
        let proof = if proof.contains("subsoil_browser=") {
            proof
        } else {
            format!("{proof}; {binding}")
        };
        Ok((response.json().await?, proof))
    }

    async fn bound_authorize(
        &self,
        launch: &Value,
        proof: &str,
        prompt: Option<&str>,
    ) -> Result<Response> {
        let mut query = vec![
            ("response_type", "code".to_string()),
            ("client_id", CLIENT.into()),
            ("redirect_uri", CALLBACK.into()),
            ("scope", SESSION_SCOPE.into()),
            ("state", "bound-launch-state".into()),
            ("code_challenge_method", "S256".into()),
            ("code_challenge", challenge(VERIFIER)),
            (
                "launch_request",
                launch["request_id"].as_str().unwrap().into(),
            ),
        ];
        if let Some(prompt) = prompt {
            query.push(("prompt", prompt.into()));
        }
        Ok(self
            .http
            .get(format!("{}/oauth/authorize", self.origin))
            .header("Cookie", proof)
            .query(&query)
            .send()
            .await?)
    }

    async fn bound_consent(
        &self,
        page: Response,
        proof: &str,
        user: &str,
        password: &str,
    ) -> Result<Response> {
        let csrf = cookies(&page);
        let html = page.text().await?;
        Ok(self
            .http
            .post(format!("{}/oauth/authorize", self.origin))
            .header("Origin", &self.origin)
            .header("Cookie", format!("{proof}; {csrf}"))
            .form(&[
                ("request_id", form_id(&html)),
                ("username", user),
                ("password", password),
                ("decision", "allow"),
            ])
            .send()
            .await?)
    }

    async fn new() -> Result<Self> {
        let temp = tempfile::tempdir()?;
        let registry = Registry::open(temp.path())?;
        registry.auth.add_user("owner", PASSWORD, &[])?;
        registry.auth.add_rule(
            "owner",
            &Grant::exact(REPO.into(), vec!["pull".into(), "push".into()]),
        )?;
        registry
            .auth
            .add_user("reader", PASSWORD, &[format!("{REPO}:pull")])?;
        registry
            .configure_applications(Applications::parse(&serde_json::to_vec(&configuration())?)?)?;
        registry.set_cors_origins(&["http://localhost:3000".into()])?;
        let listener = registry::bind("127.0.0.1:0".parse()?).await?;
        let origin = format!("http://{}", listener.local_addr()?);
        registry.set_public_url(&origin)?;
        let running = tokio::spawn(registry::serve(listener, registry.clone()));
        let http = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            temp,
            registry,
            http,
            origin,
            running,
        })
    }

    fn root(&self, user: &str) -> Result<String> {
        Ok(self
            .registry
            .auth
            .start_session(
                user,
                &[SESSION_SCOPE.into()],
                "subsoil-explorer",
                &format!("{}/explore", self.origin),
                false,
            )?
            .access_token)
    }

    fn write_token(&self) -> Result<String> {
        Ok(self
            .registry
            .auth
            .issue("owner", &[format!("repository:{REPO}:pull,push")], 900)?
            .0)
    }

    async fn publish(
        &self,
        token: &str,
        tag: &str,
        text: &str,
        artifact_type: &str,
    ) -> Result<(String, String)> {
        let blob = digest(text.as_bytes());
        let upload = self
            .http
            .post(format!(
                "{}/v2/{REPO}/blobs/uploads/?digest={blob}",
                self.origin
            ))
            .bearer_auth(token)
            .body(text.to_string())
            .send()
            .await?;
        assert_eq!(upload.status(), 201, "{}", upload.text().await?);
        let raw = serde_json::to_vec(
            &json!({"schemaVersion":2,"mediaType":registry::MANIFEST_TYPE,
            "artifactType":artifact_type,"config":{"mediaType":"application/json","digest":blob,"size":text.len()},"layers":[]}),
        )?;
        let result = self
            .http
            .put(format!("{}/v2/{REPO}/manifests/{tag}", self.origin))
            .bearer_auth(token)
            .body(raw.clone())
            .send()
            .await?;
        assert_eq!(result.status(), 201, "{}", result.text().await?);
        Ok((digest(&raw), blob))
    }

    async fn model(&self, tag: &str, text: &str) -> Result<(String, String)> {
        self.publish(
            &self.write_token()?,
            tag,
            text,
            "application/vnd.example.model.v1",
        )
        .await
    }

    fn request(&self, edit: bool) -> Value {
        let mut request = json!({"application_id":CLIENT,"repository":REPO,"reference":"issued","intent":if edit {"edit"} else {"view"},"ttl":600});
        if edit {
            request["publish"] = json!({"repository":REPO,"allowed_tags":["review-*"]});
        }
        request
    }

    async fn create(&self, root: &str, request: &Value) -> Result<Response> {
        Ok(self
            .http
            .post(format!("{}/open-artifact/launches", self.origin))
            .bearer_auth(root)
            .json(request)
            .send()
            .await?)
    }

    async fn launch(&self, root: &str, edit: bool) -> Result<(Value, String)> {
        let response = self.create(root, &self.request(edit)).await?;
        assert_eq!(response.status(), 200, "{}", response.text().await?);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let cookie = response
            .headers()
            .get("set-cookie")
            .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_string())
            .unwrap_or_default();
        Ok((response.json().await?, cookie))
    }

    async fn authorization(
        &self,
        launch: &Value,
        client: &str,
        callback: &str,
    ) -> Result<Response> {
        Ok(self
            .http
            .get(format!("{}/oauth/authorize", self.origin))
            .query(&[
                ("response_type", "code"),
                ("client_id", client),
                ("redirect_uri", callback),
                ("scope", SESSION_SCOPE),
                ("state", "per-transaction-state"),
                ("code_challenge_method", "S256"),
                ("code_challenge", &challenge(VERIFIER)),
                ("launch_request", launch["request_id"].as_str().unwrap()),
            ])
            .send()
            .await?)
    }

    async fn approve(&self, launch: &Value, guest_cookie: &str, user: &str) -> Result<String> {
        let page = self.authorization(launch, CLIENT, CALLBACK).await?;
        assert_eq!(page.status(), 200, "{}", page.text().await?);
        assert!(!page.headers().contains_key("access-control-allow-origin"));
        let cookie = page.headers()["set-cookie"]
            .to_str()?
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let html = page.text().await?;
        if !guest_cookie.is_empty() {
            assert!(html.contains("Open shared files"));
        }
        assert!(html.contains(REPO));
        assert!(html.contains("Model editor"));
        let id = html
            .split("name=\"request_id\" value=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        let form = [
            ("request_id", id),
            ("username", user),
            (
                "password",
                if guest_cookie.is_empty() {
                    PASSWORD
                } else {
                    ""
                },
            ),
            ("decision", "allow"),
        ];
        // The request ID and the form cookie alone cannot authorize a delegated launch.
        if !guest_cookie.is_empty() {
            assert_eq!(
                self.http
                    .post(format!("{}/oauth/authorize", self.origin))
                    .header("Origin", &self.origin)
                    .header("Cookie", &cookie)
                    .form(&form)
                    .send()
                    .await?
                    .status(),
                403
            );
        }
        let response = self
            .http
            .post(format!("{}/oauth/authorize", self.origin))
            .header("Origin", &self.origin)
            .header("Cookie", format!("{cookie}; {guest_cookie}"))
            .form(&form)
            .send()
            .await?;
        assert_eq!(response.status(), 303, "{}", response.text().await?);
        let url = Url::parse(response.headers()["location"].to_str()?)?;
        assert!(url
            .query_pairs()
            .any(|(k, v)| k == "iss" && v == self.origin));
        Ok(url
            .query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .into_owned())
    }

    async fn exchange(&self, code: &str, client: &str, verifier: &str) -> Result<Response> {
        Ok(self
            .http
            .post(format!("{}/oauth/token", self.origin))
            .header("Origin", "http://localhost:3000")
            .form(&[
                ("grant_type", "authorization_code"),
                ("client_id", client),
                ("redirect_uri", CALLBACK),
                ("code", code),
                ("code_verifier", verifier),
            ])
            .send()
            .await?)
    }

    async fn scoped(&self, root: &str) -> Result<String> {
        let response = self
            .http
            .get(format!("{}/token", self.origin))
            .bearer_auth(root)
            .query(&[("scope", format!("repository:{REPO}:pull,push"))])
            .send()
            .await?;
        assert_eq!(response.status(), 200, "{}", response.text().await?);
        Ok(response.json::<Value>().await?["access_token"]
            .as_str()
            .unwrap()
            .into())
    }

    async fn get(&self, path: &str, token: &str) -> Result<Response> {
        Ok(self
            .http
            .get(format!("{}{path}", self.origin))
            .bearer_auth(token)
            .send()
            .await?)
    }
}

#[test]
fn registration_validates_profiles_applications_callbacks_and_origins() -> Result<()> {
    Applications::parse(&serde_json::to_vec(&configuration())?)?;
    for bad in [
        "version",
        "duplicate_profile",
        "duplicate_format",
        "duplicate_app",
        "unknown_profile",
        "callback_origin",
        "launch_query",
        "remote_http",
        "cors_path",
        "reserved",
        "unknown_field",
    ] {
        let mut config = configuration();
        match bad {
            "version" => config["version"] = json!(2),
            "duplicate_profile" => {
                config["profiles"][1]["id"] = config["profiles"][0]["id"].clone()
            }
            "duplicate_format" => {
                config["profiles"][1]["artifact_type"] =
                    config["profiles"][0]["artifact_type"].clone()
            }
            "duplicate_app" => config["applications"][1]["id"] = json!(CLIENT),
            "unknown_profile" => {
                config["applications"][0]["supports"][0]["profile"] = json!("urn:unknown")
            }
            "callback_origin" => {
                config["applications"][0]["redirect_uris"] =
                    json!(["https://other.example/callback"])
            }
            "launch_query" => {
                config["applications"][0]["launch_url"] =
                    json!("https://app.example/open?redirect=elsewhere")
            }
            "remote_http" => {
                config["applications"][0]["launch_url"] = json!("http://app.example/open")
            }
            "cors_path" => {
                config["applications"][0]["cors_origins"] = json!(["http://localhost:3000/prefix"])
            }
            "reserved" => config["applications"][0]["id"] = json!("subsoil-explorer"),
            "unknown_field" => config["unrecognized"] = json!(true),
            _ => unreachable!(),
        }
        assert!(
            Applications::parse(&serde_json::to_vec(&config)?).is_err(),
            "{bad}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn account_launch_pins_source_and_publishes_only_new_allowed_versions() -> Result<()> {
    let fixture = Fixture::new().await?;
    let (source, source_blob) = fixture.model("issued", "source").await?;
    let (hidden, hidden_blob) = fixture.model("private", "private").await?;
    let (launch, cookie) = fixture.launch(&fixture.root("owner")?, true).await?;
    assert!(cookie.starts_with("subsoil_launch_"));
    let url = Url::parse(launch["launch_url"].as_str().unwrap())?;
    assert_eq!(url.origin().ascii_serialization(), "http://localhost:3000");
    assert!(!url.as_str().contains("token"));
    let code = fixture.approve(&launch, "", "owner").await?;
    let response = fixture.exchange(&code, CLIENT, VERIFIER).await?;
    assert_eq!(response.status(), 200, "{}", response.text().await?);
    assert!(!response.headers().contains_key("set-cookie"));
    let session: Value = response.json().await?;
    assert_eq!(session["open_artifact"]["source"]["digest"], source);
    assert_eq!(
        session["open_artifact"]["source"]["profile"],
        "urn:example:model:1"
    );
    assert_eq!(session["permissions"].as_array().unwrap().len(), 2);
    assert!(session["expires_in"].as_u64().unwrap() <= 600);
    assert_eq!(
        fixture.exchange(&code, CLIENT, VERIFIER).await?.status(),
        400
    );
    let token = fixture
        .scoped(session["access_token"].as_str().unwrap())
        .await?;
    for value in [&source, &source_blob] {
        let kind = if value == &source {
            "manifests"
        } else {
            "blobs"
        };
        assert_eq!(
            fixture
                .get(&format!("/v2/{REPO}/{kind}/{value}"), &token)
                .await?
                .status(),
            200
        );
    }
    for (kind, value) in [("manifests", hidden), ("blobs", hidden_blob)] {
        assert_eq!(
            fixture
                .get(&format!("/v2/{REPO}/{kind}/{value}"), &token)
                .await?
                .status(),
            403
        );
    }
    fixture
        .publish(
            &token,
            "review-1",
            "edited model",
            "application/vnd.example.model.v1",
        )
        .await?;
    let overwrite = fixture
        .http
        .put(format!("{}/v2/{REPO}/manifests/issued", fixture.origin))
        .bearer_auth(&token)
        .body("{}")
        .send()
        .await?;
    assert_eq!(overwrite.status(), 403);
    let (_, claims) = fixture.registry.auth.exchange(
        &fixture
            .registry
            .auth
            .validate(session["access_token"].as_str().unwrap())?,
        &["repository:private/model:pull,push".into()],
    )?;
    assert!(claims.access[0].actions.is_empty());
    // The derived authorization and uploaded version survive restarting the store.
    Registry::open(fixture.temp.path())?.auth.validate(&token)?;
    Ok(())
}

#[tokio::test]
async fn chooser_defaults_keep_intent_separate_and_let_the_app_choose_version_names() -> Result<()>
{
    let fixture = Fixture::new().await?;
    fixture.model("issued", "model").await?;
    let owner = fixture.root("owner")?;
    let path = format!("/open-artifact/applications?repository={REPO}&reference=issued");
    let discovery: Value = fixture.get(&path, &owner).await?.json().await?;
    let editor = &discovery["applications"][0];
    assert_eq!(
        editor["launches"]["view"],
        json!({"intent":"view","ttl":900})
    );
    assert_eq!(
        editor["launches"]["edit"]["publish"],
        json!({"repository":REPO,"allowed_tags":["*"]})
    );
    let mut request = editor["launches"]["edit"].clone();
    request["application_id"] = json!(CLIENT);
    request["repository"] = json!(REPO);
    request["reference"] = discovery["digest"].clone();
    let launched: Value = fixture.create(&owner, &request).await?.json().await?;
    let code = fixture.approve(&launched, "", "owner").await?;
    let session: Value = fixture
        .exchange(&code, CLIENT, VERIFIER)
        .await?
        .json()
        .await?;
    let token = fixture
        .scoped(session["access_token"].as_str().unwrap())
        .await?;
    fixture
        .publish(
            &token,
            "chosen-in-the-editor",
            "edited",
            "application/vnd.example.model.v1",
        )
        .await?;

    let reader = fixture.root("reader")?;
    let discovery: Value = fixture.get(&path, &reader).await?.json().await?;
    assert!(discovery["applications"][0]["launches"]["edit"].is_null());
    assert_eq!(
        discovery["applications"][0]["launches"]["view"]["intent"],
        "view"
    );

    let policy = GrantSet {
        version: 1,
        registry: Url::parse(&fixture.origin)?.authority().into(),
        grants: vec![
            Grant {
                repositories: vec![REPO.into()],
                tags: Some(vec!["issued".into()]),
                actions: vec!["pull".into()],
                digests: None,
            },
            Grant {
                repositories: vec![REPO.into()],
                tags: Some(vec!["review-*".into()]),
                actions: vec!["push".into()],
                digests: None,
            },
        ],
    };
    fixture.registry.auth.set_grants("owner", &policy)?;
    let discovery: Value = fixture.get(&path, &owner).await?.json().await?;
    assert_eq!(
        discovery["applications"][0]["launches"]["edit"]["publish"]["allowed_tags"],
        json!(["review-*"])
    );
    let share = fixture
        .registry
        .create_share(
            "owner",
            &GrantSet {
                grants: vec![policy.grants[0].clone()],
                ..policy
            },
            600,
            subsoil::auth::ShareBinding::Snapshot,
        )
        .await?;
    let (root, _, _) = fixture.registry.auth.redeem_share(&share.secret)?;
    let discovery: Value = fixture.get(&path, &root).await?.json().await?;
    assert!(discovery["applications"][0]["launches"]["edit"].is_null());
    Ok(())
}

#[tokio::test]
async fn signed_in_registry_decision_opens_exact_view_or_edit_without_duplicate_credentials(
) -> Result<()> {
    let fixture = Fixture::new().await?;
    let (digest, _) = fixture.model("issued", "source").await?;
    let (login, binding) = fixture.browser_login("owner").await?;
    assert!(login["permissions"]
        .as_array()
        .unwrap()
        .iter()
        .all(|g| g["actions"] == json!(["pull"])));
    for edit in [false, true] {
        let (launch, proof) = fixture
            .browser_launch(
                login["access_token"].as_str().unwrap(),
                &binding,
                edit,
                true,
            )
            .await?;
        let response = fixture.bound_authorize(&launch, &proof, None).await?;
        assert_eq!(response.status(), 303, "{}", response.text().await?);
        assert!(!response.headers()["location"]
            .to_str()?
            .contains(login["access_token"].as_str().unwrap()));
        let code = code_from(&response);
        let response = fixture.exchange(&code, CLIENT, VERIFIER).await?;
        assert_eq!(response.status(), 200, "{}", response.text().await?);
        let session: Value = response.json().await?;
        assert_eq!(session["subject"], "owner");
        assert_eq!(session["open_artifact"]["source"]["digest"], digest);
        assert_eq!(
            session["open_artifact"]["intent"],
            if edit { "edit" } else { "view" }
        );
        let token = fixture
            .scoped(session["access_token"].as_str().unwrap())
            .await?;
        let claims = fixture.registry.auth.validate(&token)?;
        assert_eq!(fixture.registry.auth.permits(&claims, REPO, "push")?, edit);
        assert_eq!(
            fixture
                .bound_authorize(&launch, &proof, None)
                .await?
                .status(),
            400
        );
        assert_eq!(
            fixture.exchange(&code, CLIENT, VERIFIER).await?.status(),
            400
        );
        if !edit {
            let (broader, receiver_proof) = fixture
                .browser_launch(
                    session["access_token"].as_str().unwrap(),
                    &binding,
                    true,
                    false,
                )
                .await?;
            let page = fixture
                .bound_authorize(&broader, &receiver_proof, None)
                .await?;
            assert_eq!(page.status(), 200);
            assert!(!page.text().await?.contains("<fieldset hidden disabled"));
        }
    }
    // An identity marker is never a registry API token.
    assert!(fixture
        .registry
        .auth
        .validate(binding.strip_prefix("subsoil_browser=").unwrap())
        .is_err());
    Ok(())
}

#[tokio::test]
async fn authenticated_api_launch_shows_consent_and_prompt_login_requires_fresh_credentials(
) -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.model("issued", "source").await?;
    let (login, binding) = fixture.browser_login("owner").await?;
    for prompt in [None, Some("consent"), Some("login")] {
        let (launch, proof) = fixture
            .browser_launch(
                login["access_token"].as_str().unwrap(),
                &binding,
                false,
                prompt.is_some(),
            )
            .await?;
        let page = fixture.bound_authorize(&launch, &proof, prompt).await?;
        assert_eq!(page.status(), 200);
        let csrf = cookies(&page);
        let html = page.text().await?;
        assert_eq!(
            html.contains("<fieldset hidden disabled"),
            prompt != Some("login")
        );
        let form = [("request_id", form_id(&html)), ("decision", "allow")];
        let csrf_denied = fixture
            .http
            .post(format!("{}/oauth/authorize", fixture.origin))
            .header("Origin", "https://foreign.example")
            .header("Cookie", format!("{proof}; {csrf}"))
            .form(&form)
            .send()
            .await?;
        assert_eq!(csrf_denied.status(), 403);
        let mut fields = form.to_vec();
        if prompt == Some("login") {
            let rejected = fixture
                .http
                .post(format!("{}/oauth/authorize", fixture.origin))
                .header("Origin", &fixture.origin)
                .header("Cookie", format!("{proof}; {csrf}"))
                .form(&fields)
                .send()
                .await?;
            assert_eq!(rejected.status(), 200);
            assert!(!rejected.headers().contains_key("location"));
            fields.extend([("username", "owner"), ("password", PASSWORD)]);
        }
        let approved = fixture
            .http
            .post(format!("{}/oauth/authorize", fixture.origin))
            .header("Origin", &fixture.origin)
            .header("Cookie", format!("{proof}; {csrf}"))
            .form(&fields)
            .send()
            .await?;
        assert_eq!(approved.status(), 303, "{}", approved.text().await?);
        assert_eq!(
            fixture
                .exchange(&code_from(&approved), CLIENT, VERIFIER)
                .await?
                .status(),
            200
        );
    }
    Ok(())
}

#[tokio::test]
async fn launch_id_or_copied_read_only_root_cannot_supply_browser_authentication_or_write_approval(
) -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.model("issued", "source").await?;
    let (login, binding) = fixture.browser_login("owner").await?;
    let root = login["access_token"].as_str().unwrap();
    let (launch, proof) = fixture.browser_launch(root, &binding, false, true).await?;
    let launch_cookie = proof
        .split(';')
        .find(|v| v.trim().starts_with("subsoil_launch_"))
        .unwrap()
        .trim();
    for unbound in [
        "".to_string(),
        binding.clone(),
        launch_cookie.into(),
        format!("{launch_cookie}; subsoil_browser=forged"),
    ] {
        let page = fixture.bound_authorize(&launch, &unbound, None).await?;
        assert_eq!(page.status(), 200);
        let csrf = cookies(&page);
        let html = page.text().await?;
        assert!(!html.contains("<fieldset hidden disabled"));
        let rejected = fixture
            .http
            .post(format!("{}/oauth/authorize", fixture.origin))
            .header("Origin", &fixture.origin)
            .header("Cookie", format!("{unbound}; {csrf}"))
            .form(&[("request_id", form_id(&html)), ("decision", "allow")])
            .send()
            .await?;
        assert_eq!(rejected.status(), 200);
        assert!(!rejected.headers().contains_key("location"));
    }
    // Bootstrapping a proof from a copied read-only credential cannot approve push.
    let (edit, copied_proof) = fixture.browser_launch(root, "", true, true).await?;
    let page = fixture.bound_authorize(&edit, &copied_proof, None).await?;
    assert_eq!(page.status(), 200);
    assert!(!page.text().await?.contains("<fieldset hidden disabled"));
    Ok(())
}

#[tokio::test]
async fn account_switch_or_browser_rotation_invalidates_pending_authentication_and_consent(
) -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.model("issued", "source").await?;
    let (login, binding) = fixture.browser_login("owner").await?;
    let root = login["access_token"].as_str().unwrap();
    let (launch, proof) = fixture.browser_launch(root, &binding, false, false).await?;
    let page = fixture.bound_authorize(&launch, &proof, None).await?;
    assert_eq!(page.status(), 200);
    let (_, other_binding) = fixture.browser_login("reader").await?;
    let launch_cookie = proof
        .split(';')
        .find(|v| v.trim().starts_with("subsoil_launch_"))
        .unwrap()
        .trim();
    let switched = format!("{launch_cookie}; {other_binding}");
    assert_eq!(
        fixture
            .bound_authorize(&launch, &switched, None)
            .await?
            .status(),
        403
    );
    assert_eq!(
        fixture
            .bound_consent(page, &switched, "", "")
            .await?
            .status(),
        403
    );
    let response = fixture
        .http
        .post(format!("{}/open-artifact/launches", fixture.origin))
        .header("Origin", &fixture.origin)
        .header("Cookie", other_binding)
        .bearer_auth(root)
        .json(&fixture.request(false))
        .send()
        .await?;
    assert_eq!(response.status(), 400);
    let (_, rotated) = fixture.browser_login("owner").await?;
    assert_eq!(
        fixture
            .bound_authorize(&launch, &format!("{launch_cookie}; {rotated}"), None)
            .await?
            .status(),
        403
    );
    Ok(())
}

#[tokio::test]
async fn cancelling_consent_invalidates_the_initial_registry_launch_decision() -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.model("issued", "source").await?;
    let (login, binding) = fixture.browser_login("owner").await?;
    let (launch, proof) = fixture
        .browser_launch(
            login["access_token"].as_str().unwrap(),
            &binding,
            false,
            true,
        )
        .await?;
    let page = fixture
        .bound_authorize(&launch, &proof, Some("consent"))
        .await?;
    assert_eq!(page.status(), 200);
    let csrf = cookies(&page);
    let html = page.text().await?;
    let denied = fixture
        .http
        .post(format!("{}/oauth/authorize", fixture.origin))
        .header("Origin", &fixture.origin)
        .header("Cookie", format!("{proof}; {csrf}"))
        .form(&[("request_id", form_id(&html)), ("decision", "deny")])
        .send()
        .await?;
    assert_eq!(denied.status(), 303);
    assert!(denied.headers()["location"]
        .to_str()?
        .contains("error=access_denied"));
    assert_eq!(
        fixture
            .bound_authorize(&launch, &proof, None)
            .await?
            .status(),
        400
    );
    Ok(())
}

#[tokio::test]
async fn explicit_launch_decision_rejects_broader_lifetime_destination_and_foreign_initiators(
) -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.model("issued", "source").await?;
    fixture
        .registry
        .auth
        .grant("owner", "other/model:pull,push")?;
    let (login, binding) = fixture.browser_login("owner").await?;
    let root = login["access_token"].as_str().unwrap();
    for bad in ["ttl", "destination", "tag-policy", "origin", "client"] {
        let mut request = fixture.request(true);
        request["ttl"] = json!(900);
        request["publish"]["allowed_tags"] = json!(["*"]);
        request["decision"] = json!("open");
        if bad == "ttl" {
            request["ttl"] = json!(901);
        }
        if bad == "destination" {
            request["publish"]["repository"] = json!("other/model");
        }
        if bad == "tag-policy" {
            request["publish"]["allowed_tags"] = json!(["review-*"]);
        }
        let external = fixture.registry.auth.start_session(
            "owner",
            &[SESSION_SCOPE.into()],
            CLIENT,
            CALLBACK,
            false,
        )?;
        let response = fixture
            .http
            .post(format!("{}/open-artifact/launches", fixture.origin))
            .header(
                "Origin",
                if bad == "origin" {
                    "https://foreign.example"
                } else {
                    &fixture.origin
                },
            )
            .header("Cookie", &binding)
            .bearer_auth(if bad == "client" {
                &external.access_token
            } else {
                root
            })
            .json(&request)
            .send()
            .await?;
        assert_eq!(response.status(), 400, "{bad}");
    }
    // A custom destination receives a separate consent page, with existing authentication.
    let mut request = fixture.request(true);
    request["publish"]["repository"] = json!("other/model");
    let response = fixture
        .http
        .post(format!("{}/open-artifact/launches", fixture.origin))
        .header("Origin", &fixture.origin)
        .header("Cookie", &binding)
        .bearer_auth(root)
        .json(&request)
        .send()
        .await?;
    assert_eq!(response.status(), 200);
    let proof = format!("{}; {binding}", cookies(&response));
    let launch = response.json::<Value>().await?;
    let page = fixture.bound_authorize(&launch, &proof, None).await?;
    assert_eq!(page.status(), 200);
    let html = page.text().await?;
    assert!(html.contains("other/model") && html.contains("<fieldset hidden disabled"));
    Ok(())
}

#[tokio::test]
async fn session_revocation_expiry_and_permission_removal_reject_browser_bound_launches(
) -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.model("issued", "source").await?;
    for reason in ["revoked", "expired", "source", "publish-after-code"] {
        fixture
            .registry
            .auth
            .grant("owner", &format!("{REPO}:pull,push"))?;
        let (login, binding) = fixture.browser_login("owner").await?;
        let root = login["access_token"].as_str().unwrap();
        let (launch, proof) = fixture.browser_launch(root, &binding, true, true).await?;
        let claims = fixture.registry.auth.validate(root)?;
        if reason == "revoked" || reason == "expired" {
            let db = rusqlite::Connection::open(fixture.temp.path().join("auth.sqlite"))?;
            db.execute(
                if reason == "revoked" {
                    "UPDATE oauth_sessions SET revoked=1 WHERE id=?1"
                } else {
                    "UPDATE oauth_sessions SET expires=0 WHERE id=?1"
                },
                [claims.sid.as_ref().unwrap()],
            )?;
            assert_eq!(
                fixture
                    .bound_authorize(&launch, &proof, None)
                    .await?
                    .status(),
                400
            );
        } else if reason == "source" {
            fixture.registry.auth.set_grants(
                "owner",
                &GrantSet {
                    version: 1,
                    registry: Url::parse(&fixture.origin)?.authority().into(),
                    grants: vec![],
                },
            )?;
            assert_eq!(
                fixture
                    .bound_authorize(&launch, &proof, None)
                    .await?
                    .status(),
                403
            );
        } else {
            let approved = fixture.bound_authorize(&launch, &proof, None).await?;
            assert_eq!(approved.status(), 303);
            fixture.registry.auth.set_grants(
                "owner",
                &GrantSet {
                    version: 1,
                    registry: Url::parse(&fixture.origin)?.authority().into(),
                    grants: vec![Grant::exact(REPO.into(), vec!["pull".into()])],
                },
            )?;
            assert_eq!(
                fixture
                    .exchange(&code_from(&approved), CLIENT, VERIFIER)
                    .await?
                    .status(),
                400
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn guest_menu_decisions_keep_share_browser_proof_and_separate_consent() -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.model("issued", "source").await?;
    let (_, account_cookie) = fixture.browser_login("reader").await?;
    let share = fixture
        .registry
        .create_share(
            "owner",
            &GrantSet {
                version: 1,
                registry: Url::parse(&fixture.origin)?.authority().into(),
                grants: vec![Grant::exact(REPO.into(), vec!["pull".into()])],
            },
            600,
            subsoil::auth::ShareBinding::Snapshot,
        )
        .await?;
    let (root, _, _) = fixture.registry.auth.redeem_share(&share.secret)?;
    let mut request = fixture.request(false);
    request["decision"] = json!("open");
    let response = fixture
        .http
        .post(format!("{}/open-artifact/launches", fixture.origin))
        .header("Origin", &fixture.origin)
        .header("Cookie", &account_cookie)
        .bearer_auth(&root)
        .json(&request)
        .send()
        .await?;
    assert_eq!(response.status(), 200);
    assert!(response.headers()["set-cookie"]
        .to_str()?
        .contains("SameSite=Strict"));
    let proof = format!("{}; {account_cookie}", cookies(&response));
    let launch = response.json::<Value>().await?;
    let page = fixture.bound_authorize(&launch, &proof, None).await?;
    assert_eq!(page.status(), 200);
    let approved = fixture.bound_consent(page, &proof, "", "").await?;
    assert_eq!(approved.status(), 303);
    let session = fixture
        .exchange(&code_from(&approved), CLIENT, VERIFIER)
        .await?
        .json::<Value>()
        .await?;
    assert_eq!(session["authorization_type"], "share");
    let token = fixture
        .scoped(session["access_token"].as_str().unwrap())
        .await?;
    assert!(!fixture.registry.auth.permits(
        &fixture.registry.auth.validate(&token)?,
        REPO,
        "push"
    )?);
    Ok(())
}

#[tokio::test]
async fn profile_discovery_multi_client_config_and_rejected_launches() -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.model("issued", "model").await?;
    fixture
        .publish(
            &fixture.write_token()?,
            "report",
            "report",
            "application/vnd.example.report.v1",
        )
        .await?;
    let root = fixture.root("owner")?;
    for (reference, expected) in [("issued", 2), ("report", 1)] {
        let response = fixture
            .get(
                &format!("/open-artifact/applications?repository={REPO}&reference={reference}"),
                &root,
            )
            .await?;
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.json::<Value>().await?["applications"]
                .as_array()
                .unwrap()
                .len(),
            expected
        );
    }
    for client in [CLIENT, "file-viewer"] {
        let config: Value = fixture
            .http
            .get(format!(
                "{}/oauth/config?client_id={client}",
                fixture.origin
            ))
            .send()
            .await?
            .json()
            .await?;
        assert_eq!(config["client_id"], client);
        assert_eq!(config["issuer"], fixture.origin);
    }
    for bad in [
        "ttl",
        "profile",
        "intent",
        "view_publish",
        "destination",
        "tags",
        "application",
    ] {
        let mut request = fixture.request(true);
        match bad {
            "ttl" => request["ttl"] = json!(28801),
            "profile" => request["reference"] = json!("report"),
            "intent" => request["application_id"] = json!("file-viewer"),
            "view_publish" => request["intent"] = json!("view"),
            "destination" => request["publish"]["repository"] = json!("other/model"),
            "tags" => request["publish"]["allowed_tags"] = json!([]),
            "application" => request["application_id"] = json!("unregistered"),
            _ => unreachable!(),
        }
        assert_eq!(
            fixture.create(&root, &request).await?.status(),
            400,
            "{bad}"
        );
    }
    let (launch, _) = fixture.launch(&root, false).await?;
    assert_eq!(
        fixture
            .authorization(&launch, "file-viewer", "http://localhost:4000/callback")
            .await?
            .status(),
        400
    );
    assert_eq!(
        fixture
            .authorization(&launch, CLIENT, "http://localhost:3000/unregistered")
            .await?
            .status(),
        400
    );
    let code = fixture.approve(&launch, "", "owner").await?;
    assert_eq!(
        fixture
            .exchange(&code, CLIENT, &"a".repeat(43))
            .await?
            .status(),
        400
    );
    assert_eq!(
        fixture.exchange(&code, CLIENT, VERIFIER).await?.status(),
        400
    );
    Ok(())
}

#[tokio::test]
async fn share_launch_requires_browser_proof_and_inherits_revocation_and_deadline() -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.model("issued", "model").await?;
    for edit in [false, true] {
        let policy = GrantSet {
            version: 1,
            registry: Url::parse(&fixture.origin)?.authority().into(),
            grants: vec![Grant::exact(
                REPO.into(),
                if edit {
                    vec!["pull".into(), "push".into()]
                } else {
                    vec!["pull".into()]
                },
            )],
        };
        let share = fixture
            .registry
            .create_share(
                "owner",
                &policy,
                180,
                if edit {
                    subsoil::auth::ShareBinding::Live
                } else {
                    subsoil::auth::ShareBinding::Snapshot
                },
            )
            .await?;
        let (root, _, _) = fixture.registry.auth.redeem_share(&share.secret)?;
        if !edit {
            assert_eq!(
                fixture
                    .create(&root, &fixture.request(true))
                    .await?
                    .status(),
                400
            );
        }
        let (launch, cookie) = fixture.launch(&root, edit).await?;
        assert!(!cookie.is_empty());
        let code = fixture.approve(&launch, &cookie, "").await?;
        let response = fixture.exchange(&code, CLIENT, VERIFIER).await?;
        assert_eq!(response.status(), 200, "{}", response.text().await?);
        let session: Value = response.json().await?;
        assert_eq!(session["authorization_type"], "share");
        assert_eq!(session["subject"], format!("share:{}", share.share.id));
        assert_eq!(session["session_expires_at"], share.share.expires_at);
        let token = fixture
            .scoped(session["access_token"].as_str().unwrap())
            .await?;
        assert_eq!(
            fixture
                .get(&format!("/v2/{REPO}/manifests/issued"), &token)
                .await?
                .status(),
            200
        );
        if edit {
            fixture
                .publish(
                    &token,
                    "review-guest",
                    "guest edited",
                    "application/vnd.example.model.v1",
                )
                .await?;
        }
        fixture
            .registry
            .auth
            .revoke_share("owner", &share.share.id)?;
        assert_eq!(
            fixture
                .get(&format!("/v2/{REPO}/manifests/issued"), &token)
                .await?
                .status(),
            401
        );
        let refresh = fixture
            .http
            .post(format!("{}/oauth/token", fixture.origin))
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", CLIENT),
                ("refresh_token", session["refresh_token"].as_str().unwrap()),
            ])
            .send()
            .await?;
        assert_eq!(refresh.status(), 400);
    }
    Ok(())
}

#[tokio::test]
async fn launches_expire_and_existing_sessions_observe_current_policy() -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.model("issued", "model").await?;
    let root = fixture.root("owner")?;
    let (launch, _) = fixture.launch(&root, true).await?;
    let code = fixture.approve(&launch, "", "owner").await?;
    let session: Value = fixture
        .exchange(&code, CLIENT, VERIFIER)
        .await?
        .json()
        .await?;
    let token = fixture
        .scoped(session["access_token"].as_str().unwrap())
        .await?;
    fixture.registry.auth.set_grants(
        "owner",
        &GrantSet {
            version: 1,
            registry: Url::parse(&fixture.origin)?.authority().into(),
            grants: vec![Grant::exact(REPO.into(), vec!["pull".into()])],
        },
    )?;
    let denied = fixture
        .http
        .post(format!("{}/v2/{REPO}/blobs/uploads/", fixture.origin))
        .bearer_auth(&token)
        .send()
        .await?;
    assert_eq!(denied.status(), 403);
    let mut request = fixture.request(false);
    request["ttl"] = json!(1);
    let launch: Value = fixture.create(&root, &request).await?.json().await?;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    assert_eq!(
        fixture
            .authorization(&launch, CLIENT, CALLBACK)
            .await?
            .status(),
        400
    );
    // Expire an issued authorization without waiting for its full lifetime.
    let claims = fixture.registry.auth.validate(&token)?;
    let db = rusqlite::Connection::open(fixture.temp.path().join("auth.sqlite"))?;
    db.execute(
        "UPDATE authorizations SET expires=?1 WHERE id=?2",
        rusqlite::params![i64::try_from(now())?, claims.aid],
    )?;
    assert!(fixture.registry.auth.validate(&token).is_err());
    Ok(())
}

#[tokio::test]
async fn independent_application_cookies_refresh_without_overwriting_each_other() -> Result<()> {
    let fixture = Fixture::new().await?;
    let mut cookies = Vec::new();
    for (client, callback) in [
        (CLIENT, CALLBACK),
        ("file-viewer", "http://localhost:4000/callback"),
    ] {
        let response = fixture
            .http
            .get(format!("{}/oauth/authorize", fixture.origin))
            .query(&[
                ("client_id", client),
                ("redirect_uri", callback),
                ("response_type", "code"),
                ("scope", SESSION_SCOPE),
                ("state", "cookie-test-state"),
                ("code_challenge_method", "S256"),
                ("code_challenge", &challenge(VERIFIER)),
            ])
            .send()
            .await?;
        assert_eq!(response.status(), 200);
        let cookie = response.headers()["set-cookie"]
            .to_str()?
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let html = response.text().await?;
        let id = html
            .split("name=\"request_id\" value=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        let response = fixture
            .http
            .post(format!("{}/oauth/authorize", fixture.origin))
            .header("Origin", &fixture.origin)
            .header("Cookie", cookie)
            .form(&[
                ("request_id", id),
                ("username", "owner"),
                ("password", PASSWORD),
                ("decision", "allow"),
                ("remember_me", "true"),
            ])
            .send()
            .await?;
        assert_eq!(response.status(), 303);
        let url = Url::parse(response.headers()["location"].to_str()?)?;
        let code = url
            .query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .into_owned();
        let response = fixture
            .http
            .post(format!("{}/oauth/token", fixture.origin))
            .header(
                "Origin",
                Url::parse(callback)?.origin().ascii_serialization(),
            )
            .form(&[
                ("client_id", client),
                ("redirect_uri", callback),
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("code_verifier", VERIFIER),
            ])
            .send()
            .await?;
        assert_eq!(response.status(), 200, "{}", response.text().await?);
        cookies.push(
            response.headers()["set-cookie"]
                .to_str()?
                .split(';')
                .next()
                .unwrap()
                .to_string(),
        );
    }
    assert_ne!(cookies[0].split('=').next(), cookies[1].split('=').next());
    for (index, (client, origin)) in [
        (CLIENT, "http://localhost:3000"),
        ("file-viewer", "http://localhost:4000"),
    ]
    .iter()
    .enumerate()
    {
        let config: Value = fixture
            .http
            .get(format!(
                "{}/oauth/config?client_id={client}",
                fixture.origin
            ))
            .send()
            .await?
            .json()
            .await?;
        assert!(cookies[index].starts_with(config["refresh_cookie_name"].as_str().unwrap()));
        let response = fixture
            .http
            .post(format!("{}/oauth/token", fixture.origin))
            .header("Origin", *origin)
            .header("Cookie", cookies.join("; "))
            .form(&[("grant_type", "refresh_token"), ("client_id", client)])
            .send()
            .await?;
        assert_eq!(response.status(), 200, "{}", response.text().await?);
        assert!(response.headers()["set-cookie"]
            .to_str()?
            .starts_with(config["refresh_cookie_name"].as_str().unwrap()));
    }
    Ok(())
}

#[tokio::test]
async fn cli_loads_registrations_and_enables_only_explicit_application_cors() -> Result<()> {
    use std::io::BufRead;
    use std::process::{Command, Stdio};
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("applications.json");
    std::fs::write(&path, serde_json::to_vec(&configuration())?)?;
    let child = Command::new(env!("CARGO_BIN_EXE_subsoil"))
        .args(["serve", "--listen", "127.0.0.1:0", "--data"])
        .arg(temp.path().join("registry"))
        .arg("--applications")
        .arg(path)
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()?;
    struct Stop(std::process::Child);
    impl Drop for Stop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut stop = Stop(child);
    let mut reader = std::io::BufReader::new(stop.0.stderr.take().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let origin = line
        .split("listening on ")
        .nth(1)
        .unwrap()
        .split(' ')
        .next()
        .unwrap();
    let http = Client::new();
    let response = http
        .get(format!("{origin}/oauth/config?client_id={CLIENT}"))
        .header("Origin", "http://localhost:3000")
        .send()
        .await?;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["access-control-allow-origin"],
        "http://localhost:3000"
    );
    assert_eq!(response.json::<Value>().await?["client_id"], CLIENT);
    let denied = http
        .get(format!("{origin}/oauth/config?client_id=file-viewer"))
        .header("Origin", "http://localhost:4000")
        .send()
        .await?;
    assert!(!denied.headers().contains_key("access-control-allow-origin"));
    let preflight = http
        .request(
            reqwest::Method::OPTIONS,
            format!("{origin}/open-artifact/launches"),
        )
        .header("Origin", "http://localhost:3000")
        .header("Access-Control-Request-Method", "POST")
        .header(
            "Access-Control-Request-Headers",
            "authorization,content-type",
        )
        .send()
        .await?;
    assert_eq!(preflight.status(), 200);
    assert_eq!(
        preflight.headers()["access-control-allow-origin"],
        "http://localhost:3000"
    );
    Ok(())
}
