//! Profile discovery and browser-bound launches with explicit PKCE approval.
use super::*;
use crate::{
    applications::{Application, Applications, Intent},
    auth::{now, AuthorizationContext, Claims, SessionTokens, SESSION_SCOPE, SESSION_SECONDS},
    policy::{self, Grant},
};
use axum::{middleware, routing::post};
use serde::{Deserialize, Serialize};

const PROTOCOL: &str = "open-artifact/1";
const LAUNCH_SECONDS: u64 = 300;

#[derive(Clone, Debug, Serialize)]
pub struct Source {
    pub registry: String,
    pub repository: String,
    pub digest: String,
    pub profile: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Publish {
    pub repository: String,
    pub allowed_tags: Vec<String>,
}

impl Publish {
    fn grant(&self) -> Result<Grant> {
        valid_repo(&self.repository)?;
        let grant = Grant {
            repositories: vec![self.repository.clone()],
            tags: Some(self.allowed_tags.clone()),
            actions: vec!["push".into()],
            digests: None,
        };
        policy::validate(std::slice::from_ref(&grant), false)?;
        Ok(grant)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct OpenArtifact {
    pub protocol: String,
    pub source: Source,
    pub intent: Intent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publish: Option<Publish>,
    pub expires_at: u64,
}

#[derive(Clone)]
pub(crate) struct Launch {
    id: String,
    application: String,
    pub application_name: String,
    pub parent: Claims,
    artifact: OpenArtifact,
    cookie: String,
    pending_until: u64,
    browser: Option<String>,
    pub explicit_approval: bool,
}

impl Launch {
    fn cookie_name(&self) -> String {
        format!("subsoil_launch_{}", self.id)
    }

    pub(crate) fn clear_cookie(&self, secure: bool) -> axum::http::HeaderValue {
        format!(
            "{}=; HttpOnly; SameSite=Strict; Path=/oauth/authorize; Max-Age=0{}",
            self.cookie_name(),
            if secure { "; Secure" } else { "" }
        )
        .parse()
        .expect("generated cookie")
    }

    pub(crate) fn has_cookie(&self, headers: &HeaderMap) -> bool {
        let expected = format!("{}={}", self.cookie_name(), self.cookie);
        let matching = headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(';'))
            .filter(|value| value.trim() == expected)
            .count();
        matching == 1
    }

    pub(crate) fn access_description(&self) -> String {
        let minutes = self.artifact.expires_at.saturating_sub(now()).div_ceil(60);
        match &self.artifact.publish {
            Some(target) => format!("Open this version and save new versions in {}. Access lasts up to {minutes} minutes.", target.repository),
            None => format!("View this version from {} for up to {minutes} minutes.", self.artifact.source.repository),
        }
    }

    fn within_parent(&self, registry: &Registry) -> Result<bool> {
        let limits = registry.auth.limits(&self.parent)?;
        match &self.artifact.publish {
            Some(target) => {
                let write = target.grant()?;
                Ok(limits
                    .iter()
                    .all(|rules| policy::delegates(rules, std::slice::from_ref(&write))))
            }
            None => Ok(true),
        }
    }

    pub(crate) fn authenticated(
        &self,
        registry: &Registry,
        headers: &HeaderMap,
    ) -> Result<Option<crate::auth::BrowserBinding>> {
        if self.parent.share_id.is_some() {
            return Ok(None);
        }
        let mut binding = crate::oauth::browser::binding(registry, headers)?;
        if let Some(binding) = &binding {
            ensure!(
                binding.sub == self.parent.sub,
                "Account changed; open the files again"
            );
            if let Some(expected) = &self.browser {
                ensure!(
                    binding.jti == *expected,
                    "Browser authentication changed; open the files again"
                );
            }
        }
        if let Some(binding) = &mut binding {
            // Receiving applications retain their own approval ceiling even in a
            // browser that has authenticated to the registry.
            binding.password_authenticated &=
                registry.auth.session_client(&self.parent)? == crate::oauth::EXPLORER_CLIENT;
        }
        Ok(binding
            .filter(|binding| {
                self.has_cookie(headers) && self.browser.as_ref() == Some(&binding.jti)
            })
            .filter(|binding| {
                binding.password_authenticated || self.within_parent(registry).unwrap_or(false)
            }))
    }
}

pub(crate) struct LaunchAuthorization {
    launch: Launch,
    context: AuthorizationContext,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Discovery {
    repository: String,
    reference: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    application_id: String,
    repository: String,
    reference: String,
    intent: Intent,
    ttl: u64,
    #[serde(default)]
    publish: Option<Publish>,
    #[serde(default)]
    decision: Option<String>,
}

async fn hardened(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert("referrer-policy", "no-referrer".parse().unwrap());
    response
        .headers_mut()
        .insert("x-content-type-options", "nosniff".parse().unwrap());
    response
}

pub(super) fn router() -> Router<Arc<Registry>> {
    Router::new()
        .route("/open-artifact/applications", get(discover))
        .route("/open-artifact/launches", post(create))
        .route("/open-artifact/client.js", get(client))
        .route("/open-artifact/controls.js", get(controls))
        .route("/open-artifact/controls.css", get(controls_style))
        .layer(DefaultBodyLimit::max(32 * 1024))
        .layer(middleware::map_response(hardened))
}

async fn client() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("open_artifact_client.js"),
    )
}

async fn controls() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("open_artifact_ui.js"),
    )
}

async fn controls_style() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("open_artifact_ui.css"),
    )
}

fn principal(
    registry: &Registry,
    headers: &HeaderMap,
) -> std::result::Result<Claims, Box<Response>> {
    let claims = authorization(registry, headers, None)?;
    if !claims.root || (claims.sid.is_none() && claims.share_id.is_none()) {
        return Err(Box::new(challenge(registry, None, true)));
    }
    Ok(claims)
}

impl Registry {
    /// Load operator registrations before serving; callback registration and CORS remain explicit.
    pub fn configure_applications(&self, configuration: Applications) -> Result<()> {
        configuration.validate()?;
        let mut configured = self
            .applications
            .write()
            .map_err(|_| anyhow::anyhow!("Application configuration lock failed"))?;
        ensure!(
            configured.applications.is_empty() && configured.profiles.is_empty(),
            "Configure external applications once, before serving"
        );
        self.oauth
            .register_applications(&configuration.applications)?;
        *configured = configuration;
        Ok(())
    }

    fn source_manifest(
        &self,
        claims: &Claims,
        repo: &str,
        reference: &str,
    ) -> Result<(String, Value)> {
        valid_repo(repo)?;
        if reference.starts_with("sha256:") {
            digest_hex(reference)?;
        } else {
            valid_tag(reference)?;
        }
        ensure!(
            self.can_manifest(claims, repo, reference, "pull")?,
            "Access to this version is denied"
        );
        let value = if reference.starts_with("sha256:") {
            reference.into()
        } else {
            fs::read_to_string(self.repo(repo).join("tags").join(reference))?
        };
        let file = self.repo(repo).join("manifests").join(digest_hex(&value)?);
        ensure!(
            file.metadata()?.len() <= 1024 * 1024,
            "Manifest exceeds 1 MiB"
        );
        let bytes = fs::read(file)?;
        ensure!(digest(&bytes) == value, "Manifest integrity failure");
        Ok((value, serde_json::from_slice(&bytes)?))
    }

    fn application(&self, id: &str) -> Result<Application> {
        self.applications
            .read()
            .map_err(|_| anyhow::anyhow!("Application configuration lock failed"))?
            .applications
            .iter()
            .find(|app| app.id == id)
            .cloned()
            .context("Unknown external application")
    }

    fn publication_access(&self, claims: &Claims, repository: &str) -> Result<Option<Publish>> {
        let limits = if claims.share_id.is_some() {
            self.auth.limits(claims)?
        } else {
            vec![self.auth.grants(&claims.sub)?]
        };
        let mut candidates = vec!["*".to_string()];
        for rules in &limits {
            for grant in rules
                .iter()
                .filter(|grant| grant.repository(repository, "push"))
            {
                if let Some(tags) = &grant.tags {
                    candidates.extend(tags.iter().cloned());
                }
            }
        }
        candidates.sort();
        candidates.dedup();
        let mut allowed_tags: Vec<_> = candidates
            .into_iter()
            .filter(|tag| {
                if !tag.contains('*') && self.repo(repository).join("tags").join(tag).exists() {
                    return false;
                }
                let requested = Grant {
                    repositories: vec![repository.into()],
                    tags: Some(vec![tag.clone()]),
                    actions: vec!["push".into()],
                    digests: None,
                };
                limits
                    .iter()
                    .all(|rules| policy::delegates(rules, std::slice::from_ref(&requested)))
            })
            .take(32)
            .collect();
        if allowed_tags.first().is_some_and(|tag| tag == "*") {
            allowed_tags.truncate(1);
        }
        if allowed_tags.is_empty() {
            Ok(None)
        } else {
            Ok(Some(Publish {
                repository: repository.into(),
                allowed_tags,
            }))
        }
    }

    pub(crate) fn pending_launch(&self, id: &str, client: &str) -> Result<Launch> {
        let mut launches = self
            .launches
            .lock()
            .map_err(|_| anyhow::anyhow!("Launch store lock failed"))?;
        launches.retain(|_, launch| launch.pending_until > now());
        let launch = launches
            .get(id)
            .context("Launch expired or already approved")?;
        ensure!(
            launch.application == client,
            "Launch belongs to another application"
        );
        self.auth.check_authorization(&launch.parent)?;
        Ok(launch.clone())
    }

    pub(crate) fn cancel_launch(&self, launch: &Launch) -> Result<()> {
        self.launches
            .lock()
            .map_err(|_| anyhow::anyhow!("Launch store lock failed"))?
            .remove(&launch.id);
        Ok(())
    }

    pub(crate) fn approve_launch(
        &self,
        launch: Launch,
        user: &str,
        permissions: &[Grant],
        inherit_parent: bool,
    ) -> Result<LaunchAuthorization> {
        ensure!(
            user == launch.parent.sub,
            "Approve with the account that selected these files"
        );
        self.auth.check_authorization(&launch.parent)?;
        let source = &launch.artifact.source;
        self.source_manifest(&launch.parent, &source.repository, &source.digest)?;
        let mut limits = if launch.parent.share_id.is_some() || inherit_parent {
            self.auth.limits(&launch.parent)?
        } else {
            vec![permissions.to_vec()]
        };
        let mut selected = vec![Grant {
            repositories: vec![source.repository.clone()],
            tags: None,
            actions: vec!["pull".into()],
            digests: Some(vec![source.digest.clone()]),
        }];
        if let Some(target) = &launch.artifact.publish {
            let write = target.grant()?;
            ensure!(
                limits
                    .iter()
                    .all(|parent| policy::delegates(parent, std::slice::from_ref(&write))),
                "The requested destination exceeds approved access"
            );
            selected.push(write);
        }
        limits.insert(0, selected);
        let context = AuthorizationContext::new(
            user,
            limits,
            launch.artifact.expires_at,
            None,
            launch.parent.share_id.clone(),
        )?;
        let mut launches = self
            .launches
            .lock()
            .map_err(|_| anyhow::anyhow!("Launch store lock failed"))?;
        ensure!(
            launch.pending_until > now() && launches.remove(&launch.id).is_some(),
            "Launch expired or already approved"
        );
        Ok(LaunchAuthorization { launch, context })
    }

    pub(crate) fn launch_session(
        &self,
        approved: LaunchAuthorization,
        client: &str,
        redirect: &str,
    ) -> Result<(SessionTokens, OpenArtifact)> {
        ensure!(
            approved.launch.application == client,
            "Application binding mismatch"
        );
        self.auth.check_authorization(&approved.launch.parent)?;
        let source = &approved.launch.artifact.source;
        self.source_manifest(&approved.launch.parent, &source.repository, &source.digest)?;
        if let Some(target) = &approved.launch.artifact.publish {
            let write = target.grant()?;
            let mut limits = approved.context.limits.clone();
            limits.push(self.auth.grants(&approved.context.user)?);
            ensure!(
                limits
                    .iter()
                    .all(|rules| policy::delegates(rules, std::slice::from_ref(&write))),
                "Publication access changed"
            );
        }
        let app = self.application(client)?;
        ensure!(
            app.redirect_uris.iter().any(|uri| uri == redirect),
            "Callback binding mismatch"
        );
        let tokens = self.auth.start_limited_session(
            approved.context,
            &[SESSION_SCOPE.into()],
            client,
            redirect,
            false,
        )?;
        self.auth.check_authorization(&tokens.claims)?;
        Ok((tokens, approved.launch.artifact))
    }
}

async fn discover(
    State(registry): State<Arc<Registry>>,
    headers: HeaderMap,
    Query(query): Query<Discovery>,
) -> std::result::Result<Response, ApiError> {
    let claims = match principal(&registry, &headers) {
        Ok(c) => c,
        Err(r) => return Ok(*r),
    };
    let (digest, manifest) =
        registry.source_manifest(&claims, &query.repository, &query.reference)?;
    let publication = registry.publication_access(&claims, &query.repository)?;
    let config = registry.applications.read().map_err(ApiError::bad)?;
    let profile = config.profile(&manifest);
    let mut apps = Vec::new();
    if let Some(profile) = profile {
        for app in &config.applications {
            let Some(support) = app
                .supports
                .iter()
                .find(|support| support.profile == profile.id)
            else {
                continue;
            };
            let mut launches = serde_json::Map::new();
            if support.intents.contains(&Intent::View) {
                launches.insert(
                    "view".into(),
                    json!({"intent":"view","ttl":crate::auth::TOKEN_SECONDS}),
                );
            }
            if support.intents.contains(&Intent::Edit)
                && (!support.publish || publication.is_some())
            {
                let mut launch = json!({"intent":"edit","ttl":crate::auth::TOKEN_SECONDS});
                if support.publish {
                    launch["publish"] =
                        serde_json::to_value(&publication).map_err(ApiError::bad)?;
                }
                launches.insert("edit".into(), launch);
            }
            if !launches.is_empty() {
                apps.push(json!({"id":app.id,"name":app.name,"intents":support.intents,"publish":support.publish,"launches":launches}));
            }
        }
    }
    Ok(Json(json!({"protocol":PROTOCOL,"profile":profile.map(|p| &p.id),"digest":digest,"applications":apps})).into_response())
}

async fn create(
    State(registry): State<Arc<Registry>>,
    headers: HeaderMap,
    Json(request): Json<Request>,
) -> std::result::Result<Response, ApiError> {
    let parent = match principal(&registry, &headers) {
        Ok(c) => c,
        Err(r) => return Ok(*r),
    };
    ensure_request(
        request.ttl > 0 && request.ttl <= SESSION_SECONDS,
        "Launch lifetime must be 1-28800 seconds",
    )?;
    ensure_request(
        request.intent == Intent::Edit || request.publish.is_none(),
        "Viewing cannot request publication",
    )?;
    let (digest, manifest) =
        registry.source_manifest(&parent, &request.repository, &request.reference)?;
    let app = registry.application(&request.application_id)?;
    let profile = registry
        .applications
        .read()
        .map_err(ApiError::bad)?
        .profile(&manifest)
        .cloned()
        .context("No registered profile matches this version")?;
    let support = app
        .supports
        .iter()
        .find(|support| support.profile == profile.id)
        .context("Application does not support this profile")?;
    ensure_request(
        support.intents.contains(&request.intent),
        "Application does not support this operation",
    )?;
    if let Some(target) = &request.publish {
        ensure_request(support.publish, "Application cannot publish this profile")?;
        let write = target.grant()?;
        let limits = if parent.share_id.is_some() {
            registry.auth.limits(&parent)?
        } else {
            vec![registry.auth.grants(&parent.sub)?]
        };
        ensure_request(
            limits
                .iter()
                .all(|rules| policy::delegates(rules, std::slice::from_ref(&write))),
            "Destination exceeds your access",
        )?;
    }
    let parent_context = registry.auth.authorization(&parent.aid)?;
    ensure_request(
        request
            .decision
            .as_deref()
            .is_none_or(|value| value == "open"),
        "Unknown launch decision",
    )?;
    let same_origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok())
        == Some(registry.public_origin().as_str());
    let mut browser = None;
    let mut browser_cookie = None;
    if parent.share_id.is_none() {
        browser = crate::oauth::browser::binding(&registry, &headers)?;
        ensure_request(
            browser
                .as_ref()
                .is_none_or(|binding| binding.sub == parent.sub),
            "Account changed; sign in again",
        )?;
        if browser.is_none()
            && same_origin
            && registry.auth.session_client(&parent)? == crate::oauth::EXPLORER_CLIENT
        {
            let (token, binding) =
                registry
                    .auth
                    .issue_browser_binding(&parent.sub, parent_context.expires, false)?;
            browser_cookie = Some(crate::oauth::browser::cookie(&registry, &token));
            browser = Some(binding);
        }
    }
    let explicit_approval = if request.decision.as_deref() == Some("open")
        && parent.share_id.is_none()
    {
        ensure_request(
            same_origin && registry.auth.session_client(&parent)? == crate::oauth::EXPLORER_CLIENT,
            "A launch decision requires the registry file browser",
        )?;
        ensure_request(
            request.ttl <= crate::auth::TOKEN_SECONDS,
            "Launch decision exceeds the displayed lifetime",
        )?;
        if let Some(target) = &request.publish {
            ensure_request(
                registry
                    .publication_access(&parent, &request.repository)?
                    .as_ref()
                    == Some(target),
                "Launch decision exceeds the selected files' access",
            )?;
        }
        true
    } else {
        false
    };
    let expires_at = now()
        .saturating_add(request.ttl)
        .min(parent_context.expires);
    let id = Uuid::new_v4().simple().to_string();
    let launch = Launch {
        id: id.clone(),
        application: app.id,
        application_name: app.name,
        parent,
        artifact: OpenArtifact {
            protocol: PROTOCOL.into(),
            source: Source {
                registry: registry.public_origin(),
                repository: request.repository,
                digest,
                profile: profile.id,
            },
            intent: request.intent,
            publish: request.publish,
            expires_at,
        },
        cookie: Uuid::new_v4().simple().to_string(),
        pending_until: now().saturating_add(LAUNCH_SECONDS).min(expires_at),
        browser: browser.map(|binding| binding.jti),
        explicit_approval,
    };
    let mut url = reqwest::Url::parse(&app.launch_url).map_err(ApiError::bad)?;
    url.query_pairs_mut()
        .append_pair("issuer", &registry.public_origin())
        .append_pair("request_id", &id);
    let mut response = Json(json!({"protocol":PROTOCOL,"request_id":id,"launch_url":url.as_str(),"expires_at":launch.pending_until})).into_response();
    {
        response.headers_mut().insert(
            header::SET_COOKIE,
            format!(
                "{}={}; HttpOnly; SameSite={}; Path=/oauth/authorize; Max-Age={}{}",
                launch.cookie_name(),
                launch.cookie,
                if launch.parent.share_id.is_some() {
                    "Strict"
                } else {
                    "Lax"
                },
                LAUNCH_SECONDS,
                if registry.secure_cookies() {
                    "; Secure"
                } else {
                    ""
                }
            )
            .parse()
            .map_err(ApiError::bad)?,
        );
    }
    if let Some(cookie) = browser_cookie {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    let mut launches = registry.launches.lock().map_err(ApiError::bad)?;
    launches.retain(|_, launch| launch.pending_until > now());
    ensure_request(
        launches.len() < 1024
            && launches
                .values()
                .filter(|l| l.parent.sub == launch.parent.sub)
                .count()
                < 128,
        "Too many pending launches; try again shortly",
    )?;
    launches.insert(id, launch);
    Ok(response)
}

fn ensure_request(condition: bool, message: &str) -> std::result::Result<(), ApiError> {
    if condition {
        Ok(())
    } else {
        Err(ApiError::bad(message))
    }
}
