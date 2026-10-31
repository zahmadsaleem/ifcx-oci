//! OCI manifests and blobs, with standard Bearer discovery and scoped login.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};

use anyhow::{bail, ensure, Context, Result};
use reqwest::{Method, StatusCode, Url};
use serde::{Deserialize, Serialize};

use crate::{
    auth::{private_file, Access},
    registry::{atomic_write, MANIFEST_TYPE},
    release::{self, checked_path, digest, digest_hex, ARTIFACT_TYPE},
};

const MAX_BLOB: u64 = 512 * 1024 * 1024;
const MAX_BLOB_REDIRECTS: usize = 5;

#[derive(Clone, Debug)]
pub struct Reference {
    pub registry: String,
    pub repository: String,
    pub reference: String,
    pub base: Url,
}
impl Reference {
    pub fn parse(value: &str, plain_http: bool) -> Result<Self> {
        ensure!(
            !value.contains("://"),
            "Use an OCI reference such as 127.0.0.1:5000/project/model:issued"
        );
        let (registry, rest) = value
            .split_once('/')
            .context("Reference needs a registry and repository")?;
        let (repository, reference) = if let Some(pair) = rest.rsplit_once('@') {
            digest_hex(pair.1)?;
            pair
        } else {
            rest.rsplit_once(':').unwrap_or((rest, "latest"))
        };
        crate::registry::valid_repo(repository)?;
        ensure!(
            !reference.is_empty() && !reference.contains('/') && reference.len() <= 128,
            "Invalid reference"
        );
        let base = registry_url(registry, plain_http)?;
        Ok(Self {
            registry: registry.into(),
            repository: repository.into(),
            reference: reference.into(),
            base,
        })
    }
    fn url(&self, suffix: &str) -> Result<Url> {
        Ok(self
            .base
            .join(&format!("v2/{}/{suffix}", self.repository))?)
    }
}

pub fn registry_url(registry: &str, plain_http: bool) -> Result<Url> {
    ensure!(
        !registry.contains(['/', '?', '#', '@']),
        "Registry must be a hostname with optional port"
    );
    let url = Url::parse(&format!(
        "{}://{registry}/",
        if plain_http { "http" } else { "https" }
    ))?;
    ensure!(
        url.username().is_empty() && url.password().is_none() && url.host_str().is_some(),
        "Invalid registry address"
    );
    if plain_http {
        ensure!(
            is_loopback(&url),
            "Plain HTTP is restricted to loopback; use HTTPS for remote registries"
        );
    }
    Ok(url)
}
fn is_loopback(url: &Url) -> bool {
    let host = url.host_str().unwrap_or("").trim_matches(['[', ']']);
    host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Descriptor {
    pub media_type: String,
    pub digest: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub schema_version: u32,
    pub media_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
    pub config: Descriptor,
    pub layers: Vec<Descriptor>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadedFile {
    pub path: String,
    #[serde(flatten)]
    pub descriptor: Descriptor,
}

/// Successfully downloaded layers and the integrity-checked config descriptor.
#[derive(Debug, Serialize)]
pub struct PullReport {
    pub files: Vec<DownloadedFile>,
    pub config: Descriptor,
}

#[derive(Default, Serialize, Deserialize)]
struct Credentials {
    tokens: BTreeMap<String, String>,
}

pub struct Client {
    http: reqwest::Client,
    credentials: Credentials,
    anonymous_tokens: Mutex<BTreeMap<(String, String), String>>,
    auth_file: PathBuf,
    pub plain_http: bool,
}

#[derive(Deserialize)]
struct TokenReply {
    #[serde(default)]
    token: String,
    #[serde(default)]
    access_token: String,
    #[serde(default)]
    expires_in: u64,
    #[serde(default)]
    access: Vec<Access>,
}

impl TokenReply {
    fn bearer(&self) -> Result<&str> {
        let token = if self.token.is_empty() {
            &self.access_token
        } else {
            &self.token
        };
        ensure!(!token.is_empty(), "Token endpoint returned no access token");
        Ok(token)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginInfo {
    pub registry: String,
    pub expires_in: u64,
    pub granted_access: Vec<Access>,
}

impl Client {
    pub fn new(auth_file: impl AsRef<Path>, plain_http: bool) -> Result<Self> {
        let auth_file = auth_file.as_ref().to_path_buf();
        let credentials = if auth_file.exists() {
            serde_json::from_slice(&fs::read(&auth_file)?)?
        } else {
            Credentials::default()
        };
        Ok(Self {
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(300))
                .build()?,
            credentials,
            anonymous_tokens: Mutex::new(BTreeMap::new()),
            auth_file,
            plain_http,
        })
    }
    fn request(&self, method: Method, url: Url, registry: &str) -> reqwest::RequestBuilder {
        let request = self.http.request(method, url);
        if let Some(token) = self.credentials.tokens.get(registry) {
            request.bearer_auth(token)
        } else {
            request
        }
    }

    async fn read(
        &self,
        mut request: reqwest::RequestBuilder,
        reference: &Reference,
    ) -> Result<reqwest::Response> {
        // Explicitly stored credentials keep their existing login/error behavior.
        if self.credentials.tokens.contains_key(&reference.registry) {
            return Ok(request.send().await?);
        }
        let key = (reference.registry.clone(), reference.repository.clone());
        let cached = self.anonymous_tokens.lock().unwrap().get(&key).cloned();
        let retry = request.try_clone().context("Cannot retry registry read")?;
        if let Some(token) = cached {
            request = request.bearer_auth(token);
        }
        let response = request.send().await?;
        if response.status() != StatusCode::UNAUTHORIZED {
            return Ok(response);
        }
        let mut realm = bearer_realm(&response, self.plain_http)?;
        realm.query_pairs_mut().append_pair(
            "scope",
            &format!("repository:{}:pull", reference.repository),
        );
        // Never send stored credentials to a challenge's token endpoint.
        let reply: TokenReply = successful(self.http.get(realm).send().await?)
            .await?
            .json()
            .await?;
        let token = reply.bearer()?.to_string();
        let response = retry.bearer_auth(&token).send().await?;
        if response.status().is_success() || response.status().is_redirection() {
            self.anonymous_tokens.lock().unwrap().insert(key, token);
        } else {
            self.anonymous_tokens.lock().unwrap().remove(&key);
        }
        Ok(response)
    }

    async fn blob_response(
        &self,
        method: Method,
        reference: &Reference,
        digest: &str,
    ) -> Result<reqwest::Response> {
        let request = self.request(
            method.clone(),
            reference.url(&format!("blobs/{digest}"))?,
            &reference.registry,
        );
        let mut response = self.read(request, reference).await?;
        let mut registry_auth = true;
        for hop in 0..=MAX_BLOB_REDIRECTS {
            if !matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
                return successful(response).await;
            }
            ensure!(hop < MAX_BLOB_REDIRECTS, "Too many blob redirects");
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .context("Blob redirect has no location")?
                .to_str()?;
            let url = blob_redirect_url(response.url(), location, self.plain_http)?;
            // Once a chain leaves the registry, no later hop gets its credentials.
            registry_auth &= url.origin() == reference.base.origin();
            response = if registry_auth {
                self.read(
                    self.request(method.clone(), url, &reference.registry),
                    reference,
                )
                .await?
            } else {
                self.http.request(method.clone(), url).send().await?
            };
        }
        unreachable!()
    }

    pub async fn login(
        &mut self,
        registry: &str,
        user: &str,
        password: &str,
        scopes: &[String],
    ) -> Result<LoginInfo> {
        let base = registry_url(registry, self.plain_http)?;
        let challenge = self.http.get(base.join("v2/")?).send().await?;
        ensure!(
            challenge.status() == StatusCode::UNAUTHORIZED,
            "Expected an OCI Bearer challenge from the registry"
        );
        let mut realm = bearer_realm(&challenge, self.plain_http)?;
        for scope in scopes {
            if scope == "registry:catalog:read" {
                realm.query_pairs_mut().append_pair("scope", scope);
                continue;
            }
            let scope = scope.strip_prefix("repository:").unwrap_or(scope);
            crate::auth::parse_grant(scope)?;
            realm
                .query_pairs_mut()
                .append_pair("scope", &format!("repository:{scope}"));
        }
        let response = self
            .http
            .get(realm)
            .basic_auth(user, Some(password))
            .send()
            .await?;
        let reply: TokenReply = successful(response).await?.json().await?;
        self.credentials
            .tokens
            .insert(registry.into(), reply.bearer()?.into());
        let parent = self
            .auth_file
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        atomic_write(&self.auth_file, &serde_json::to_vec(&self.credentials)?)?;
        private_file(&self.auth_file)?;
        Ok(LoginInfo {
            registry: registry.into(),
            expires_in: reply.expires_in,
            granted_access: reply.access,
        })
    }

    pub async fn manifest(&self, reference: &Reference) -> Result<(Vec<u8>, Manifest)> {
        let response = successful(
            self.read(
                self.request(
                    Method::GET,
                    reference.url(&format!("manifests/{}", reference.reference))?,
                    &reference.registry,
                )
                .header(reqwest::header::ACCEPT, MANIFEST_TYPE),
                reference,
            )
            .await?,
        )
        .await?;
        let advertised = response
            .headers()
            .get("docker-content-digest")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let bytes = response.bytes().await?.to_vec();
        ensure!(bytes.len() <= 4 * 1024 * 1024, "Manifest is too large");
        let actual = digest(&bytes);
        if let Some(expected) = advertised {
            ensure!(expected == actual, "Manifest integrity failure");
        }
        if reference.reference.starts_with("sha256:") {
            ensure!(
                reference.reference == actual,
                "Pinned manifest digest mismatch"
            );
        }
        let manifest: Manifest = serde_json::from_slice(&bytes)?;
        ensure!(
            manifest.schema_version == 2 && manifest.media_type == MANIFEST_TYPE,
            "Unsupported OCI manifest"
        );
        Ok((bytes, manifest))
    }

    /// Resolve a tag or pinned reference using verified manifest bytes.
    pub async fn resolve(&self, source: &str) -> Result<String> {
        let reference = Reference::parse(source, self.plain_http)?;
        let (raw, _) = self.manifest(&reference).await?;
        Ok(digest(&raw))
    }

    /// List repositories visible to the current catalog token, across all pages.
    pub async fn repositories(&self, registry: &str, last: Option<&str>) -> Result<Vec<String>> {
        let base = registry_url(registry, self.plain_http)?;
        self.list(registry, base.join("v2/_catalog")?, "repositories", last)
            .await
    }

    /// List tags of a bare REGISTRY/REPOSITORY name, across all pages.
    pub async fn tags(&self, repository: &str, last: Option<&str>) -> Result<Vec<String>> {
        let reference = Reference::parse(&format!("{repository}:latest"), self.plain_http)?;
        self.list(
            &reference.registry,
            reference.url("tags/list")?,
            "tags",
            last,
        )
        .await
    }

    async fn list(
        &self,
        registry: &str,
        mut url: Url,
        field: &str,
        last: Option<&str>,
    ) -> Result<Vec<String>> {
        url.query_pairs_mut().append_pair("n", "100");
        if let Some(last) = last {
            url.query_pairs_mut().append_pair("last", last);
        }
        let endpoint = url.clone();
        let mut visited = BTreeSet::new();
        let mut entries = BTreeSet::new();
        loop {
            ensure!(
                visited.insert(url.as_str().to_string()),
                "Registry returned a pagination loop"
            );
            let response = successful(
                self.request(Method::GET, url.clone(), registry)
                    .send()
                    .await?,
            )
            .await?;
            let next = next_page(&response, &url)?;
            if let Some(next) = &next {
                ensure!(
                    next.origin() == endpoint.origin()
                        && next.path() == endpoint.path()
                        && next.username().is_empty()
                        && next.password().is_none()
                        && next.fragment().is_none(),
                    "Refusing a pagination link outside the listing endpoint"
                );
            }
            let page: serde_json::Value = response.json().await?;
            let values = page
                .get(field)
                .with_context(|| format!("Registry listing is missing {field}"))?;
            if !(field == "tags" && values.is_null()) {
                for entry in serde_json::from_value::<Vec<String>>(values.clone())? {
                    // Some registries ignore the initial last cursor.
                    if last.is_none_or(|last| entry.as_str() > last) {
                        entries.insert(entry);
                    }
                }
            }
            match next {
                Some(next) => url = next,
                None => return Ok(entries.into_iter().collect()),
            }
        }
    }

    pub async fn blob(&self, reference: &Reference, descriptor: &Descriptor) -> Result<Vec<u8>> {
        digest_hex(&descriptor.digest)?;
        ensure!(
            descriptor.size <= MAX_BLOB,
            "Blob exceeds this showcase's 512 MiB limit"
        );
        let mut response = self
            .blob_response(Method::GET, reference, &descriptor.digest)
            .await?;
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                (bytes.len() + chunk.len()) as u64 <= descriptor.size,
                "Blob exceeds advertised size"
            );
            bytes.extend_from_slice(&chunk);
        }
        ensure!(
            bytes.len() as u64 == descriptor.size && digest(&bytes) == descriptor.digest,
            "Blob integrity failure"
        );
        Ok(bytes)
    }

    /// Fetch one blob by digest, independently of any release manifest.
    pub async fn fetch_blob(&self, source: &str) -> Result<Vec<u8>> {
        ensure!(
            source.contains('@'),
            "Blob fetch requires a reference of the form REGISTRY/REPOSITORY@sha256:DIGEST"
        );
        let reference = Reference::parse(source, self.plain_http)?;
        let response = self
            .blob_response(Method::HEAD, &reference, &reference.reference)
            .await?;
        let size = response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .context("Registry did not return the blob size")?
            .to_str()?
            .parse()?;
        let descriptor = Descriptor {
            media_type: "application/octet-stream".into(),
            digest: reference.reference.clone(),
            size,
            annotations: BTreeMap::new(),
        };
        self.blob(&reference, &descriptor).await
    }

    async fn upload(
        &self,
        target: &Reference,
        descriptor: &Descriptor,
        bytes: Vec<u8>,
    ) -> Result<()> {
        ensure!(
            bytes.len() as u64 == descriptor.size && digest(&bytes) == descriptor.digest,
            "Refusing mismatched upload bytes"
        );
        ensure!(
            descriptor.size <= MAX_BLOB,
            "Blob exceeds this showcase's 512 MiB limit"
        );
        let existing = self
            .request(
                Method::HEAD,
                target.url(&format!("blobs/{}", descriptor.digest))?,
                &target.registry,
            )
            .send()
            .await?;
        if existing.status().is_success() {
            return Ok(());
        }
        if existing.status() != StatusCode::NOT_FOUND {
            successful(existing).await?;
        }
        let response = successful(
            self.request(
                Method::POST,
                target.url("blobs/uploads/")?,
                &target.registry,
            )
            .send()
            .await?,
        )
        .await?;
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .context("Registry did not return an upload location")?
            .to_str()?;
        let mut url = target.base.join(location)?;
        ensure!(
            url.origin() == target.base.origin(),
            "Refusing an upload redirect to another origin"
        );
        url.query_pairs_mut()
            .append_pair("digest", &descriptor.digest);
        successful(
            self.request(Method::PUT, url, &target.registry)
                .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                .body(bytes)
                .send()
                .await?,
        )
        .await?;
        Ok(())
    }

    async fn publish(&self, target: &Reference, bytes: Vec<u8>) -> Result<String> {
        let expected = digest(&bytes);
        let response = successful(
            self.request(
                Method::PUT,
                target.url(&format!("manifests/{}", target.reference))?,
                &target.registry,
            )
            .header(reqwest::header::CONTENT_TYPE, MANIFEST_TYPE)
            .body(bytes)
            .send()
            .await?,
        )
        .await?;
        if let Some(value) = response.headers().get("docker-content-digest") {
            ensure!(
                value.to_str()? == expected,
                "Registry changed the manifest digest"
            );
        }
        Ok(expected)
    }

    pub async fn push(&self, root: &Path, destination: &str) -> Result<String> {
        release::verify(root)?;
        let index = release::read_index(root)?;
        let ifc_files: Vec<_> = index
            .files
            .iter()
            .filter(|file| file.media_type == "application/x-step" || file.path.ends_with(".ifc"))
            .collect();
        let ifc_source = ifc_files.first().filter(|file| {
            ifc_files.len() == 1
                && file.media_type == "application/x-step"
                && file.path.ends_with(".ifc")
                && file.digest == index.source_digest
        });
        let mut ifc_annotations = BTreeMap::new();
        if ifc_source.is_some() {
            ifc_annotations.insert(
                release::IFC_PROFILE_KEY.into(),
                release::IFC_RELEASE_PROFILE.into(),
            );
            ifc_annotations.insert(release::IFC_SCHEMA_KEY.into(), index.source_schema.clone());
        }
        let target = Reference::parse(destination, self.plain_http)?;
        let config_bytes = b"{}".to_vec();
        let config = Descriptor {
            media_type: "application/vnd.oci.empty.v1+json".into(),
            digest: digest(&config_bytes),
            size: 2,
            annotations: BTreeMap::new(),
        };
        self.upload(&target, &config, config_bytes).await?;
        let mut layers = Vec::new();
        let mut files = vec![("index.json".to_string(), "application/json".to_string())];
        files.extend(
            index
                .files
                .iter()
                .map(|f| (f.path.clone(), f.media_type.clone())),
        );
        for (path, media_type) in files {
            let bytes = fs::read(checked_path(root, &path)?)?;
            let mut annotations =
                BTreeMap::from([("org.opencontainers.image.title".into(), path.clone())]);
            if ifc_source.is_some_and(|file| file.path == path) {
                annotations.extend(ifc_annotations.clone());
            }
            let descriptor = Descriptor {
                media_type,
                digest: digest(&bytes),
                size: bytes.len() as u64,
                annotations,
            };
            self.upload(&target, &descriptor, bytes).await?;
            layers.push(descriptor);
        }
        let mut annotations = BTreeMap::from([(
            "org.opencontainers.image.title".into(),
            "IFC model release".into(),
        )]);
        annotations.extend(ifc_annotations);
        let manifest = Manifest {
            schema_version: 2,
            media_type: MANIFEST_TYPE.into(),
            artifact_type: Some(ARTIFACT_TYPE.into()),
            config,
            layers,
            annotations,
        };
        self.publish(&target, serde_json::to_vec(&manifest)?).await
    }

    /// Download all layers and check integrity without interpreting an artifact profile.
    pub async fn pull(&self, source: &str, output: &Path) -> Result<(String, PullReport)> {
        ensure!(!output.exists(), "Pull output must not already exist");
        let reference = Reference::parse(source, self.plain_http)?;
        let (raw, manifest) = self.manifest(&reference).await?;
        let (stage, files) = self
            .download_layers(&reference, output, &manifest.layers)
            .await?;
        self.blob(&reference, &manifest.config).await?;
        ensure!(!output.exists(), "Pull output appeared during transfer");
        fs::rename(stage.path(), output)?;
        Ok((
            digest(&raw),
            PullReport {
                files,
                config: manifest.config,
            },
        ))
    }

    /// Pull exact layer titles and check their bytes without verifying a full release.
    pub async fn pull_layers(
        &self,
        source: &str,
        output: &Path,
        titles: &[String],
    ) -> Result<(String, Vec<Descriptor>)> {
        ensure!(!output.exists(), "Pull output must not already exist");
        ensure!(!titles.is_empty(), "Select at least one layer");
        let reference = Reference::parse(source, self.plain_http)?;
        let (raw, manifest) = self.manifest(&reference).await?;
        let titles: BTreeSet<_> = titles.iter().collect();
        let mut layers = Vec::new();
        for title in titles {
            let mut matches = manifest.layers.iter().filter(|layer| {
                layer.annotations.get("org.opencontainers.image.title") == Some(title)
            });
            let layer = matches
                .next()
                .with_context(|| format!("Layer not found: {title}"))?;
            ensure!(matches.next().is_none(), "Ambiguous layer title: {title}");
            layers.push(layer.clone());
        }
        let (stage, _) = self.download_layers(&reference, output, &layers).await?;
        ensure!(!output.exists(), "Pull output appeared during transfer");
        fs::rename(stage.path(), output)?;
        Ok((digest(&raw), layers))
    }

    async fn download_layers(
        &self,
        reference: &Reference,
        output: &Path,
        layers: &[Descriptor],
    ) -> Result<(tempfile::TempDir, Vec<DownloadedFile>)> {
        let parent = output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let stage = tempfile::Builder::new()
            .prefix(".subsoil-pull-")
            .tempdir_in(parent)?;
        let mut paths = BTreeSet::new();
        // Validate all destination paths before downloading any payloads.
        let mut targets = Vec::new();
        for descriptor in layers {
            let path = match descriptor.annotations.get("org.opencontainers.image.title") {
                Some(title) => title.clone(),
                None => format!("blobs/sha256/{}", digest_hex(&descriptor.digest)?),
            };
            ensure!(paths.insert(path.clone()), "Duplicate artifact layer title");
            targets.push(checked_path(stage.path(), &path)?);
        }
        let mut files = Vec::new();
        for (descriptor, target) in layers.iter().zip(targets) {
            let bytes = self.blob(reference, descriptor).await?;
            fs::create_dir_all(target.parent().context("Missing payload parent")?)?;
            fs::write(&target, bytes)?;
            files.push(DownloadedFile {
                path: target.strip_prefix(stage.path())?.to_string_lossy().into(),
                descriptor: descriptor.clone(),
            });
        }
        Ok((stage, files))
    }

    pub async fn copy(&self, source: &str, destination: &str) -> Result<String> {
        let from = Reference::parse(source, self.plain_http)?;
        let target = Reference::parse(destination, self.plain_http)?;
        let (raw, manifest) = self.manifest(&from).await?;
        for descriptor in std::iter::once(&manifest.config).chain(&manifest.layers) {
            let bytes = self.blob(&from, descriptor).await?;
            self.upload(&target, descriptor, bytes).await?;
        }
        self.publish(&target, raw).await
    }
}

fn safe_read_url(url: &Url, plain_http: bool) -> Result<()> {
    ensure!(
        url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && (url.scheme() == "https"
                || (plain_http && url.scheme() == "http" && is_loopback(url))),
        "Refusing an unsafe token endpoint or blob redirect; use HTTPS (or loopback HTTP with --plain-http) without URL credentials or fragments"
    );
    Ok(())
}

fn blob_redirect_url(current: &Url, location: &str, plain_http: bool) -> Result<Url> {
    let url = current.join(location)?;
    safe_read_url(&url, plain_http)?;
    ensure!(
        current.scheme() != "https" || url.scheme() == "https",
        "Refusing an HTTPS blob redirect to insecure transport"
    );
    Ok(url)
}

fn bearer_realm(response: &reqwest::Response, plain_http: bool) -> Result<Url> {
    let parameters = response
        .headers()
        .get_all(reqwest::header::WWW_AUTHENTICATE)
        .iter()
        .filter_map(|header| header.to_str().ok())
        .find_map(|header| {
            let (scheme, parameters) = header.trim().split_once(char::is_whitespace)?;
            scheme.eq_ignore_ascii_case("Bearer").then_some(parameters)
        })
        .context("Registry did not return a Bearer challenge; login with the required scopes")?;
    let mut quoted = false;
    let mut escaped = false;
    let parts = parameters.split(|ch| {
        if escaped {
            escaped = false;
        } else if quoted && ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            quoted = !quoted;
        } else if ch == ',' && !quoted {
            return true;
        }
        false
    });
    let mut values = BTreeMap::new();
    for part in parts {
        let (key, value) = part.split_once('=').context("Invalid Bearer challenge")?;
        let value = value.trim();
        let value = if let Some(value) = value.strip_prefix('"') {
            let value = value
                .strip_suffix('"')
                .context("Invalid Bearer challenge")?;
            let mut chars = value.chars();
            let mut decoded = String::new();
            while let Some(ch) = chars.next() {
                decoded.push(if ch == '\\' {
                    chars.next().context("Invalid Bearer challenge escape")?
                } else {
                    ensure!(ch != '"', "Invalid Bearer challenge quote");
                    ch
                });
            }
            decoded
        } else {
            ensure!(
                !value.is_empty() && !value.contains('"'),
                "Invalid Bearer challenge"
            );
            value.into()
        };
        ensure!(
            values
                .insert(key.trim().to_ascii_lowercase(), value)
                .is_none(),
            "Duplicate Bearer challenge parameter"
        );
    }
    ensure!(!quoted && !escaped, "Invalid Bearer challenge quote");
    let mut realm = Url::parse(
        values
            .get("realm")
            .context("Bearer challenge missing realm")?,
    )?;
    safe_read_url(&realm, plain_http)?;
    let query: Vec<_> = realm
        .query_pairs()
        .filter(|(key, _)| key != "service" && key != "scope")
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    realm.set_query(None);
    realm.query_pairs_mut().extend_pairs(query);
    if let Some(service) = values.get("service") {
        realm.query_pairs_mut().append_pair("service", service);
    }
    Ok(realm)
}

fn next_page(response: &reqwest::Response, current: &Url) -> Result<Option<Url>> {
    let mut next = None;
    for header in response.headers().get_all(reqwest::header::LINK) {
        for link in header.to_str()?.split(',') {
            let (target, parameters) = link
                .trim()
                .split_once('>')
                .context("Invalid registry pagination link")?;
            let is_next = parameters.split(';').any(|parameter| {
                parameter.split_once('=').is_some_and(|(key, value)| {
                    key.trim() == "rel"
                        && value
                            .trim()
                            .trim_matches('"')
                            .split_ascii_whitespace()
                            .any(|relation| relation == "next")
                })
            });
            if is_next {
                ensure!(next.is_none(), "Registry returned multiple next-page links");
                next = Some(
                    current.join(
                        target
                            .strip_prefix('<')
                            .context("Invalid registry pagination target")?,
                    )?,
                );
            }
        }
    }
    Ok(next)
}

async fn successful(response: reqwest::Response) -> Result<reqwest::Response> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let detail = response.text().await.unwrap_or_default();
    if status == StatusCode::UNAUTHORIZED {
        bail!("Registry authentication failed ({status}); login again with the required scopes. {detail}");
    }
    bail!("Registry request failed ({status}): {detail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_redirects_require_safe_urls_and_never_downgrade_https() -> Result<()> {
        let https = Url::parse("https://registry.example/v2/model/blobs/sha256:abc")?;
        let http = Url::parse("http://127.0.0.1:5000/v2/model/blobs/sha256:abc")?;
        assert_eq!(
            blob_redirect_url(&https, "/storage?signature=abc", false)?.as_str(),
            "https://registry.example/storage?signature=abc"
        );
        assert!(blob_redirect_url(&https, "https://cdn.example/model", false).is_ok());
        assert!(blob_redirect_url(&http, "http://localhost:5001/model", true).is_ok());
        for unsafe_url in [
            "http://cdn.example/model",
            "http://127.0.0.1:5001/model",
            "https://user:secret@cdn.example/model",
            "https://cdn.example/model#fragment",
            "file:///etc/passwd",
        ] {
            assert!(
                blob_redirect_url(&https, unsafe_url, true).is_err(),
                "{unsafe_url}"
            );
        }
        assert!(blob_redirect_url(&http, "/storage", false).is_err());
        Ok(())
    }
}
