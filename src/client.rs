//! OCI manifests and blobs, with standard Bearer discovery and scoped login.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
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
    auth_file: PathBuf,
    pub plain_http: bool,
}

#[derive(Deserialize)]
struct TokenReply {
    token: String,
    #[serde(default)]
    expires_in: u64,
    #[serde(default)]
    access: Vec<Access>,
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
        let header = challenge
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .context("Registry did not return a Bearer challenge")?
            .to_str()?;
        ensure!(
            header.starts_with("Bearer "),
            "This client requires OCI Bearer authentication"
        );
        let parameter = |key: &str| -> Result<String> {
            let needle = format!("{key}=\"");
            let rest = header
                .split_once(&needle)
                .with_context(|| format!("Bearer challenge missing {key}"))?
                .1;
            Ok(rest
                .split('"')
                .next()
                .context("Invalid Bearer challenge")?
                .into())
        };
        let mut realm = Url::parse(&parameter("realm")?)?;
        ensure!(
            realm.scheme() == "https"
                || (self.plain_http && realm.scheme() == "http" && is_loopback(&realm)),
            "Refusing credentials over insecure transport"
        );
        realm
            .query_pairs_mut()
            .append_pair("service", &parameter("service")?);
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
        self.credentials.tokens.insert(registry.into(), reply.token);
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
            self.request(
                Method::GET,
                reference.url(&format!("manifests/{}", reference.reference))?,
                &reference.registry,
            )
            .header(reqwest::header::ACCEPT, MANIFEST_TYPE)
            .send()
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
        let mut response = successful(
            self.request(
                Method::GET,
                reference.url(&format!("blobs/{}", descriptor.digest))?,
                &reference.registry,
            )
            .send()
            .await?,
        )
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
        let response = successful(
            self.request(
                Method::HEAD,
                reference.url(&format!("blobs/{}", reference.reference))?,
                &reference.registry,
            )
            .send()
            .await?,
        )
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
