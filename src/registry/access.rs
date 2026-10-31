//! Repository selectors are enforced on concrete roots and their content closure.
use super::*;
use crate::{auth::Claims, policy::Grant};

const MAX_ROOTS: usize = 4096;
const MAX_POLICY_BYTES: usize = 32 * 1024 * 1024;

fn unrestricted(layers: &[Vec<Grant>], repo: &str, action: &str) -> bool {
    layers.iter().all(|rules| {
        rules
            .iter()
            .any(|r| r.repository(repo, action) && r.tags.is_none() && r.digests.is_none())
    })
}

fn allowed(
    layers: &[Vec<Grant>],
    repo: &str,
    tag: Option<&str>,
    digest: &str,
    action: &str,
) -> bool {
    layers
        .iter()
        .all(|rules| rules.iter().any(|r| r.artifact(repo, tag, digest, action)))
}

impl Registry {
    pub fn repositories(&self) -> Result<Vec<String>> {
        let mut repositories = Vec::new();
        for entry in fs::read_dir(self.root.join("repositories"))? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let name =
                String::from_utf8(hex::decode(entry.file_name().to_string_lossy().as_ref())?)?;
            valid_repo(&name)?;
            repositories.push(name);
            ensure!(
                repositories.len() <= 100_000,
                "Repository discovery limit exceeded"
            );
        }
        repositories.sort();
        Ok(repositories)
    }

    fn roots(&self, repo: &str) -> Result<Vec<(Option<String>, String)>> {
        let mut roots = Vec::new();
        let tags = self.repo(repo).join("tags");
        if tags.exists() {
            for entry in fs::read_dir(tags)? {
                let entry = entry?;
                if !entry.file_type()?.is_file() {
                    continue;
                }
                let tag = entry.file_name().to_string_lossy().into_owned();
                valid_tag(&tag)?;
                let digest = fs::read_to_string(entry.path())?;
                digest_hex(&digest)?;
                roots.push((Some(tag), digest));
                ensure!(
                    roots.len() <= MAX_ROOTS,
                    "Artifact discovery limit exceeded"
                );
            }
        }
        let manifests = self.repo(repo).join("manifests");
        if manifests.exists() {
            for entry in fs::read_dir(manifests)? {
                let entry = entry?;
                if !entry.file_type()?.is_file() {
                    continue;
                }
                let digest = format!("sha256:{}", entry.file_name().to_string_lossy());
                digest_hex(&digest)?;
                roots.push((None, digest));
                ensure!(
                    roots.len() <= MAX_ROOTS,
                    "Artifact discovery limit exceeded"
                );
            }
        }
        roots.sort();
        roots.dedup();
        Ok(roots)
    }

    pub(crate) fn visible_roots(
        &self,
        layers: &[Vec<Grant>],
        repo: &str,
    ) -> Result<Vec<(Option<String>, String)>> {
        if !layers
            .iter()
            .all(|rules| rules.iter().any(|r| r.repository(repo, "pull")))
        {
            return Ok(Vec::new());
        }
        Ok(self
            .roots(repo)?
            .into_iter()
            .filter(|(tag, digest)| allowed(layers, repo, tag.as_deref(), digest, "pull"))
            .collect())
    }

    pub(crate) fn can_manifest(
        &self,
        claims: &Claims,
        repo: &str,
        reference: &str,
        action: &str,
    ) -> Result<bool> {
        let layers = self.auth.limits(claims)?;
        if action == "push" {
            return Ok(if reference.starts_with("sha256:") {
                unrestricted(&layers, repo, action)
            } else {
                allowed(&layers, repo, Some(reference), "", action)
            });
        }
        if !reference.starts_with("sha256:") {
            let path = self.repo(repo).join("tags").join(reference);
            let digest = if path.exists() {
                fs::read_to_string(path)?
            } else {
                String::new()
            };
            return Ok(allowed(&layers, repo, Some(reference), &digest, action));
        }
        if unrestricted(&layers, repo, "pull") {
            return Ok(true);
        }
        Ok(self
            .visible_roots(&layers, repo)?
            .iter()
            .any(|(_, digest)| digest == reference))
    }

    pub(crate) fn can_blob(&self, claims: &Claims, repo: &str, value: &str) -> Result<bool> {
        let layers = self.auth.limits(claims)?;
        if unrestricted(&layers, repo, "pull") && claims.sub != crate::auth::PUBLIC_SUBJECT {
            return Ok(true);
        }
        let mut budget = MAX_POLICY_BYTES;
        let mut seen = std::collections::HashSet::new();
        for (_, root) in self.visible_roots(&layers, repo)? {
            if !seen.insert(root.clone()) {
                continue;
            }
            let path = self.repo(repo).join("manifests").join(digest_hex(&root)?);
            let size = usize::try_from(path.metadata()?.len())?;
            ensure!(
                size <= 1024 * 1024 && size <= budget,
                "Policy content budget exceeded"
            );
            budget -= size;
            let bytes = fs::read(path)?;
            ensure!(digest(&bytes) == root, "Stored manifest integrity failure");
            let manifest: Value = serde_json::from_slice(&bytes)?;
            let config = manifest.get("config").context("Missing config")?;
            let layers = manifest["layers"].as_array().context("Missing layers")?;
            if std::iter::once(config)
                .chain(layers)
                .any(|d| d["digest"].as_str() == Some(value))
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn snapshot(&self, mut limits: Vec<Vec<Grant>>, requested: &[Grant]) -> Result<Vec<Grant>> {
        limits.push(requested.to_vec());
        let mut result = Vec::new();
        let mut count = 0;
        for repo in self.repositories()? {
            let digests: std::collections::BTreeSet<_> = self
                .visible_roots(&limits, &repo)?
                .into_iter()
                .map(|(_, d)| d)
                .collect();
            if digests.is_empty() {
                continue;
            }
            count += digests.len();
            ensure!(
                count <= MAX_ROOTS,
                "Snapshot contains too many artifact roots"
            );
            result.push(Grant {
                repositories: vec![repo],
                tags: None,
                actions: vec!["pull".into()],
                digests: Some(digests.into_iter().collect()),
            });
        }
        Ok(result)
    }

    pub(crate) fn upload_owner(claims: &Claims) -> String {
        format!(
            "{}:{}:{}",
            claims.sub,
            claims.sid.as_deref().unwrap_or(&claims.aid),
            claims.share_id.as_deref().unwrap_or("")
        )
    }
    pub(crate) fn uploaded_by(&self, claims: &Claims, repo: &str, digest: &str) -> Result<bool> {
        use sha2::Digest;
        Ok(self
            .repo(repo)
            .join("staged")
            .join(digest_hex(digest)?)
            .join(hex::encode(sha2::Sha256::digest(
                Self::upload_owner(claims).as_bytes(),
            )))
            .is_file())
    }

    pub(crate) fn check_upload_owner(&self, repo: &str, id: &str, claims: &Claims) -> Result<bool> {
        let owner = self.upload(repo, id)?.with_extension("owner");
        Ok(owner.is_file() && fs::read_to_string(owner)? == Self::upload_owner(claims))
    }
}
