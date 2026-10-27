//! Registry-observed publication provenance, stored separately from immutable manifests.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Publication {
    digest: String,
    publisher: String,
    pushed_at: u64,
}

fn path(registry: &Registry, repo: &str, reference: &str) -> Result<PathBuf> {
    let base = registry.repo(repo).join("publications");
    if reference.starts_with("sha256:") {
        Ok(base.join("digests").join(digest_hex(reference)?))
    } else {
        valid_tag(reference)?;
        Ok(base.join("tags").join(reference))
    }
}

pub(super) fn record(
    registry: &Registry,
    repo: &str,
    reference: &str,
    digest: &str,
    publisher: &str,
) -> Result<()> {
    let value = serde_json::to_vec(&Publication {
        digest: digest.into(),
        publisher: publisher.into(),
        pushed_at: crate::auth::now(),
    })?;
    // Digest reads describe the first observed publication of these bytes here.
    let first = path(registry, repo, digest)?;
    if !first.exists() {
        atomic_write(&first, &value)?;
    }
    if !reference.starts_with("sha256:") {
        atomic_write(&path(registry, repo, reference)?, &value)?;
    }
    Ok(())
}

pub(super) fn headers(
    registry: &Registry,
    repo: &str,
    reference: &str,
    digest: &str,
) -> Result<Vec<(&'static str, String)>> {
    let file = path(registry, repo, reference)?;
    if !file.exists() {
        return Ok(Vec::new());
    }
    let value: Publication = serde_json::from_slice(&fs::read(file)?)?;
    // A failed tag replacement must not attach new provenance to old bytes.
    if value.digest != digest {
        return Ok(Vec::new());
    }
    Ok(vec![
        ("ifcx-registry-publisher", value.publisher),
        ("ifcx-registry-pushed-at", value.pushed_at.to_string()),
    ])
}
