//! Registry-observed publication provenance, stored separately from immutable manifests.
use super::*;
use serde::{Deserialize, Serialize};

pub(super) const PUBLISHER_HEADER: &str = "subsoil-registry-publisher";
pub(super) const PUSHED_AT_HEADER: &str = "subsoil-registry-pushed-at";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Publication {
    digest: String,
    publisher: String,
    pushed_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    share_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    created_by: Option<String>,
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
    claims: &crate::auth::Claims,
) -> Result<()> {
    let value = serde_json::to_vec(&Publication {
        digest: digest.into(),
        publisher: claims
            .share_id
            .as_ref()
            .map(|id| format!("share:{id}"))
            .unwrap_or_else(|| claims.sub.clone()),
        share_id: claims.share_id.clone(),
        created_by: claims.share_id.as_ref().map(|_| claims.sub.clone()),
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
    let mut headers = vec![
        (PUBLISHER_HEADER, value.publisher),
        (PUSHED_AT_HEADER, value.pushed_at.to_string()),
    ];
    if let Some(id) = value.share_id {
        headers.push(("subsoil-registry-share-id", id));
    }
    if let Some(creator) = value.created_by {
        headers.push(("subsoil-registry-created-by", creator));
    }
    Ok(headers)
}
