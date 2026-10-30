//! Validated allow rules shared by accounts, approved sessions, and share links.
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};

pub const MAX_RULES: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub repositories: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    pub actions: Vec<String>,
    /// Exact artifact roots used internally for snapshot shares, never a wildcard.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digests: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantSet {
    pub version: u32,
    pub registry: String,
    pub grants: Vec<Grant>,
}

pub fn registry_name(value: &str) -> Result<String> {
    ensure!(
        !value.contains(['/', '?', '#', '@', '*', '\\']) && !value.chars().any(char::is_whitespace),
        "Registry must be an exact host with optional port"
    );
    let url = reqwest::Url::parse(&format!("https://{value}"))?;
    ensure!(
        url.host_str().is_some() && url.username().is_empty() && url.password().is_none(),
        "Invalid registry"
    );
    Ok(format!(
        "{}{}",
        url.host_str().expect("validated host"),
        url.port().map(|p| format!(":{p}")).unwrap_or_default()
    ))
}

impl GrantSet {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= 256 * 1024, "Grant document exceeds 256 KiB");
        let mut document: Self = serde_json::from_slice(bytes).context("Invalid grant JSON")?;
        ensure!(document.version == 1, "Unsupported grant version");
        document.registry = registry_name(&document.registry)?;
        validate(&document.grants, false)?;
        Ok(document)
    }
}

pub fn validate(grants: &[Grant], snapshots: bool) -> Result<()> {
    ensure!(grants.len() <= MAX_RULES, "Too many grant rules");
    for grant in grants {
        ensure!(
            !grant.repositories.is_empty() && grant.repositories.len() <= 32,
            "Each rule needs 1-32 repository selectors"
        );
        ensure!(
            !grant.actions.is_empty()
                && grant.actions.len() <= 2
                && grant
                    .actions
                    .iter()
                    .all(|a| matches!(a.as_str(), "pull" | "push")),
            "Only pull and push are supported; tags are immutable"
        );
        for repository in &grant.repositories {
            ensure!(
                !repository.is_empty() && repository.len() <= 255,
                "Invalid repository pattern"
            );
            for part in repository.split('/') {
                if part == "**" {
                    continue;
                }
                ensure!(
                    !part.is_empty()
                        && !part.contains("**")
                        && part.bytes().all(|b| b.is_ascii_lowercase()
                            || b.is_ascii_digit()
                            || b"._-*".contains(&b)),
                    "Repository patterns support only * and standalone **"
                );
                let example = part.replace('*', "x");
                crate::registry::valid_repo(&example)?;
            }
        }
        if let Some(tags) = &grant.tags {
            ensure!(
                !tags.is_empty() && tags.len() <= 32 && grant.digests.is_none(),
                "Tags must be nonempty and cannot be combined with digests"
            );
            for tag in tags {
                ensure!(
                    !tag.is_empty()
                        && tag.len() <= 128
                        && !tag.starts_with(['.', '-'])
                        && tag
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"_.*-".contains(&b)),
                    "Invalid tag selector"
                );
            }
        }
        if let Some(digests) = &grant.digests {
            ensure!(
                snapshots
                    && !digests.is_empty()
                    && digests.len() <= 4096
                    && grant.actions.iter().all(|a| a == "pull"),
                "Digest rules are reserved for read-only snapshots"
            );
            for digest in digests {
                crate::release::digest_hex(digest)?;
            }
        }
    }
    Ok(())
}

impl Grant {
    pub fn exact(repository: String, actions: Vec<String>) -> Self {
        Self {
            repositories: vec![repository],
            tags: None,
            actions,
            digests: None,
        }
    }
    pub fn repository(&self, repository: &str, action: &str) -> bool {
        self.actions.iter().any(|a| a == action)
            && self
                .repositories
                .iter()
                .any(|p| repository_matches(p, repository))
    }
    pub fn artifact(
        &self,
        repository: &str,
        tag: Option<&str>,
        digest: &str,
        action: &str,
    ) -> bool {
        self.repository(repository, action)
            && self
                .tags
                .as_ref()
                .is_none_or(|tags| tag.is_some_and(|tag| tags.iter().any(|p| wildcard(p, tag))))
            && self
                .digests
                .as_ref()
                .is_none_or(|digests| digests.iter().any(|d| d == digest))
    }
}

/// Anchored, linear-space glob matching. * never crosses a repository component.
pub fn wildcard(pattern: &str, value: &str) -> bool {
    let (p, v) = (pattern.as_bytes(), value.as_bytes());
    let (mut i, mut j, mut star, mut retry) = (0, 0, None, 0);
    while j < v.len() {
        if i < p.len() && p[i] == v[j] {
            i += 1;
            j += 1;
        } else if i < p.len() && p[i] == b'*' {
            star = Some(i);
            i += 1;
            retry = j;
        } else if let Some(s) = star {
            i = s + 1;
            retry += 1;
            j = retry;
        } else {
            return false;
        }
    }
    while i < p.len() && p[i] == b'*' {
        i += 1;
    }
    i == p.len()
}

pub fn repository_matches(pattern: &str, repository: &str) -> bool {
    let patterns: Vec<_> = pattern.split('/').collect();
    let values: Vec<_> = repository.split('/').collect();
    // A namespace subtree does not include the repository named by the namespace.
    if pattern.ends_with("/**") && repository == pattern.trim_end_matches("/**") {
        return false;
    }
    let mut row = vec![false; values.len() + 1];
    row[0] = true;
    let count = patterns.len();
    for (index, part) in patterns.into_iter().enumerate() {
        let mut next = vec![false; values.len() + 1];
        if part == "**" {
            let descendant = index + 1 == count && count > 1;
            next[0] = row[0] && !descendant;
            for j in 1..=values.len() {
                next[j] = (if descendant { row[j - 1] } else { row[j] }) || next[j - 1];
            }
        } else {
            for j in 1..=values.len() {
                next[j] = row[j - 1] && wildcard(part, values[j - 1]);
            }
        }
        row = next;
    }
    row[values.len()]
}

/// Conservative delegation containment. Ambiguous glob-language inclusion is denied.
pub fn covers(parent: &str, child: &str, repository: bool) -> bool {
    if parent == child || (repository && parent == "**") || (!repository && parent == "*") {
        return true;
    }
    if !child.contains('*') {
        return if repository {
            repository_matches(parent, child)
        } else {
            wildcard(parent, child)
        };
    }
    if repository {
        if let Some(prefix) = parent.strip_suffix("/**") {
            return !prefix.contains('*') && child.starts_with(&format!("{prefix}/"));
        }
    }
    false
}

pub fn delegates(parent: &[Grant], requested: &[Grant]) -> bool {
    requested.iter().all(|rule| {
        rule.repositories.iter().all(|repository| {
            rule.actions.iter().all(|action| {
                let selectors = rule.tags.clone().unwrap_or_else(|| vec![String::new()]);
                selectors.iter().all(|tag| {
                    parent.iter().any(|p| {
                        p.actions.contains(action)
                            && p.repositories.iter().any(|r| covers(r, repository, true))
                            && p.digests.is_none()
                            && match &p.tags {
                                None => true,
                                Some(tags) => {
                                    !tag.is_empty() && tags.iter().any(|t| covers(t, tag, false))
                                }
                            }
                    })
                })
            })
        })
    })
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
