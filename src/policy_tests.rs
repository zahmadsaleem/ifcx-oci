use super::*;
use serde_json::json;

#[test]
fn repository_globs_are_anchored_and_respect_namespace_boundaries() {
    assert!(!repository_matches("hospital-*/**", "hospital-a"));
    assert!(repository_matches("hospital-*/**", "hospital-a/models"));
    for (pattern, yes, no) in [
        (
            "hospital-a/*",
            "hospital-a/model",
            "hospital-a/models/architecture",
        ),
        (
            "hospital-a/**",
            "hospital-a/models/architecture",
            "hospital-ab/model",
        ),
        ("hospital-a/**/*", "hospital-a/model", "hospital-a"),
        ("**", "any/project/model", ""),
    ] {
        assert!(repository_matches(pattern, yes), "{pattern}: {yes}");
        if !no.is_empty() {
            assert!(!repository_matches(pattern, no), "{pattern}: {no}");
        }
    }
    assert!(!repository_matches("hospital-a/**", "hospital-a"));
    assert!(!repository_matches("models/*", "private/models/a"));
}

#[test]
fn tags_and_actions_are_conjunctive_and_empty_or_overwrite_rules_are_rejected() -> Result<()> {
    let document = json!({
        "version": 1, "registry": "registry.example.com",
        "grants": [{"repositories": ["hospital-a/**"], "tags": ["issued", "review-*"], "actions": ["pull"]}]
    });
    let policy = GrantSet::parse(&serde_json::to_vec(&document)?)?;
    let grant = &policy.grants[0];
    assert!(grant.artifact("hospital-a/model", Some("issued"), "digest", "pull"));
    assert!(grant.artifact("hospital-a/model", Some("review-2"), "digest", "pull"));
    assert!(!grant.artifact("hospital-a/model", None, "digest", "pull"));
    assert!(!grant.artifact("hospital-a/model", Some("draft"), "digest", "pull"));
    assert!(!grant.artifact("other/model", Some("issued"), "digest", "pull"));
    assert!(!grant.artifact("hospital-a/model", Some("issued"), "digest", "push"));
    for (field, value) in [
        ("/grants/0/actions", json!(["overwrite"])),
        ("/grants/0/actions", json!([])),
        ("/grants/0/tags", json!([])),
        ("/version", json!(2)),
    ] {
        let mut invalid = document.clone();
        *invalid.pointer_mut(field).expect("fixture field") = value;
        assert!(GrantSet::parse(&serde_json::to_vec(&invalid)?).is_err());
    }
    Ok(())
}

#[test]
fn delegation_cannot_add_actions_tags_or_another_project() -> Result<()> {
    let parent = GrantSet::parse(
        br#"{
        "version": 1, "registry": "r.example",
        "grants": [{"repositories": ["a/**"], "tags": ["review-*"], "actions": ["pull", "push"]}]
    }"#,
    )?
    .grants;
    let mut child = vec![Grant {
        repositories: vec!["a/models/one".into()],
        tags: Some(vec!["review-1".into()]),
        actions: vec!["pull".into()],
        digests: None,
    }];
    assert!(delegates(&parent, &child));
    child[0].tags = None;
    assert!(!delegates(&parent, &child));
    child[0].tags = Some(vec!["issued".into()]);
    assert!(!delegates(&parent, &child));
    child[0].tags = Some(vec!["review-1".into()]);
    child[0].repositories = vec!["another/model".into()];
    assert!(!delegates(&parent, &child));
    Ok(())
}

#[test]
fn json_is_the_only_policy_format_and_uses_the_shared_grant_shape() -> Result<()> {
    let policy = GrantSet::parse(
        br#"{
        "version": 1, "registry": "REGISTRY.EXAMPLE.COM",
        "grants": [{"repositories": ["hospital-a/**"], "actions": ["pull", "push"]}]
    }"#,
    )?;
    assert_eq!(policy.registry, "registry.example.com");
    assert!(policy.grants[0].tags.is_none());
    let encoded = serde_json::to_vec(&policy)?;
    assert_eq!(GrantSet::parse(&encoded)?.grants, policy.grants);
    let empty = GrantSet::parse(br#"{"version":1,"registry":"registry.example.com","grants":[]}"#)?;
    assert!(empty.grants.is_empty());
    for invalid in [
        b"version: 1\nregistry: registry.example.com\ngrants: []".as_slice(),
        br#"{"version":1,"registry":"registry.example.com","grants":[],"extra":true}"#,
        br#"{"version":1,"registry":"registry.example.com","grants":[{"repositories":["a/**"],"actions":["pull"],"typo":true}]}"#,
        br#"{"version":1,"registry":"registry.example.com","grants":[],}"#,
    ] {
        assert!(GrantSet::parse(invalid).is_err());
    }
    assert!(GrantSet::parse(&vec![b' '; 256 * 1024 + 1]).is_err());
    Ok(())
}
