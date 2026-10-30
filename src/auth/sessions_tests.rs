use super::*;

fn fixture() -> Result<(tempfile::TempDir, Auth)> {
    let root = tempfile::tempdir()?;
    let auth = Auth::open(root.path())?;
    auth.add_user(
        "reader",
        "reader-test-password",
        &["project/model:pull".into()],
    )?;
    Ok((root, auth))
}

#[test]
fn refresh_rotation_survives_restart_and_replay_revokes_all_access() -> Result<()> {
    let (root, auth) = fixture()?;
    let first = auth.start_session(
        "reader",
        &["repository:project/model:pull,push".into()],
        "model-client",
        "http://localhost:3000/callback",
        false,
    )?;
    assert!(!first.session.remember);
    assert!(first.session.expires <= now() + SESSION_SECONDS);
    assert!(first.claims.exp <= now() + TOKEN_SECONDS);
    auth.validate(&first.access_token)?;
    assert!(auth
        .rotate_session(&first.refresh_token, "other-client")
        .is_err());
    // A failed client binding must not consume the valid token.
    auth.validate(&first.access_token)?;
    let db = Connection::open(root.path().join("auth.sqlite"))?;
    let stored: String = db.query_row("SELECT hash FROM oauth_refresh_tokens", [], |row| {
        row.get(0)
    })?;
    assert_eq!(stored, hash(&first.refresh_token));
    assert_ne!(stored, first.refresh_token);
    drop(auth);
    let auth = Auth::open(root.path())?;
    let next = auth.rotate_session(&first.refresh_token, "model-client")?;
    assert_ne!(first.refresh_token, next.refresh_token);
    assert_eq!(first.session.id, next.session.id);
    assert_eq!(first.session.expires, next.session.expires);
    auth.validate(&next.access_token)?;
    assert!(auth
        .rotate_session(&first.refresh_token, "model-client")
        .is_err());
    assert!(auth.validate(&first.access_token).is_err());
    assert!(auth.validate(&next.access_token).is_err());
    assert!(auth
        .rotate_session(&next.refresh_token, "model-client")
        .is_err());
    Ok(())
}

#[test]
fn remembered_sessions_last_30_days_and_refresh_does_not_expand_approved_grants() -> Result<()> {
    let (root, auth) = fixture()?;
    let first = auth.start_session(
        "reader",
        &[super::super::CATALOG_GRANTS_SCOPE.into()],
        "model-client",
        "https://app.example/callback",
        true,
    )?;
    assert!(first.session.remember);
    assert!(
        (now() + REMEMBER_SECONDS - 2..=now() + REMEMBER_SECONDS).contains(&first.session.expires)
    );
    auth.grant("reader", "project/model:push")?;
    auth.grant("reader", "private/model:pull,push")?;
    let second = auth.rotate_session(&first.refresh_token, "model-client")?;
    assert_eq!(second.session.expires, first.session.expires);
    assert!(auth.permits(&second.claims, "project/model", "pull")?);
    assert!(!auth.permits(&second.claims, "project/model", "push")?);
    assert!(!auth.permits(&second.claims, "private/model", "pull")?);
    let db = Connection::open(root.path().join("auth.sqlite"))?;
    db.execute(
        "DELETE FROM policy_rules WHERE user='reader' AND rule LIKE '%pull%'",
        [],
    )?;
    let third = auth.rotate_session(&second.refresh_token, "model-client")?;
    assert!(!auth.permits(&third.claims, "project/model", "pull")?);
    assert!(third
        .claims
        .access
        .iter()
        .filter(|a| a.kind == "repository")
        .all(|a| a.actions.is_empty()));
    Ok(())
}

#[test]
fn deadline_caps_access_and_logout_with_a_consumed_token_revokes_the_family() -> Result<()> {
    let (root, auth) = fixture()?;
    let first = auth.start_session(
        "reader",
        &["repository:project/model:pull".into()],
        "model-client",
        "http://localhost:3000/callback",
        false,
    )?;
    let db = Connection::open(root.path().join("auth.sqlite"))?;
    let deadline = now() + 30;
    db.execute(
        "UPDATE oauth_sessions SET expires=?1 WHERE id=?2",
        params![i64::try_from(deadline)?, first.session.id],
    )?;
    let second = auth.rotate_session(&first.refresh_token, "model-client")?;
    assert_eq!(second.claims.exp, deadline);
    auth.revoke_session(&first.refresh_token, "other-client")?;
    auth.validate(&second.access_token)?;
    auth.revoke_session(&first.refresh_token, "model-client")?;
    assert!(auth.validate(&second.access_token).is_err());
    assert!(auth
        .rotate_session(&second.refresh_token, "model-client")
        .is_err());
    // Old CLI tokens have no browser session and keep their original semantics.
    auth.validate(&auth.issue("reader", &[], TOKEN_SECONDS)?.0)?;
    let third = auth.start_session(
        "reader",
        &[],
        "model-client",
        "http://localhost:3000/callback",
        false,
    )?;
    db.execute(
        "UPDATE oauth_sessions SET expires=?1 WHERE id=?2",
        params![i64::try_from(now())?, third.session.id],
    )?;
    assert!(auth.validate(&third.access_token).is_err());
    assert!(auth
        .rotate_session(&third.refresh_token, "model-client")
        .is_err());
    Ok(())
}

#[test]
fn concurrent_reuse_is_atomic_and_revokes_the_rotated_token() -> Result<()> {
    let (_root, auth) = fixture()?;
    let first = auth.start_session(
        "reader",
        &[],
        "model-client",
        "http://localhost:3000/callback",
        false,
    )?;
    let auth = std::sync::Arc::new(auth);
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let auth = auth.clone();
            let token = first.refresh_token.clone();
            std::thread::spawn(move || auth.rotate_session(&token, "model-client"))
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert!(auth
        .validate(
            &results
                .into_iter()
                .find_map(Result::ok)
                .unwrap()
                .access_token
        )
        .is_err());
    Ok(())
}

#[test]
fn failed_token_and_session_issuance_do_not_leave_persistent_credentials() -> Result<()> {
    let (root, auth) = fixture()?;
    let db = Connection::open(root.path().join("auth.sqlite"))?;
    let counts = || -> Result<(i64, i64, i64)> {
        Ok((
            db.query_row("SELECT COUNT(*) FROM authorizations", [], |r| r.get(0))?,
            db.query_row("SELECT COUNT(*) FROM oauth_sessions", [], |r| r.get(0))?,
            db.query_row("SELECT COUNT(*) FROM oauth_refresh_tokens", [], |r| {
                r.get(0)
            })?,
        ))
    };
    let before = counts()?;
    assert!(auth
        .issue("reader", &["unsupported:scope".into()], 900)
        .is_err());
    assert_eq!(counts()?, before);
    for table in ["oauth_sessions", "oauth_refresh_tokens"] {
        db.execute_batch(&format!("CREATE TRIGGER reject_session_insert BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT,'simulated storage failure'); END;"))?;
        assert!(auth
            .start_session(
                "reader",
                &[super::super::SESSION_SCOPE.into()],
                "client",
                "http://localhost/callback",
                false
            )
            .is_err());
        assert_eq!(
            counts()?,
            before,
            "failed {table} insert must roll back the entire session"
        );
        db.execute_batch("DROP TRIGGER reject_session_insert;")?;
    }
    let valid = auth.start_session(
        "reader",
        &[super::super::SESSION_SCOPE.into()],
        "client",
        "http://localhost/callback",
        false,
    )?;
    auth.validate(&valid.access_token)?;
    assert_eq!(counts()?, (1, 1, 1));
    Ok(())
}
