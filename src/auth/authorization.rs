//! Server-side approval ceilings keep standard OCI JWTs compact and resource-scoped.
use super::*;
use crate::policy::Grant;

pub const SESSION_SCOPE: &str = "subsoil:session";
pub const CATALOG_GRANTS_SCOPE: &str = "subsoil:catalog:grants";

#[derive(Clone, Debug)]
pub struct AuthorizationContext {
    pub id: String,
    pub user: String,
    pub expires: u64,
    pub limits: Vec<Vec<Grant>>,
    pub session: Option<String>,
    pub share: Option<String>,
}

pub(super) fn schema(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS authorizations (
        id TEXT PRIMARY KEY,user TEXT NOT NULL REFERENCES users(name) ON DELETE CASCADE,
        expires INTEGER NOT NULL,limits TEXT NOT NULL,session TEXT,share TEXT);",
    )?;
    Ok(())
}

impl AuthorizationContext {
    pub(super) fn new(
        user: &str,
        limits: Vec<Vec<Grant>>,
        expires: u64,
        session: Option<String>,
        share: Option<String>,
    ) -> Result<Self> {
        ensure!(
            expires > now() && !limits.is_empty(),
            "Invalid authorization"
        );
        Ok(Self {
            id: Uuid::new_v4().to_string(),
            user: user.into(),
            expires,
            limits,
            session,
            share,
        })
    }

    pub(super) fn store(&self, db: &Connection) -> Result<()> {
        db.execute(
            "DELETE FROM authorizations WHERE expires<=?1",
            [i64::try_from(now())?],
        )?;
        db.execute(
            "INSERT INTO authorizations VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                self.id,
                self.user,
                i64::try_from(self.expires)?,
                serde_json::to_string(&self.limits)?,
                self.session,
                self.share
            ],
        )?;
        Ok(())
    }
}

impl Auth {
    pub(crate) fn authorization(&self, id: &str) -> Result<AuthorizationContext> {
        let db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("Identity store lock failed"))?;
        let (user, expires, limits, session, share): (
            String,
            i64,
            String,
            Option<String>,
            Option<String>,
        ) = db.query_row(
            "SELECT user,expires,limits,session,share FROM authorizations WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )?;
        let expires = u64::try_from(expires)?;
        ensure!(expires > now(), "Authorization expired");
        Ok(AuthorizationContext {
            id: id.into(),
            user,
            expires,
            limits: serde_json::from_str(&limits)?,
            session,
            share,
        })
    }

    pub fn limits(&self, claims: &Claims) -> Result<Vec<Vec<Grant>>> {
        self.check_authorization(claims)?;
        let mut limits = self.authorization(&claims.aid)?.limits;
        limits.push(self.grants(&claims.sub)?);
        Ok(limits)
    }

    pub(crate) fn can_repository(
        &self,
        context: &AuthorizationContext,
        repository: &str,
        action: &str,
    ) -> Result<bool> {
        Ok(context
            .limits
            .iter()
            .all(|rules| rules.iter().any(|r| r.repository(repository, action)))
            && self
                .grants(&context.user)?
                .iter()
                .any(|r| r.repository(repository, action)))
    }

    pub(crate) fn requested_in(
        &self,
        context: &AuthorizationContext,
        scopes: &[String],
    ) -> Result<Vec<Access>> {
        let mut access = Vec::new();
        for scope in scopes.iter().flat_map(|s| s.split_whitespace()) {
            if matches!(
                scope,
                "registry:catalog:read" | "registry:catalog:*" | CATALOG_GRANTS_SCOPE
            ) {
                access.push(Access {
                    kind: "registry".into(),
                    name: "catalog".into(),
                    actions: vec!["read".into()],
                });
                if scope == CATALOG_GRANTS_SCOPE {
                    // Explicit optional extension: concrete account repositories only.
                    let names: BTreeSet<_> = self
                        .grants(&context.user)?
                        .into_iter()
                        .flat_map(|r| r.repositories)
                        .filter(|r| !r.contains('*'))
                        .collect();
                    for name in names {
                        let mut actions = Vec::new();
                        for action in ["pull", "push"] {
                            if self.can_repository(context, &name, action)? {
                                actions.push(action.into());
                            }
                        }
                        if !actions.is_empty() {
                            access.push(Access {
                                kind: "repository".into(),
                                name,
                                actions,
                            });
                        }
                    }
                }
                continue;
            }
            let value = scope
                .strip_prefix("repository:")
                .context("Unsupported token scope")?;
            let (name, requested) = parse_grant(value)?;
            let mut actions = Vec::new();
            for action in requested {
                if self.can_repository(context, &name, &action)? {
                    actions.push(action);
                }
            }
            access.push(Access {
                kind: "repository".into(),
                name,
                actions,
            });
        }
        Ok(access)
    }

    pub(crate) fn sign_authorization(
        &self,
        context: &AuthorizationContext,
        access: Vec<Access>,
        root: bool,
        ttl: u64,
    ) -> Result<(String, Claims)> {
        let issued = now();
        let expires = context
            .expires
            .min(issued.saturating_add(ttl.min(TOKEN_SECONDS)));
        ensure!(expires > issued, "Authorization expired");
        let claims = Claims {
            iss: self.issuer.clone(),
            aud: self.service.clone(),
            sub: context.user.clone(),
            exp: expires,
            iat: issued,
            jti: Uuid::new_v4().to_string(),
            access,
            sid: context.session.clone(),
            aid: context.id.clone(),
            share_id: context.share.clone(),
            root,
        };
        Ok((
            encode(
                &Header::new(Algorithm::HS256),
                &claims,
                &EncodingKey::from_secret(&self.secret),
            )?,
            claims,
        ))
    }

    pub fn exchange(&self, root: &Claims, scopes: &[String]) -> Result<(String, Claims)> {
        ensure!(
            root.root && (root.sid.is_some() || root.share_id.is_some()),
            "Use an approved session credential"
        );
        // Revalidate expiry/revocation even for callers holding a Claims instance.
        self.check_authorization(root)?;
        let context = self.authorization(&root.aid)?;
        let access = self.requested_in(&context, scopes)?;
        self.sign_authorization(&context, access, false, TOKEN_SECONDS)
    }

    pub(crate) fn check_authorization(&self, claims: &Claims) -> Result<()> {
        let context = self.authorization(&claims.aid)?;
        ensure!(
            context.user == claims.sub
                && context.session == claims.sid
                && context.share == claims.share_id
                && claims.exp <= context.expires
                && claims.exp > now(),
            "Invalid authorization binding"
        );
        if let Some(sid) = &claims.sid {
            let db = self
                .db
                .lock()
                .map_err(|_| anyhow::anyhow!("Identity store lock failed"))?;
            ensure!(db.query_row("SELECT EXISTS(SELECT 1 FROM oauth_sessions WHERE id=?1 AND user=?2 AND revoked=0 AND expires>?3)", params![sid,claims.sub,i64::try_from(now())?], |r| r.get::<_,bool>(0))?, "Session expired or revoked");
        }
        if let Some(share) = &claims.share_id {
            let db = self
                .db
                .lock()
                .map_err(|_| anyhow::anyhow!("Identity store lock failed"))?;
            ensure!(db.query_row("SELECT EXISTS(SELECT 1 FROM shares WHERE id=?1 AND creator=?2 AND revoked=0 AND expires>?3)", params![share,claims.sub,i64::try_from(now())?], |r| r.get::<_,bool>(0))?, "Share expired or revoked");
        }
        Ok(())
    }
}
