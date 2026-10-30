//! Persistent, rotating browser sessions. Only refresh-token hashes reach disk.
use anyhow::{ensure, Context, Result};
use rand_core::{OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{now, Access, Auth, Claims, TOKEN_SECONDS};

pub const SESSION_SECONDS: u64 = 8 * 60 * 60;
pub const REMEMBER_SECONDS: u64 = 30 * 24 * 60 * 60;

#[derive(Clone, Serialize, Deserialize)]
pub struct RefreshSession {
    pub id: String,
    pub user: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub expires: u64,
    pub remember: bool,
    pub access: Vec<Access>,
    pub authorization_id: String,
    pub root: bool,
}

pub struct SessionTokens {
    pub permissions: Vec<crate::policy::Grant>,
    pub access_token: String,
    pub claims: Claims,
    pub refresh_token: String,
    pub session: RefreshSession,
}

pub(super) fn schema(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS oauth_sessions (
        id TEXT PRIMARY KEY,user TEXT NOT NULL REFERENCES users(name) ON DELETE CASCADE,
        client_id TEXT NOT NULL,redirect_uri TEXT NOT NULL,expires INTEGER NOT NULL,
        remember INTEGER NOT NULL,access TEXT NOT NULL,revoked INTEGER NOT NULL DEFAULT 0,authorization TEXT NOT NULL,root INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
        hash TEXT PRIMARY KEY,session_id TEXT NOT NULL REFERENCES oauth_sessions(id) ON DELETE CASCADE,
        used INTEGER NOT NULL DEFAULT 0);
        CREATE INDEX IF NOT EXISTS oauth_refresh_session ON oauth_refresh_tokens(session_id);")?;
    Ok(())
}

fn token() -> String {
    let mut bytes = [0; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn hash(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn from_row(row: &Row<'_>) -> rusqlite::Result<RefreshSession> {
    let access: String = row.get(6)?;
    let expires: i64 = row.get(4)?;
    Ok(RefreshSession {
        id: row.get(0)?,
        user: row.get(1)?,
        client_id: row.get(2)?,
        redirect_uri: row.get(3)?,
        expires: expires
            .try_into()
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(4, expires))?,
        remember: row.get(5)?,
        authorization_id: row.get(7)?,
        root: row.get(8)?,
        access: serde_json::from_str(&access).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(6, rusqlite::types::Type::Text, Box::new(e))
        })?,
    })
}

impl Auth {
    pub fn start_session(
        &self,
        user: &str,
        scopes: &[String],
        client_id: &str,
        redirect_uri: &str,
        remember: bool,
    ) -> Result<SessionTokens> {
        self.start_approved_session(
            (user, self.grants(user)?),
            scopes,
            client_id,
            redirect_uri,
            remember,
        )
    }

    pub(crate) fn start_approved_session(
        &self,
        approved: (&str, Vec<crate::policy::Grant>),
        scopes: &[String],
        client_id: &str,
        redirect_uri: &str,
        remember: bool,
    ) -> Result<SessionTokens> {
        let (user, permissions) = approved;
        let expires = now()
            + if remember {
                REMEMBER_SECONDS
            } else {
                SESSION_SECONDS
            };
        let context =
            super::AuthorizationContext::new(user, vec![permissions], expires, None, None)?;
        self.start_limited_session(context, scopes, client_id, redirect_uri, remember)
    }

    pub(crate) fn start_limited_session(
        &self,
        mut context: super::AuthorizationContext,
        scopes: &[String],
        client_id: &str,
        redirect_uri: &str,
        remember: bool,
    ) -> Result<SessionTokens> {
        let id = Uuid::new_v4().to_string();
        context.session = Some(id.clone());
        let user = context.user.clone();
        let expires = context.expires;
        let root = scopes == [super::SESSION_SCOPE.to_string()];
        let catalog = ["registry:catalog:*".into()];
        let access = self.requested_in(&context, if root { &catalog } else { scopes })?;
        if !root {
            // A repository-only approval may not later mint access to other resources.
            // Catalog grants remain an explicit extension, not an implicit widening.
            let approved: Vec<_> = access
                .iter()
                .filter(|a| a.kind == "repository")
                .map(|a| crate::policy::Grant::exact(a.name.clone(), a.actions.clone()))
                .collect();
            // Catalog-only approval can list the captured policy, while its JWT
            // still carries no repository access or token-exchange capability.
            if !approved.is_empty() {
                context.limits.push(approved);
            }
        }
        let session = RefreshSession {
            id,
            user,
            client_id: client_id.into(),
            redirect_uri: redirect_uri.into(),
            expires,
            remember,
            access,
            authorization_id: context.id.clone(),
            root,
        };
        let refresh_token = token();
        {
            let mut db = self
                .db
                .lock()
                .map_err(|_| anyhow::anyhow!("Identity store lock failed"))?;
            let tx = db.transaction()?;
            context.store(&tx)?;
            tx.execute(
                "DELETE FROM oauth_sessions WHERE expires<=?1",
                [i64::try_from(now())?],
            )?;
            tx.execute(
                "INSERT INTO oauth_sessions(id,user,client_id,redirect_uri,expires,remember,access,authorization,root)
                VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    session.id,
                    session.user,
                    session.client_id,
                    session.redirect_uri,
                    i64::try_from(session.expires)?,
                    session.remember,
                    serde_json::to_string(&session.access)?,session.authorization_id,session.root
                ],
            )?;
            tx.execute(
                "INSERT INTO oauth_refresh_tokens(hash,session_id) VALUES (?1,?2)",
                params![hash(&refresh_token), session.id],
            )?;
            tx.commit()?;
        }
        self.session_tokens(session, refresh_token)
    }

    /// Read binding metadata before an HTTP caller checks cookie origin/mode.
    pub fn refresh_session(&self, refresh_token: &str) -> Result<Option<RefreshSession>> {
        let db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("Identity store lock failed"))?;
        Ok(db
            .query_row(
                "SELECT s.id,s.user,s.client_id,s.redirect_uri,s.expires,s.remember,s.access,s.authorization,s.root
            FROM oauth_refresh_tokens t JOIN oauth_sessions s ON s.id=t.session_id WHERE t.hash=?1",
                [hash(refresh_token)],
                from_row,
            )
            .optional()?)
    }

    pub fn rotate_session(&self, refresh_token: &str, client_id: &str) -> Result<SessionTokens> {
        let replacement = token();
        let session = {
            let mut db = self
                .db
                .lock()
                .map_err(|_| anyhow::anyhow!("Identity store lock failed"))?;
            let tx = db.transaction()?;
            tx.execute(
                "DELETE FROM oauth_sessions WHERE expires<=?1",
                [i64::try_from(now())?],
            )?;
            let (session, revoked, used) = tx.query_row(
                "SELECT s.id,s.user,s.client_id,s.redirect_uri,s.expires,s.remember,s.access,s.authorization,s.root,s.revoked,t.used
                FROM oauth_refresh_tokens t JOIN oauth_sessions s ON s.id=t.session_id WHERE t.hash=?1",
                [hash(refresh_token)], |row| Ok((from_row(row)?,row.get::<_,bool>(9)?,row.get::<_,bool>(10)?)))
                .optional()?.context("Invalid refresh token")?;
            ensure!(
                session.client_id == client_id && !revoked,
                "Invalid refresh session"
            );
            if used {
                tx.execute(
                    "UPDATE oauth_sessions SET revoked=1 WHERE id=?1",
                    [&session.id],
                )?;
                tx.commit()?;
                anyhow::bail!("Refresh token replay revoked the session");
            }
            tx.execute(
                "UPDATE oauth_refresh_tokens SET used=1 WHERE hash=?1",
                [hash(refresh_token)],
            )?;
            tx.execute(
                "INSERT INTO oauth_refresh_tokens(hash,session_id) VALUES (?1,?2)",
                params![hash(&replacement), session.id],
            )?;
            tx.commit()?;
            session
        };
        self.session_tokens(session, replacement)
    }

    fn session_tokens(
        &self,
        session: RefreshSession,
        refresh_token: String,
    ) -> Result<SessionTokens> {
        let remaining = session.expires.saturating_sub(now());
        ensure!(remaining > 0, "Session has expired");
        let mut access = Vec::new();
        // Reevaluate removals while never widening beyond the original approval.
        for approved in &session.access {
            let mut grant = approved.clone();
            if grant.kind == "repository" {
                grant.actions = approved
                    .actions
                    .iter()
                    .filter_map(
                        |action| match self.allowed(&session.user, &grant.name, action) {
                            Ok(true) => Some(Ok(action.clone())),
                            Ok(false) => None,
                            Err(e) => Some(Err(e)),
                        },
                    )
                    .collect::<Result<Vec<_>>>()?;
            }
            access.push(grant);
        }
        let mut context = self.authorization(&session.authorization_id)?;
        context.expires = context.expires.min(session.expires);
        let (access_token, claims) =
            self.sign_authorization(&context, access, session.root, TOKEN_SECONDS.min(remaining))?;
        if claims.share_id.is_some() {
            self.check_authorization(&claims)?;
        }
        Ok(SessionTokens {
            permissions: context.limits.first().cloned().unwrap_or_default(),
            access_token,
            claims,
            refresh_token,
            session,
        })
    }

    pub fn revoke_session(&self, refresh_token: &str, client_id: &str) -> Result<()> {
        let db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("Identity store lock failed"))?;
        db.execute(
            "UPDATE oauth_sessions SET revoked=1 WHERE client_id=?1 AND id IN
            (SELECT session_id FROM oauth_refresh_tokens WHERE hash=?2)",
            params![client_id, hash(refresh_token)],
        )?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "sessions_tests.rs"]
mod tests;
