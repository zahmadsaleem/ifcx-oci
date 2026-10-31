//! Local identity store, Argon2 passwords and repository-scoped JWTs.
use std::{
    collections::BTreeSet,
    fs,
    path::Path,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{ensure, Context, Result};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand_core::{OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const TOKEN_SECONDS: u64 = 900;
// An internal read-only principal, outside the allowed account-name alphabet.
pub(crate) const PUBLIC_SUBJECT: &str = "@public";
mod authorization;
mod browser;
pub(crate) use browser::BrowserBinding;
mod grants;
mod sessions;
mod shares;
pub use authorization::{AuthorizationContext, CATALOG_GRANTS_SCOPE, SESSION_SCOPE};
pub use grants::StoredGrant;
pub use shares::{Share, ShareBinding, ShareCreated, ShareSpec, DEFAULT_SHARE_MAX_SECONDS};
mod throttle;
pub use sessions::{RefreshSession, SessionTokens, REMEMBER_SECONDS, SESSION_SECONDS};
pub(crate) use throttle::PasswordLoginError;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Access {
    #[serde(rename = "type")]
    pub kind: String,
    pub name: String,
    pub actions: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub exp: u64,
    pub iat: u64,
    pub jti: String,
    pub access: Vec<Access>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    pub aid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share_id: Option<String>,
    #[serde(default)]
    pub root: bool,
}

pub struct Auth {
    db: Mutex<Connection>,
    login_throttle: Mutex<throttle::LoginThrottle>,
    secret: Vec<u8>,
    pub service: String,
    issuer: String,
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

#[cfg(unix)]
pub fn private_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}
#[cfg(not(unix))]
pub fn private_file(_path: &Path) -> Result<()> {
    Ok(())
}

fn secret_file(path: &Path) -> Result<Vec<u8>> {
    use std::io::Write;
    if path.exists() {
        let value = fs::read(path)?;
        ensure!(value.len() == 32, "Invalid registry signing key");
        return Ok(value);
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    let mut value = vec![0u8; 32];
    OsRng.fill_bytes(&mut value);
    file.write_all(&value)?;
    file.sync_all()?;
    Ok(value)
}

impl Auth {
    pub(crate) fn check_ready(&self) -> Result<()> {
        let mut db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("Identity store lock failed"))?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        ensure!(
            tx.execute("UPDATE settings SET value=value WHERE key='id'", [])? == 1,
            "Missing registry identity"
        );
        tx.rollback()?;
        Ok(())
    }
    pub fn open(root: &Path) -> Result<Self> {
        fs::create_dir_all(root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
        }
        let db_path = root.join("auth.sqlite");
        let db = Connection::open(&db_path)?;
        private_file(&db_path)?;
        db.execute_batch(
            "PRAGMA foreign_keys=ON;
          CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY,value TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS users (name TEXT PRIMARY KEY,password_hash TEXT NOT NULL);
",
        )?;
        grants::schema(&db)?;
        authorization::schema(&db)?;
        shares::schema(&db)?;
        sessions::schema(&db)?;
        db.execute(
            "INSERT OR IGNORE INTO settings VALUES ('id',?1)",
            [Uuid::new_v4().to_string()],
        )?;
        let id: String = db.query_row("SELECT value FROM settings WHERE key='id'", [], |r| {
            r.get(0)
        })?;
        let secret = secret_file(&root.join("signing.key"))?;
        Ok(Self {
            db: Mutex::new(db),
            login_throttle: Mutex::new(throttle::LoginThrottle::default()),
            secret,
            service: format!("subsoil:{id}"),
            issuer: format!("urn:subsoil:registry:{id}"),
        })
    }

    pub fn add_user(&self, name: &str, password: &str, grants: &[String]) -> Result<()> {
        ensure!(
            !name.is_empty()
                && name.len() <= 64
                && name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c)),
            "Invalid user name"
        );
        ensure!(
            password.len() >= 12,
            "Use a password of at least 12 characters"
        );
        let parsed: Vec<_> = grants
            .iter()
            .map(|g| parse_grant(g))
            .collect::<Result<_>>()?;
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("Password hashing failed: {e}"))?
            .to_string();
        let mut db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("Identity store lock failed"))?;
        let tx = db.transaction()?;
        tx.execute("INSERT INTO users VALUES (?1,?2)", params![name, hash])
            .context("User already exists or cannot be created")?;
        for (repo, actions) in parsed {
            let rule = crate::policy::Grant::exact(repo, actions);
            tx.execute(
                "INSERT INTO policy_rules(user,rule) VALUES (?1,?2)",
                params![name, serde_json::to_string(&rule)?],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn grant(&self, user: &str, grant: &str) -> Result<()> {
        let (repository, actions) = parse_grant(grant)?;
        self.add_rule(user, &crate::policy::Grant::exact(repository, actions))?;
        Ok(())
    }

    pub fn authenticate(&self, name: &str, password: &str) -> Result<()> {
        ensure!(name != PUBLIC_SUBJECT, "Invalid credentials");
        let db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("Identity store lock failed"))?;
        let hash: String = db
            .query_row(
                "SELECT password_hash FROM users WHERE name=?1",
                [name],
                |r| r.get(0),
            )
            .context("Invalid credentials")?;
        drop(db);
        let hash = PasswordHash::new(&hash)
            .map_err(|_| anyhow::anyhow!("Invalid stored password hash"))?;
        Argon2::default()
            .verify_password(password.as_bytes(), &hash)
            .map_err(|_| anyhow::anyhow!("Invalid credentials"))?;
        Ok(())
    }

    fn allowed(&self, user: &str, repo: &str, action: &str) -> Result<bool> {
        Ok(self
            .grants(user)?
            .iter()
            .any(|r| r.repository(repo, action)))
    }

    pub fn issue(&self, user: &str, scopes: &[String], ttl: u64) -> Result<(String, Claims)> {
        let context = AuthorizationContext::new(
            user,
            vec![self.grants(user)?],
            now().saturating_add(ttl),
            None,
            None,
        )?;
        let access = self.requested_in(&context, scopes)?;
        let issued = self.sign_authorization(&context, access, false, ttl)?;
        let db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("Identity store lock failed"))?;
        context.store(&db)?;
        Ok(issued)
    }

    pub fn validate(&self, token: &str) -> Result<Claims> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.leeway = 0;
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.service]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub", "iat"]);
        let claims =
            decode::<Claims>(token, &DecodingKey::from_secret(&self.secret), &validation)?.claims;
        ensure!(
            claims.exp > now() && claims.iat <= now() + 5,
            "Token has expired or has an invalid issue time"
        );
        let db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("Identity store lock failed"))?;
        let exists: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE name=?1)",
            [&claims.sub],
            |r| r.get(0),
        )?;
        ensure!(exists, "Unknown token subject");
        if let Some(id) = &claims.sid {
            let active: bool = db.query_row(
                "SELECT EXISTS(SELECT 1 FROM oauth_sessions WHERE id=?1 AND user=?2 AND revoked=0 AND expires>?3)",
                params![id, claims.sub, i64::try_from(now())?], |row| row.get(0),
            )?;
            ensure!(active, "Session has expired or been revoked");
        }
        drop(db);
        self.check_authorization(&claims)?;
        Ok(claims)
    }

    pub fn permits(&self, claims: &Claims, repo: &str, action: &str) -> Result<bool> {
        self.check_authorization(claims)?;
        Ok(claims.access.iter().any(|a| {
            a.kind == "repository" && a.name == repo && a.actions.iter().any(|v| v == action)
        }) && self.can_repository(&self.authorization(&claims.aid)?, repo, action)?)
    }
}

pub fn parse_grant(value: &str) -> Result<(String, Vec<String>)> {
    let (repo, actions) = value.rsplit_once(':').context("Use repository:pull,push")?;
    crate::registry::valid_repo(repo)?;
    let actions: BTreeSet<_> = actions.split(',').map(str::to_string).collect();
    ensure!(
        !actions.is_empty() && actions.iter().all(|a| a == "pull" || a == "push"),
        "Only pull and push actions are supported"
    );
    Ok((repo.into(), actions.into_iter().collect()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn passwords_scopes_expiry_signature_issuer_and_audience() -> Result<()> {
        let root = tempfile::tempdir()?;
        let auth = Auth::open(root.path())?;
        auth.add_user(
            "reader",
            "reader-test-password",
            &["project/model:pull".into()],
        )?;
        auth.authenticate("reader", "reader-test-password")?;
        assert!(auth.authenticate("reader", "incorrect-password").is_err());
        let (token, claims) = auth.issue(
            "reader",
            &["repository:project/model:pull,push".into()],
            900,
        )?;
        assert_eq!(claims.access[0].actions, vec!["pull"]);
        let verified = auth.validate(&token)?;
        assert!(auth.permits(&verified, "project/model", "pull")?);
        assert!(!auth.permits(&verified, "project/model", "push")?);
        assert!(!auth.permits(&verified, "private/model", "pull")?);
        assert!(auth.issue("reader", &[], 0).is_err());
        let mut expired = claims.clone();
        expired.exp = now();
        assert!(auth
            .validate(&encode(
                &Header::new(Algorithm::HS256),
                &expired,
                &EncodingKey::from_secret(&auth.secret)
            )?)
            .is_err());
        assert!(auth.validate("invalid.jwt.signature").is_err());
        let mut changed = claims.clone();
        changed.aud = "another-registry".into();
        assert!(auth
            .validate(&encode(
                &Header::new(Algorithm::HS256),
                &changed,
                &EncodingKey::from_secret(&auth.secret)
            )?)
            .is_err());
        changed = claims.clone();
        changed.iss = "another-issuer".into();
        assert!(auth
            .validate(&encode(
                &Header::new(Algorithm::HS256),
                &changed,
                &EncodingKey::from_secret(&auth.secret)
            )?)
            .is_err());
        changed = claims;
        changed.iat = now() + 3600;
        assert!(auth
            .validate(&encode(
                &Header::new(Algorithm::HS256),
                &changed,
                &EncodingKey::from_secret(&auth.secret)
            )?)
            .is_err());
        assert!(auth
            .validate(&encode(
                &Header::new(Algorithm::HS256),
                &verified,
                &EncodingKey::from_secret(b"unrelated signing material of sufficient length")
            )?)
            .is_err());
        let db = Connection::open(root.path().join("auth.sqlite"))?;
        let stored: String = db.query_row("SELECT password_hash FROM users", [], |r| r.get(0))?;
        assert!(stored.starts_with("$argon2id$") && !stored.contains("reader-test-password"));
        drop(auth);
        let reopened = Auth::open(root.path())?;
        assert!(reopened.validate(&token).is_ok());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(root.path().join("signing.key"))?
                    .permissions()
                    .mode()
                    & 0o077,
                0
            );
        }
        Ok(())
    }
}
