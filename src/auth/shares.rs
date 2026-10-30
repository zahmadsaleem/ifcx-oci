//! Revocable, independent share authorizations. Only secret hashes are persisted.
use super::*;
use crate::policy::{self, Grant};
use rand_core::RngCore;
use sha2::{Digest, Sha256};

pub const DEFAULT_SHARE_MAX_SECONDS: u64 = 30 * 24 * 60 * 60;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ShareBinding {
    #[default]
    Snapshot,
    Live,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Share {
    pub id: String,
    pub creator: String,
    pub expires_at: u64,
    pub binding: ShareBinding,
    pub grants: Vec<Grant>,
    pub revoked: bool,
}

#[derive(Serialize)]
pub struct ShareCreated {
    #[serde(flatten)]
    pub share: Share,
    pub secret: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareSpec {
    pub grants: Vec<Grant>,
    #[serde(default)]
    pub binding: ShareBinding,
    pub ttl: u64,
}

pub(super) fn schema(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS shares (
        id TEXT PRIMARY KEY,creator TEXT NOT NULL REFERENCES users(name) ON DELETE CASCADE,
        secret_hash TEXT NOT NULL UNIQUE,expires INTEGER NOT NULL,revoked INTEGER NOT NULL DEFAULT 0,
        authorization TEXT NOT NULL,metadata TEXT NOT NULL);")?;
    Ok(())
}

fn hash(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

impl Auth {
    pub(crate) fn create_share(
        &self,
        creator: &str,
        spec: ShareSpec,
        mut limits: Vec<Vec<Grant>>,
        snapshot: Option<Vec<Grant>>,
        maximum: u64,
    ) -> Result<ShareCreated> {
        policy::validate(&spec.grants, false)?;
        ensure!(
            !spec.grants.is_empty() && spec.ttl > 0 && spec.ttl <= maximum,
            "Share TTL must be positive and within the configured maximum"
        );
        limits.push(self.grants(creator)?);
        ensure!(
            limits
                .iter()
                .all(|parent| policy::delegates(parent, &spec.grants)),
            "Share exceeds the creator's approved permissions"
        );
        limits.push(spec.grants.clone());
        match spec.binding {
            ShareBinding::Snapshot => {
                ensure!(
                    spec.grants
                        .iter()
                        .all(|g| g.actions.iter().all(|a| a == "pull")),
                    "Snapshot shares are read-only; choose live explicitly to publish"
                );
                let snapshot = snapshot.context("Snapshot must be resolved by the registry")?;
                policy::validate(&snapshot, true)?;
                ensure!(
                    !snapshot.is_empty(),
                    "No authorized artifacts match this snapshot"
                );
                limits.push(snapshot);
            }
            ShareBinding::Live => ensure!(
                snapshot.is_none(),
                "Live shares cannot contain snapshot roots"
            ),
        }
        let expires_at = now().checked_add(spec.ttl).context("Invalid TTL")?;
        let id = Uuid::new_v4().to_string();
        let context =
            AuthorizationContext::new(creator, limits, expires_at, None, Some(id.clone()))?;
        let mut secret = [0; 32];
        rand_core::OsRng.fill_bytes(&mut secret);
        let secret = hex::encode(secret);
        let share = Share {
            id,
            creator: creator.into(),
            expires_at,
            binding: spec.binding,
            grants: spec.grants,
            revoked: false,
        };
        let mut db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("Identity store lock failed"))?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let active: i64 = tx.query_row(
            "SELECT COUNT(*) FROM shares WHERE creator=?1 AND revoked=0 AND expires>?2",
            params![creator, i64::try_from(now())?],
            |r| r.get(0),
        )?;
        ensure!(
            active < 128,
            "At most 128 active shares are allowed per account"
        );
        context.store(&tx)?;
        tx.execute(
            "INSERT INTO shares VALUES (?1,?2,?3,?4,0,?5,?6)",
            params![
                share.id,
                creator,
                hash(&secret),
                i64::try_from(expires_at)?,
                context.id,
                serde_json::to_string(&share)?
            ],
        )?;
        tx.commit()?;
        Ok(ShareCreated { share, secret })
    }

    pub fn list_shares(&self, creator: &str) -> Result<Vec<Share>> {
        let db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("Identity store lock failed"))?;
        let mut query =
            db.prepare("SELECT metadata,revoked FROM shares WHERE creator=?1 ORDER BY expires,id")?;
        let rows = query.query_map([creator], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?))
        })?;
        rows.map(|r| {
            let (metadata, revoked) = r?;
            let mut share: Share = serde_json::from_str(&metadata)?;
            share.revoked = revoked;
            Ok(share)
        })
        .collect()
    }

    pub fn revoke_share(&self, creator: &str, id: &str) -> Result<()> {
        let db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("Identity store lock failed"))?;
        ensure!(
            db.execute(
                "UPDATE shares SET revoked=1 WHERE creator=?1 AND id=?2",
                params![creator, id]
            )? == 1,
            "Unknown share"
        );
        Ok(())
    }

    pub fn redeem_share(&self, secret: &str) -> Result<(String, Claims, Share)> {
        ensure!(
            secret.len() == 64 && secret.bytes().all(|b| b.is_ascii_hexdigit()),
            "Invalid share credential"
        );
        let (authorization, metadata) = {
            let db = self
                .db
                .lock()
                .map_err(|_| anyhow::anyhow!("Identity store lock failed"))?;
            db.query_row("SELECT authorization,metadata FROM shares WHERE secret_hash=?1 AND revoked=0 AND expires>?2", params![hash(secret),i64::try_from(now())?], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?)))?
        };
        let context = self.authorization(&authorization)?;
        let access = self.requested_in(&context, &["registry:catalog:*".into()])?;
        let (token, claims) = self.sign_authorization(&context, access, true, TOKEN_SECONDS)?;
        self.check_authorization(&claims)?;
        Ok((token, claims, serde_json::from_str(&metadata)?))
    }

    pub fn delegation_limits(&self, claims: &Claims) -> Result<Vec<Vec<Grant>>> {
        self.check_authorization(claims)?;
        ensure!(
            claims.share_id.is_none(),
            "Share guests cannot delegate or administer shares"
        );
        let mut limits = self.limits(claims)?;
        if !claims.root {
            limits.push(
                claims
                    .access
                    .iter()
                    .filter(|a| a.kind == "repository")
                    .map(|a| Grant::exact(a.name.clone(), a.actions.clone()))
                    .collect(),
            );
        }
        Ok(limits)
    }
}
