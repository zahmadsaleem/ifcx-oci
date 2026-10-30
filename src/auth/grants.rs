//! Account grant administration. Grant sets are registry-bound and fail closed.
use super::*;
use crate::policy::{self, Grant, GrantSet};

#[derive(Serialize)]
pub struct StoredGrant {
    pub id: i64,
    #[serde(flatten)]
    pub grant: Grant,
}

pub(super) fn schema(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS policy_rules (
        id INTEGER PRIMARY KEY,user TEXT NOT NULL REFERENCES users(name) ON DELETE CASCADE,rule TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS policy_user ON policy_rules(user);")?;
    Ok(())
}

impl Auth {
    pub fn grants(&self, user: &str) -> Result<Vec<Grant>> {
        Ok(self
            .list_grants(user)?
            .into_iter()
            .map(|r| r.grant)
            .collect())
    }

    pub fn list_grants(&self, user: &str) -> Result<Vec<StoredGrant>> {
        let db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("Identity store lock failed"))?;
        let mut query = db.prepare("SELECT id,rule FROM policy_rules WHERE user=?1 ORDER BY id")?;
        let rows = query.query_map([user], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
        })?;
        rows.map(|row| {
            let (id, rule) = row?;
            Ok(StoredGrant {
                id,
                grant: serde_json::from_str(&rule)?,
            })
        })
        .collect()
    }

    pub fn add_rule(&self, user: &str, rule: &Grant) -> Result<i64> {
        policy::validate(std::slice::from_ref(rule), false)?;
        let db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("Identity store lock failed"))?;
        let count: i64 = db.query_row(
            "SELECT COUNT(*) FROM policy_rules WHERE user=?1",
            [user],
            |r| r.get(0),
        )?;
        ensure!(count < policy::MAX_RULES as i64, "Too many grant rules");
        db.execute(
            "INSERT INTO policy_rules(user,rule) VALUES (?1,?2)",
            params![user, serde_json::to_string(rule)?],
        )?;
        Ok(db.last_insert_rowid())
    }

    pub fn remove_grant(&self, user: &str, id: i64) -> Result<()> {
        let db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("Identity store lock failed"))?;
        ensure!(
            db.execute(
                "DELETE FROM policy_rules WHERE user=?1 AND id=?2",
                params![user, id]
            )? == 1,
            "Unknown grant"
        );
        Ok(())
    }

    pub fn set_grants(&self, user: &str, policy: &GrantSet) -> Result<()> {
        ensure!(policy.version == 1, "Unsupported grant version");
        policy::validate(&policy.grants, false)?;
        let registry = policy::registry_name(&policy.registry)?;
        let mut db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("Identity store lock failed"))?;
        let tx = db.transaction()?;
        ensure!(
            tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM users WHERE name=?1)",
                [user],
                |r| r.get::<_, bool>(0)
            )?,
            "Unknown user"
        );
        let binding: Option<String> = tx
            .query_row(
                "SELECT value FROM settings WHERE key='policy_registry'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        ensure!(
            binding.as_ref().is_none_or(|b| b == &registry),
            "Grant registry does not match this store"
        );
        tx.execute(
            "INSERT OR IGNORE INTO settings(key,value) VALUES ('policy_registry',?1)",
            [&registry],
        )?;
        tx.execute("DELETE FROM policy_rules WHERE user=?1", [user])?;
        for rule in &policy.grants {
            tx.execute(
                "INSERT INTO policy_rules(user,rule) VALUES (?1,?2)",
                params![user, serde_json::to_string(rule)?],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn validate_registry(&self, registry: &str) -> Result<()> {
        let db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("Identity store lock failed"))?;
        let binding: Option<String> = db
            .query_row(
                "SELECT value FROM settings WHERE key='policy_registry'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        ensure!(
            binding.is_none_or(|b| b == registry),
            "Public registry does not match the imported grant set"
        );
        Ok(())
    }
}
