//! Registry browser identity markers. These JWTs carry no API authorization.
use super::*;
use sha2::{Digest, Sha256};

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct BrowserBinding {
    pub sub: String,
    pub jti: String,
    pub exp: u64,
    pub password_authenticated: bool,
    iat: u64,
    iss: String,
    aud: String,
    credential_epoch: String,
}

impl Auth {
    pub(crate) fn issue_browser_binding(
        &self,
        user: &str,
        expires: u64,
        password_authenticated: bool,
    ) -> Result<(String, BrowserBinding)> {
        let issued = now();
        ensure!(
            expires > issued && expires <= issued.saturating_add(REMEMBER_SECONDS),
            "Invalid browser binding lifetime"
        );
        let binding = BrowserBinding {
            sub: user.into(),
            jti: Uuid::new_v4().to_string(),
            exp: expires,
            password_authenticated,
            iat: issued,
            iss: self.issuer.clone(),
            aud: format!("{}:browser", self.service),
            credential_epoch: self.browser_credential_epoch(user)?,
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &binding,
            &EncodingKey::from_secret(&self.secret),
        )?;
        Ok((token, binding))
    }

    pub(crate) fn browser_binding(&self, token: &str) -> Result<BrowserBinding> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.leeway = 0;
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[format!("{}:browser", self.service)]);
        let binding =
            decode::<BrowserBinding>(token, &DecodingKey::from_secret(&self.secret), &validation)?
                .claims;
        ensure!(
            binding.exp > now() && binding.iat <= now() + 5,
            "Browser binding expired"
        );
        ensure!(
            binding.credential_epoch == self.browser_credential_epoch(&binding.sub)?,
            "Account credentials changed"
        );
        Ok(binding)
    }

    fn browser_credential_epoch(&self, user: &str) -> Result<String> {
        let db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("Identity store lock failed"))?;
        let password: String = db.query_row(
            "SELECT password_hash FROM users WHERE name=?1",
            [user],
            |row| row.get(0),
        )?;
        let mut digest = Sha256::new();
        digest.update(&self.secret);
        digest.update(password.as_bytes());
        Ok(hex::encode(digest.finalize()))
    }

    pub(crate) fn session_client(&self, claims: &Claims) -> Result<String> {
        self.check_authorization(claims)?;
        let db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("Identity store lock failed"))?;
        Ok(db.query_row("SELECT client_id FROM oauth_sessions WHERE id=?1 AND user=?2 AND revoked=0 AND expires>?3",
            params![claims.sid, claims.sub, i64::try_from(now())?], |row| row.get(0))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_markers_are_purpose_bound_expiring_and_invalidated_by_credential_changes(
    ) -> Result<()> {
        let temp = tempfile::tempdir()?;
        let auth = Auth::open(temp.path())?;
        auth.add_user("owner", "browser-marker-test-password", &[])?;
        let (token, binding) = auth.issue_browser_binding("owner", now() + 60, true)?;
        assert_eq!(auth.browser_binding(&token)?.sub, "owner");
        assert!(auth.validate(&token).is_err());
        let (access, _) = auth.issue("owner", &[], 60)?;
        assert!(auth.browser_binding(&access).is_err());
        let mut expired = binding.clone();
        expired.exp = now();
        let expired = encode(
            &Header::new(Algorithm::HS256),
            &expired,
            &EncodingKey::from_secret(&auth.secret),
        )?;
        assert!(auth.browser_binding(&expired).is_err());
        let mut future = binding;
        future.iat = now() + 60;
        let future = encode(
            &Header::new(Algorithm::HS256),
            &future,
            &EncodingKey::from_secret(&auth.secret),
        )?;
        assert!(auth.browser_binding(&future).is_err());
        let db = Connection::open(temp.path().join("auth.sqlite"))?;
        db.execute(
            "UPDATE users SET password_hash=password_hash || 'changed' WHERE name='owner'",
            [],
        )?;
        assert!(auth.browser_binding(&token).is_err());
        Ok(())
    }
}
