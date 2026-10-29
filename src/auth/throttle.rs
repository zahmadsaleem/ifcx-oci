//! Shared online password budget. Never keyed by untrusted proxy headers.
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use super::Auth;
use crate::registry::Registry;

const WINDOW: Duration = Duration::from_secs(60);
const ACCOUNT_LIMIT: usize = 5;
const GLOBAL_LIMIT: usize = 60;

pub(crate) enum PasswordLoginError {
    InvalidCredentials,
    Throttled(u64),
    Unavailable,
}

struct Budget {
    start: Instant,
    attempts: usize,
}
impl Budget {
    fn new(time: Instant) -> Self {
        Self {
            start: time,
            attempts: 0,
        }
    }
    fn retry_after(&self, time: Instant) -> u64 {
        (WINDOW
            .saturating_sub(time.duration_since(self.start))
            .as_secs_f64()
            .ceil() as u64)
            .max(1)
    }
}

pub(super) struct LoginThrottle {
    global: Budget,
    accounts: HashMap<[u8; 32], Budget>,
}
impl Default for LoginThrottle {
    fn default() -> Self {
        Self {
            global: Budget::new(Instant::now()),
            accounts: HashMap::new(),
        }
    }
}
impl LoginThrottle {
    fn reserve(&mut self, username: &str, time: Instant) -> Result<(), PasswordLoginError> {
        if time.duration_since(self.global.start) >= WINDOW {
            self.global = Budget::new(time);
        }
        self.accounts
            .retain(|_, b| time.duration_since(b.start) < WINDOW);
        if self.global.attempts >= GLOBAL_LIMIT {
            return Err(PasswordLoginError::Throttled(self.global.retry_after(time)));
        }
        let budget = self
            .accounts
            .entry(Sha256::digest(username.as_bytes()).into())
            .or_insert_with(|| Budget::new(time));
        if budget.attempts >= ACCOUNT_LIMIT {
            return Err(PasswordLoginError::Throttled(budget.retry_after(time)));
        }
        // Reserve before Argon2, including successful attempts and nonexistent
        // accounts. The global budget also bounds this map and password work.
        budget.attempts += 1;
        self.global.attempts += 1;
        Ok(())
    }
}

impl Auth {
    fn password_login(&self, username: &str, password: &str) -> Result<(), PasswordLoginError> {
        self.login_throttle
            .lock()
            .map_err(|_| PasswordLoginError::Unavailable)?
            .reserve(username, Instant::now())?;
        self.authenticate(username, password)
            .map_err(|_| PasswordLoginError::InvalidCredentials)
    }
}

impl Registry {
    pub(crate) async fn password_login(
        self: &Arc<Self>,
        username: String,
        password: String,
    ) -> Result<(), PasswordLoginError> {
        let registry = self.clone();
        tokio::task::spawn_blocking(move || registry.auth.password_login(&username, &password))
            .await
            .map_err(|_| PasswordLoginError::Unavailable)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_and_global_budgets_expire_and_bound_memory() {
        let mut throttle = LoginThrottle::default();
        let time = Instant::now();
        for _ in 0..ACCOUNT_LIMIT {
            assert!(throttle.reserve("writer", time).is_ok());
        }
        assert!(matches!(
            throttle.reserve("writer", time),
            Err(PasswordLoginError::Throttled(60))
        ));
        for i in ACCOUNT_LIMIT..GLOBAL_LIMIT {
            assert!(throttle.reserve(&format!("user{i}"), time).is_ok());
        }
        for i in 0..1000 {
            assert!(matches!(
                throttle.reserve(&format!("spray{i}"), time),
                Err(PasswordLoginError::Throttled(60))
            ));
        }
        assert!(throttle.accounts.len() <= GLOBAL_LIMIT);
        assert!(throttle.reserve("writer", time + WINDOW).is_ok());
        assert_eq!(throttle.accounts.len(), 1);
    }
}
