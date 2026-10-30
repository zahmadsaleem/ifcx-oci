//! Shared failed-login budget and total password-work limit, keyed by account.
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

struct LoginAttempt {
    account: [u8; 32],
    window_start: Instant,
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
    fn reserve(
        &mut self,
        username: &str,
        time: Instant,
    ) -> Result<LoginAttempt, PasswordLoginError> {
        if time.duration_since(self.global.start) >= WINDOW {
            self.global = Budget::new(time);
        }
        self.accounts
            .retain(|_, b| time.duration_since(b.start) < WINDOW);
        if self.global.attempts >= GLOBAL_LIMIT {
            return Err(PasswordLoginError::Throttled(self.global.retry_after(time)));
        }
        let account = Sha256::digest(username.as_bytes()).into();
        let budget = self
            .accounts
            .entry(account)
            .or_insert_with(|| Budget::new(time));
        if budget.attempts >= ACCOUNT_LIMIT {
            return Err(PasswordLoginError::Throttled(budget.retry_after(time)));
        }
        // Reserve before Argon2 so concurrent failures cannot bypass the limit.
        // Success returns the account slot; all attempts consume the global
        // password-work budget, including nonexistent accounts.
        budget.attempts += 1;
        self.global.attempts += 1;
        Ok(LoginAttempt {
            account,
            window_start: budget.start,
        })
    }

    fn complete(&mut self, attempt: LoginAttempt, success: bool) {
        if success {
            if let Some(budget) = self.accounts.get_mut(&attempt.account) {
                // A slow verification must not refund an attempt in a new window.
                if budget.start == attempt.window_start {
                    budget.attempts -= 1;
                }
            }
        }
    }
}

impl Auth {
    fn password_login(&self, username: &str, password: &str) -> Result<(), PasswordLoginError> {
        let attempt = self
            .login_throttle
            .lock()
            .map_err(|_| PasswordLoginError::Unavailable)?
            .reserve(username, Instant::now())?;
        let authenticated = self.authenticate(username, password);
        self.login_throttle
            .lock()
            .map_err(|_| PasswordLoginError::Unavailable)?
            .complete(attempt, authenticated.is_ok());
        authenticated.map_err(|_| PasswordLoginError::InvalidCredentials)
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

    #[test]
    fn successes_return_account_slots_but_keep_global_work_and_prior_failures() {
        let mut throttle = LoginThrottle::default();
        let time = Instant::now();
        for _ in 0..ACCOUNT_LIMIT - 1 {
            let attempt = throttle
                .reserve("writer", time)
                .unwrap_or_else(|_| panic!("reserved"));
            throttle.complete(attempt, false);
        }
        for _ in ACCOUNT_LIMIT - 1..GLOBAL_LIMIT {
            let attempt = throttle
                .reserve("writer", time)
                .unwrap_or_else(|_| panic!("success has a slot"));
            throttle.complete(attempt, true);
        }
        assert!(matches!(
            throttle.reserve("writer", time),
            Err(PasswordLoginError::Throttled(60))
        ));
        assert!(matches!(
            throttle.reserve("another", time),
            Err(PasswordLoginError::Throttled(60))
        ));
        assert_eq!(
            throttle.accounts.values().next().unwrap().attempts,
            ACCOUNT_LIMIT - 1
        );
    }

    #[test]
    fn pending_attempts_are_bounded_and_old_completions_do_not_refund_new_failures() {
        let mut throttle = LoginThrottle::default();
        let time = Instant::now();
        let attempts: Vec<_> = (0..ACCOUNT_LIMIT)
            .map(|_| {
                throttle
                    .reserve("writer", time)
                    .unwrap_or_else(|_| panic!("reserved"))
            })
            .collect();
        assert!(matches!(
            throttle.reserve("writer", time),
            Err(PasswordLoginError::Throttled(60))
        ));
        for _ in 0..ACCOUNT_LIMIT {
            let attempt = throttle
                .reserve("writer", time + WINDOW)
                .unwrap_or_else(|_| panic!("new window"));
            throttle.complete(attempt, false);
        }
        for attempt in attempts {
            throttle.complete(attempt, true);
        }
        assert!(matches!(
            throttle.reserve("writer", time + WINDOW),
            Err(PasswordLoginError::Throttled(60))
        ));
        assert!(throttle.reserve("other", time + WINDOW).is_ok());
    }

    #[test]
    fn valid_passwords_do_not_exhaust_account_budget_and_unknown_users_are_throttled(
    ) -> anyhow::Result<()> {
        let root = tempfile::tempdir()?;
        let auth = Auth::open(root.path())?;
        auth.add_user("writer", "test-only-long-password", &[])?;
        for _ in 0..ACCOUNT_LIMIT + 2 {
            assert!(auth
                .password_login("writer", "test-only-long-password")
                .is_ok());
        }
        for username in ["writer", "unknown"] {
            for _ in 0..ACCOUNT_LIMIT {
                assert!(matches!(
                    auth.password_login(username, "wrong-password"),
                    Err(PasswordLoginError::InvalidCredentials)
                ));
            }
            assert!(matches!(
                auth.password_login(username, "test-only-long-password"),
                Err(PasswordLoginError::Throttled(_))
            ));
        }
        Ok(())
    }
}
