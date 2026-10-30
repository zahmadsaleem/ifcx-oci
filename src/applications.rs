//! Operator-managed profile and web application registrations.
use anyhow::{ensure, Context, Result};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Intent {
    View,
    Edit,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub id: String,
    pub artifact_type: String,
    pub config_media_type: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Support {
    pub profile: String,
    pub intents: Vec<Intent>,
    #[serde(default)]
    pub publish: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Application {
    pub id: String,
    pub name: String,
    pub launch_url: String,
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub cors_origins: Vec<String>,
    pub supports: Vec<Support>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Applications {
    pub version: u32,
    pub profiles: Vec<Profile>,
    pub applications: Vec<Application>,
}

impl Default for Applications {
    fn default() -> Self {
        Self {
            version: 1,
            profiles: Vec::new(),
            applications: Vec::new(),
        }
    }
}

/// Exact web addresses are shared by launch and OAuth callback registrations.
pub(crate) fn web_url(value: &str) -> Result<Url> {
    let url = Url::parse(value)?;
    let host = url.host_str().unwrap_or("").trim_matches(['[', ']']);
    let loopback = host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    ensure!(
        !value.chars().any(|c| c.is_whitespace() || c.is_control())
            && !value.contains('\\')
            && (url.scheme() == "https" || (url.scheme() == "http" && loopback))
            && url.host_str().is_some() && !host.contains('*')
            && url.username().is_empty() && url.password().is_none()
            && url.query().is_none() && url.fragment().is_none(),
        "Application URLs must be exact HTTPS or loopback HTTP URLs without credentials, query or fragment"
    );
    Ok(url)
}

pub(crate) fn client_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
        && value != crate::oauth::EXPLORER_CLIENT
}

impl Applications {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= 256 * 1024,
            "Application configuration exceeds 256 KiB"
        );
        let config: Self =
            serde_json::from_slice(bytes).context("Invalid application configuration")?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1,
            "Unsupported application configuration version"
        );
        ensure!(
            self.profiles.len() <= 128 && self.applications.len() <= 128,
            "Too many registrations"
        );
        let mut ids = HashSet::new();
        let mut formats = HashSet::new();
        for profile in &self.profiles {
            ensure!(
                !profile.id.is_empty()
                    && profile.id.len() <= 512
                    && Url::parse(&profile.id).is_ok()
                    && ids.insert(&profile.id),
                "Profiles require unique absolute identifiers"
            );
            for media_type in [&profile.artifact_type, &profile.config_media_type] {
                ensure!(
                    media_type.len() <= 256
                        && media_type.contains('/')
                        && media_type.bytes().all(|b| b.is_ascii_graphic()),
                    "Invalid profile media type"
                );
            }
            ensure!(
                formats.insert((&profile.artifact_type, &profile.config_media_type)),
                "Profile artifact/config media type pairs must be unique"
            );
        }
        let mut applications = HashSet::new();
        for app in &self.applications {
            ensure!(
                client_id(&app.id) && applications.insert(&app.id),
                "Invalid or duplicate application ID"
            );
            ensure!(
                !app.name.trim().is_empty()
                    && app.name.len() <= 128
                    && !app.name.chars().any(char::is_control),
                "Invalid application name"
            );
            let launch = web_url(&app.launch_url)?;
            ensure!(
                !app.redirect_uris.is_empty() && app.redirect_uris.len() <= 16,
                "Applications need 1-16 callback URLs"
            );
            for redirect in &app.redirect_uris {
                ensure!(
                    web_url(redirect)?.origin() == launch.origin(),
                    "Application callbacks must share its launch origin"
                );
            }
            ensure!(
                app.cors_origins.len() <= 16,
                "Too many application CORS origins"
            );
            for origin in &app.cors_origins {
                let url = web_url(origin)?;
                ensure!(
                    url.path() == "/" && url.origin() == launch.origin(),
                    "Application CORS origins must be exact launch origins"
                );
            }
            ensure!(
                !app.supports.is_empty() && app.supports.len() <= 128,
                "Applications must declare supported profiles"
            );
            let mut supported = HashSet::new();
            for support in &app.supports {
                ensure!(
                    ids.contains(&support.profile) && supported.insert(&support.profile),
                    "Unknown or duplicate supported profile"
                );
                ensure!(
                    !support.intents.is_empty()
                        && support.intents.len() <= 2
                        && (support.intents.len() == 1 || support.intents[0] != support.intents[1]),
                    "Declare unique view/edit intents"
                );
                ensure!(
                    !support.publish || support.intents.contains(&Intent::Edit),
                    "Publishing requires edit support"
                );
            }
        }
        Ok(())
    }

    pub(crate) fn profile(&self, manifest: &serde_json::Value) -> Option<&Profile> {
        self.profiles.iter().find(|profile| {
            manifest["artifactType"].as_str() == Some(profile.artifact_type.as_str())
                && manifest["config"]["mediaType"].as_str()
                    == Some(profile.config_media_type.as_str())
        })
    }
}
