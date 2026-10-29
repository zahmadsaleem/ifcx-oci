//! The external origin is operator configuration, never request metadata.
use super::*;
use reqwest::Url;

impl Registry {
    /// Configure before serving. Paths/prefix mounts are intentionally unsupported.
    pub fn set_public_url(&self, value: &str) -> Result<()> {
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
                && url.host_str().is_some()
                && !host.contains('*')
                && url.username().is_empty()
                && url.password().is_none()
                && url.path() == "/"
                && url.query().is_none()
                && url.fragment().is_none(),
            "Public URL must be an HTTPS origin (or loopback HTTP) without credentials, path, query or fragment"
        );
        *self
            .public_url
            .write()
            .map_err(|_| anyhow::anyhow!("Public URL lock failed"))? = Some(url);
        Ok(())
    }

    pub fn public_origin(&self) -> String {
        self.public_url
            .read()
            .expect("public URL lock")
            .as_ref()
            .map(|url| url.origin().ascii_serialization())
            .unwrap_or_default()
    }

    pub(crate) fn secure_cookies(&self) -> bool {
        self.public_url
            .read()
            .expect("public URL lock")
            .as_ref()
            .is_some_and(|url| url.scheme() == "https")
    }

    pub(super) fn configure_listener(&self, address: SocketAddr) -> Result<()> {
        if self.public_origin().is_empty() {
            ensure!(
                address.ip().is_loopback(),
                "Non-loopback listeners require --public-url https://registry.example.com"
            );
            self.set_public_url(&format!("http://{address}"))?;
        }
        self.oauth.validate_transport(self.secure_cookies())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_public_origin_and_external_listener_configuration() -> Result<()> {
        let root = tempfile::tempdir()?;
        let registry = Registry::open(root.path())?;
        for value in [
            "http://registry.example.com",
            "https://user:pass@registry.example.com",
            "https://registry.example.com/prefix",
            "https://registry.example.com/?x=1",
            "https://registry.example.com/#fragment",
            "https://*.example.com",
            "https://registry.example.com\n",
            "https:\\registry.example.com",
            "file:///tmp/test",
        ] {
            assert!(registry.set_public_url(value).is_err(), "{value}");
        }
        assert!(registry
            .configure_listener("0.0.0.0:5000".parse()?)
            .is_err());
        registry.set_public_url("http://localhost:5000")?;
        registry.configure_listener("0.0.0.0:5000".parse()?)?;
        registry.set_public_url("https://REGISTRY.example.com:443/")?;
        registry.configure_listener("0.0.0.0:5000".parse()?)?;
        assert_eq!(registry.public_origin(), "https://registry.example.com");
        assert_eq!(
            registry.oauth_authorization_endpoint(),
            "https://registry.example.com/oauth/authorize"
        );
        registry
            .oauth
            .configure("app", &["http://localhost:3000/callback".into()])?;
        assert!(registry
            .configure_listener("0.0.0.0:5000".parse()?)
            .is_err());
        Ok(())
    }
}
