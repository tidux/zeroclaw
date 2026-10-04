use super::{SharedProcess, Tunnel, TunnelProcess, kill_shared, new_shared_process};
use anyhow::{Result, bail};
use tokio::process::Command;

/// Tailnet port the gateway is published on. Passed explicitly as `--https`
/// so the advertised URL is derived from the same value as the command line.
/// 443 is valid for both `serve` and `funnel` (funnel accepts only
/// 443/8443/10000) and lets the URL omit the port.
const GATEWAY_HTTPS_PORT: u16 = 443;

/// `tailscale serve|funnel --https=443 <local_port>`: an HTTPS proxy on the
/// tailnet port [`GATEWAY_HTTPS_PORT`] to `127.0.0.1:<local_port>`.
fn gateway_serve_args(funnel: bool, local_port: u16) -> [String; 3] {
    let subcommand = if funnel { "funnel" } else { "serve" };
    [
        subcommand.to_string(),
        format!("--https={GATEWAY_HTTPS_PORT}"),
        local_port.to_string(),
    ]
}

/// The URL Tailscale serves the gateway at. The local port is never part of
/// it: Tailscale listens on [`GATEWAY_HTTPS_PORT`] (443, the HTTPS default),
/// not on the gateway's own port.
fn gateway_public_url(hostname: &str) -> String {
    format!("https://{hostname}")
}

/// Tailscale Tunnel — uses `tailscale serve` (tailnet-only) or
/// `tailscale funnel` (public internet).
/// Requires Tailscale installed and authenticated (`tailscale up`).
pub struct TailscaleTunnel {
    funnel: bool,
    hostname: Option<String>,
    proc: SharedProcess,
}

impl TailscaleTunnel {
    pub fn new(funnel: bool, hostname: Option<String>) -> Self {
        Self {
            funnel,
            hostname,
            proc: new_shared_process(),
        }
    }
}

#[async_trait::async_trait]
impl Tunnel for TailscaleTunnel {
    fn name(&self) -> &str {
        "tailscale"
    }

    async fn start(&self, _local_host: &str, local_port: u16) -> Result<String> {
        // Get the tailscale hostname for URL construction
        let hostname = if let Some(ref h) = self.hostname {
            h.clone()
        } else {
            // Query tailscale for the current hostname
            let output = Command::new("tailscale")
                .args(["status", "--json"])
                .output()
                .await?;

            if !output.status.success() {
                bail!(
                    "tailscale status failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }

            let status: serde_json::Value =
                serde_json::from_slice(&output.stdout).unwrap_or_default();
            status["Self"]["DNSName"]
                .as_str()
                .unwrap_or("localhost")
                .trim_end_matches('.')
                .to_string()
        };

        let child = Command::new("tailscale")
            .args(gateway_serve_args(self.funnel, local_port))
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

        let public_url = gateway_public_url(&hostname);

        let mut guard = self.proc.lock().await;
        *guard = Some(TunnelProcess {
            child,
            public_url: public_url.clone(),
        });

        Ok(public_url)
    }

    async fn stop(&self) -> Result<()> {
        // Also reset the tailscale serve/funnel
        let subcommand = if self.funnel { "funnel" } else { "serve" };
        Command::new("tailscale")
            .args([subcommand, "reset"])
            .output()
            .await
            .ok();

        kill_shared(&self.proc).await
    }

    async fn health_check(&self) -> bool {
        let guard = self.proc.lock().await;
        guard.as_ref().is_some_and(|tp| tp.child.id().is_some())
    }

    fn public_url(&self) -> Option<String> {
        self.proc
            .try_lock()
            .ok()
            .and_then(|g| g.as_ref().map(|tp| tp.public_url.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructor_stores_hostname_and_mode() {
        let tunnel = TailscaleTunnel::new(true, Some("myhost.tailnet.ts.net".into()));
        assert!(tunnel.funnel);
        assert_eq!(tunnel.hostname.as_deref(), Some("myhost.tailnet.ts.net"));
    }

    #[test]
    fn public_url_is_none_before_start() {
        let tunnel = TailscaleTunnel::new(false, None);
        assert!(tunnel.public_url().is_none());
    }

    #[tokio::test]
    async fn health_check_is_false_before_start() {
        let tunnel = TailscaleTunnel::new(false, None);
        assert!(!tunnel.health_check().await);
    }

    #[test]
    fn gateway_serve_args_pin_the_https_port() {
        assert_eq!(
            gateway_serve_args(false, 42617),
            ["serve", "--https=443", "42617"]
        );
        assert_eq!(
            gateway_serve_args(true, 42617),
            ["funnel", "--https=443", "42617"]
        );
    }

    #[test]
    fn gateway_public_url_omits_the_local_port() {
        // Regression: the URL used to be https://<host>:<local_port>, but
        // Tailscale serves the gateway on 443, not on the gateway's own port.
        assert_eq!(
            gateway_public_url("node.tailnet.ts.net"),
            "https://node.tailnet.ts.net"
        );
    }

    #[tokio::test]
    async fn stop_without_started_process_is_ok() {
        let tunnel = TailscaleTunnel::new(false, None);
        let result = tunnel.stop().await;
        assert!(result.is_ok());
    }
}
