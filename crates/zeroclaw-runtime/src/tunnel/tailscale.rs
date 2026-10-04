use super::{
    PublishedTcpService, SharedProcess, TcpService, Tunnel, TunnelProcess, kill_shared,
    new_shared_process,
};
use anyhow::{Result, bail};
use std::sync::Arc;
use std::time::Duration;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

/// How long a freshly spawned `tailscale serve --tcp` gets to reject its
/// configuration (port already served, not an operator, ...) before it is
/// treated as running. Foreground serve exits promptly on such errors.
const TCP_SERVE_SETTLE: Duration = Duration::from_millis(750);

/// Tailscale Tunnel — uses `tailscale serve` (tailnet-only) or
/// `tailscale funnel` (public internet).
/// Requires Tailscale installed and authenticated (`tailscale up`).
pub struct TailscaleTunnel {
    funnel: bool,
    hostname: Option<String>,
    proc: SharedProcess,
    /// Foreground `tailscale serve --tcp` forwarders for the daemon's
    /// self-TLS listeners. Foreground serve config lives exactly as long as
    /// the process, so killing these withdraws the forwards.
    tcp_procs: Arc<Mutex<Vec<Child>>>,
}

impl TailscaleTunnel {
    pub fn new(funnel: bool, hostname: Option<String>) -> Self {
        Self {
            funnel,
            hostname,
            proc: new_shared_process(),
            tcp_procs: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// The configured hostname override, else this node's MagicDNS name.
    async fn resolve_hostname(&self) -> Result<String> {
        if let Some(ref h) = self.hostname {
            return Ok(h.clone());
        }
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

        let status: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_default();
        Ok(status["Self"]["DNSName"]
            .as_str()
            .unwrap_or("localhost")
            .trim_end_matches('.')
            .to_string())
    }
}

/// Arguments for a raw TCP passthrough of `service` on the same tailnet port.
///
/// Always `serve` (tailnet-only), never `funnel`: Funnel only listens on
/// 443/8443/10000, so these ports cannot be published publicly as-is, and
/// widening a mutually authenticated plane to the internet must be an
/// explicit operator decision rather than a side effect of gateway funnel.
fn tcp_serve_args(service: &TcpService) -> Vec<String> {
    vec![
        "serve".into(),
        "--tcp".into(),
        service.target.port().to_string(),
        format!("tcp://{}", service.target),
    ]
}

fn tcp_endpoint(hostname: &str, service: &TcpService) -> String {
    format!("{}://{hostname}:{}", service.scheme, service.target.port())
}

#[async_trait::async_trait]
impl Tunnel for TailscaleTunnel {
    fn name(&self) -> &str {
        "tailscale"
    }

    async fn start(&self, _local_host: &str, local_port: u16) -> Result<String> {
        let subcommand = if self.funnel { "funnel" } else { "serve" };

        // Get the tailscale hostname for URL construction
        let hostname = self.resolve_hostname().await?;

        // tailscale serve|funnel <port>
        let child = Command::new("tailscale")
            .args([subcommand, &local_port.to_string()])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

        let public_url = format!("https://{hostname}:{local_port}");

        let mut guard = self.proc.lock().await;
        *guard = Some(TunnelProcess {
            child,
            public_url: public_url.clone(),
        });

        Ok(public_url)
    }

    async fn publish_tcp_services(
        &self,
        services: &[TcpService],
    ) -> Result<Vec<PublishedTcpService>> {
        if services.is_empty() {
            return Ok(Vec::new());
        }
        if self.funnel {
            ::zeroclaw_log::record!(
                WARN,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                    .with_attrs(::serde_json::json!({
                        "services": services.iter().map(|s| s.name).collect::<Vec<_>>(),
                    })),
                "tailscale funnel publishes the gateway publicly; WSS and enrollment are \
                 published tailnet-only via `tailscale serve --tcp`"
            );
        }
        let hostname = self.resolve_hostname().await?;

        let mut spawned = Vec::with_capacity(services.len());
        for service in services {
            let child = Command::new("tailscale")
                .args(tcp_serve_args(service))
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .spawn()?;
            spawned.push((service, child));
        }

        tokio::time::sleep(TCP_SERVE_SETTLE).await;

        let mut published = Vec::with_capacity(spawned.len());
        let mut procs = self.tcp_procs.lock().await;
        for (service, mut child) in spawned {
            match child.try_wait() {
                Ok(None) => {
                    published.push(PublishedTcpService {
                        service: *service,
                        endpoint: tcp_endpoint(&hostname, service),
                    });
                    procs.push(child);
                }
                Ok(Some(status)) => {
                    let stderr = match child.wait_with_output().await {
                        Ok(out) => String::from_utf8_lossy(&out.stderr).trim().to_string(),
                        Err(e) => e.to_string(),
                    };
                    ::zeroclaw_log::record!(
                        WARN,
                        ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Fail)
                            .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                            .with_attrs(::serde_json::json!({
                                "service": service.name,
                                "target": service.target.to_string(),
                                "status": status.to_string(),
                                "stderr": stderr,
                            })),
                        "tailscale serve --tcp exited; service not published on the tailnet"
                    );
                }
                Err(e) => {
                    ::zeroclaw_log::record!(
                        WARN,
                        ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Fail)
                            .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                            .with_attrs(::serde_json::json!({
                                "service": service.name,
                                "error": e.to_string(),
                            })),
                        "tailscale serve --tcp status unknown; withdrawing it"
                    );
                    child.kill().await.ok();
                }
            }
        }
        Ok(published)
    }

    async fn stop(&self) -> Result<()> {
        {
            let mut procs = self.tcp_procs.lock().await;
            for mut child in procs.drain(..) {
                child.kill().await.ok();
                child.wait().await.ok();
            }
        }

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

    fn service(name: &'static str, scheme: &'static str, target: &str) -> TcpService {
        TcpService {
            name,
            scheme,
            target: target.parse().unwrap(),
        }
    }

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

    #[tokio::test]
    async fn stop_without_started_process_is_ok() {
        let tunnel = TailscaleTunnel::new(false, None);
        let result = tunnel.stop().await;
        assert!(result.is_ok());
    }

    #[test]
    fn tcp_serve_args_are_raw_passthrough_on_the_same_port() {
        let wss = service("wss", "wss", "127.0.0.1:9781");
        assert_eq!(
            tcp_serve_args(&wss),
            vec!["serve", "--tcp", "9781", "tcp://127.0.0.1:9781"]
        );
    }

    #[test]
    fn tcp_serve_args_bracket_ipv6_targets() {
        let enroll = service("enroll", "https", "[::1]:9782");
        assert_eq!(
            tcp_serve_args(&enroll),
            vec!["serve", "--tcp", "9782", "tcp://[::1]:9782"]
        );
    }

    #[test]
    fn tcp_endpoint_uses_service_scheme_and_port() {
        let wss = service("wss", "wss", "127.0.0.1:9781");
        let enroll = service("enroll", "https", "127.0.0.1:9782");
        assert_eq!(
            tcp_endpoint("node.tailnet.ts.net", &wss),
            "wss://node.tailnet.ts.net:9781"
        );
        assert_eq!(
            tcp_endpoint("node.tailnet.ts.net", &enroll),
            "https://node.tailnet.ts.net:9782"
        );
    }

    #[tokio::test]
    async fn publish_no_services_spawns_nothing() {
        // No hostname override: any `tailscale` invocation would be attempted,
        // so an empty result proves the early return.
        let tunnel = TailscaleTunnel::new(false, None);
        let published = tunnel.publish_tcp_services(&[]).await.unwrap();
        assert!(published.is_empty());
        assert!(tunnel.tcp_procs.lock().await.is_empty());
    }
}
