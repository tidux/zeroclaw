use super::{
    PublishedTcpService, SharedProcess, TcpService, Tunnel, TunnelProcess, kill_shared,
    new_shared_process,
};
use anyhow::{Context, Result, bail};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use zeroclaw_config::schema::{EnrollConfig, TunnelConfig, WssConfig};

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
        Ok(query_tailscale_self()
            .await?
            .dns_name
            .unwrap_or_else(|| "localhost".to_string()))
    }
}

// ── Tailnet identity ─────────────────────────────────────────────

/// Upper bound on `tailscale status`, so a wedged tailscaled cannot stall a
/// listener's startup.
const STATUS_TIMEOUT: Duration = Duration::from_secs(5);

/// This node's tailnet identity, as reported by `tailscale status --json`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TailscaleSelf {
    /// MagicDNS FQDN without the trailing dot (`node.tailnet.ts.net`).
    pub dns_name: Option<String>,
    /// The node's tailnet addresses.
    pub ips: Vec<IpAddr>,
}

/// Ask the local tailscaled who this node is.
pub async fn query_tailscale_self() -> Result<TailscaleSelf> {
    let output = tokio::time::timeout(
        STATUS_TIMEOUT,
        Command::new("tailscale")
            .args(["status", "--json"])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("tailscale status timed out")??;

    if !output.status.success() {
        bail!(
            "tailscale status failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(parse_tailscale_self(&output.stdout))
}

/// Extract the node identity from `tailscale status --json`. Missing or
/// malformed fields yield an empty identity rather than an error.
fn parse_tailscale_self(json: &[u8]) -> TailscaleSelf {
    let status: serde_json::Value = serde_json::from_slice(json).unwrap_or_default();
    let node = &status["Self"];
    let dns_name = node["DNSName"]
        .as_str()
        .map(|n| n.trim().trim_end_matches('.').to_string())
        .filter(|n| !n.is_empty());
    let ips = node["TailscaleIPs"]
        .as_array()
        .map(|ips| {
            ips.iter()
                .filter_map(|ip| ip.as_str()?.parse().ok())
                .collect()
        })
        .unwrap_or_default();
    TailscaleSelf { dns_name, ips }
}

/// Whether `ip` is in Tailscale's address space: the CGNAT range
/// `100.64.0.0/10` or the tailnet ULA prefix `fd7a:115c:a1e0::/48`.
pub fn is_tailscale_ip(ip: IpAddr) -> bool {
    const TS_V4_NET: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 0);
    const TS_V6_NET: Ipv6Addr = Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0);
    match ip {
        IpAddr::V4(v4) => u32::from(v4) & 0xffc0_0000 == u32::from(TS_V4_NET),
        IpAddr::V6(v6) => v6.segments()[..3] == TS_V6_NET.segments()[..3],
    }
}

/// Whether the daemon's self-TLS listeners are reached over the tailnet: the
/// Tailscale tunnel publishes them, or one is bound directly to a tailnet
/// address. Only then does the server certificate need tailnet names.
fn tailnet_reaches_listeners(
    tunnel: &TunnelConfig,
    wss: &WssConfig,
    enroll: &EnrollConfig,
) -> bool {
    if !wss.enabled {
        return false;
    }
    let bound_to_tailnet = |bind: &str| bind.trim().parse::<IpAddr>().is_ok_and(is_tailscale_ip);
    tunnel.tunnel_provider == "tailscale"
        || bound_to_tailnet(&wss.bind)
        || (enroll.enabled && bound_to_tailnet(&enroll.bind))
}

/// The names a tailnet client uses to reach this node: the configured
/// hostname override, the MagicDNS FQDN and its short name, and the node's
/// tailnet IPs. Deduplicated, case-insensitively, in that order.
fn tailnet_names(hostname_override: Option<&str>, node: &TailscaleSelf) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let mut push = |name: &str| {
        let name = name.trim().trim_end_matches('.');
        if !name.is_empty() && !names.iter().any(|n| n.eq_ignore_ascii_case(name)) {
            names.push(name.to_string());
        }
    };
    if let Some(h) = hostname_override {
        push(h);
    }
    if let Some(fqdn) = node.dns_name.as_deref() {
        push(fqdn);
        if let Some((short, _)) = fqdn.split_once('.') {
            push(short);
        }
    }
    for ip in &node.ips {
        push(&ip.to_string());
    }
    names
}

/// Extra server-certificate SANs for the daemon's self-TLS listeners (WSS,
/// enrollment) when they are reached over the tailnet; empty otherwise.
///
/// Resolved from tailscaled at listener startup rather than stored in config,
/// so a renamed node or changed tailnet is picked up on the next start (the
/// leaf is regenerated; the CA is untouched). When tailscaled cannot be
/// queried this logs and returns only the configured hostname override, if
/// any: the listener still starts with the operator's `[wss].sans`.
pub async fn tailscale_server_sans(
    tunnel: &TunnelConfig,
    wss: &WssConfig,
    enroll: &EnrollConfig,
) -> Vec<String> {
    if !tailnet_reaches_listeners(tunnel, wss, enroll) {
        return Vec::new();
    }
    let hostname_override = tunnel
        .tailscale
        .as_ref()
        .and_then(|ts| ts.hostname.as_deref());
    let node = match query_tailscale_self().await {
        Ok(node) => node,
        Err(e) => {
            ::zeroclaw_log::record!(
                WARN,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Fail)
                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                    .with_attrs(::serde_json::json!({"error": e.to_string()})),
                "could not read this node's tailnet identity; the WSS server certificate \
                 will not carry its MagicDNS name or tailnet IPs until the next start"
            );
            TailscaleSelf::default()
        }
    };
    tailnet_names(hostname_override, &node)
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

    const STATUS_JSON: &str = r#"{
        "BackendState": "Running",
        "Self": {
            "HostName": "zcnode",
            "DNSName": "zcnode.tail1234.ts.net.",
            "TailscaleIPs": ["100.101.102.103", "fd7a:115c:a1e0::1234", "not-an-ip"]
        }
    }"#;

    fn tailscale_tunnel_cfg(hostname: Option<&str>) -> TunnelConfig {
        TunnelConfig {
            tunnel_provider: "tailscale".into(),
            tailscale: Some(zeroclaw_config::schema::TailscaleTunnelConfig {
                funnel: false,
                hostname: hostname.map(Into::into),
            }),
            ..TunnelConfig::default()
        }
    }

    fn wss_enabled(bind: &str) -> WssConfig {
        WssConfig {
            enabled: true,
            bind: bind.into(),
            ..WssConfig::default()
        }
    }

    #[test]
    fn parse_tailscale_self_reads_dns_name_and_ips() {
        let node = parse_tailscale_self(STATUS_JSON.as_bytes());
        assert_eq!(node.dns_name.as_deref(), Some("zcnode.tail1234.ts.net"));
        assert_eq!(
            node.ips,
            vec![
                "100.101.102.103".parse::<IpAddr>().unwrap(),
                "fd7a:115c:a1e0::1234".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn parse_tailscale_self_tolerates_garbage() {
        assert_eq!(parse_tailscale_self(b"not json"), TailscaleSelf::default());
        assert_eq!(
            parse_tailscale_self(br#"{"Self":{"DNSName":""}}"#),
            TailscaleSelf::default()
        );
    }

    #[test]
    fn is_tailscale_ip_matches_cgnat_and_tailnet_ula_only() {
        for ip in [
            "100.64.0.0",
            "100.101.102.103",
            "100.127.255.255",
            "fd7a:115c:a1e0::1",
        ] {
            assert!(is_tailscale_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "100.63.255.255",
            "100.128.0.0",
            "127.0.0.1",
            "0.0.0.0",
            "192.168.1.1",
            "fd7a:115c:a1e1::1",
            "::1",
        ] {
            assert!(!is_tailscale_ip(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn tailnet_reach_requires_wss() {
        let enroll = EnrollConfig::default();
        assert!(!tailnet_reaches_listeners(
            &tailscale_tunnel_cfg(None),
            &WssConfig::default(),
            &enroll
        ));
    }

    #[test]
    fn tailnet_reach_via_tailscale_tunnel() {
        assert!(tailnet_reaches_listeners(
            &tailscale_tunnel_cfg(None),
            &wss_enabled("0.0.0.0"),
            &EnrollConfig::default()
        ));
    }

    #[test]
    fn tailnet_reach_via_direct_tailnet_bind_without_tunnel() {
        let no_tunnel = TunnelConfig::default();
        assert!(tailnet_reaches_listeners(
            &no_tunnel,
            &wss_enabled("100.101.102.103"),
            &EnrollConfig::default()
        ));
        let enroll = EnrollConfig {
            enabled: true,
            bind: "fd7a:115c:a1e0::1234".into(),
            ..EnrollConfig::default()
        };
        assert!(tailnet_reaches_listeners(
            &no_tunnel,
            &wss_enabled("127.0.0.1"),
            &enroll
        ));
    }

    #[test]
    fn tailnet_reach_false_for_lan_only_daemon() {
        // A disabled enroll bound to a tailnet IP does not count: nothing listens.
        let enroll = EnrollConfig {
            enabled: false,
            bind: "100.101.102.103".into(),
            ..EnrollConfig::default()
        };
        assert!(!tailnet_reaches_listeners(
            &TunnelConfig::default(),
            &wss_enabled("0.0.0.0"),
            &enroll
        ));
    }

    #[test]
    fn tailnet_names_lists_override_fqdn_short_name_and_ips() {
        let node = parse_tailscale_self(STATUS_JSON.as_bytes());
        assert_eq!(
            tailnet_names(Some("zero.example.ts.net."), &node),
            vec![
                "zero.example.ts.net",
                "zcnode.tail1234.ts.net",
                "zcnode",
                "100.101.102.103",
                "fd7a:115c:a1e0::1234",
            ]
        );
    }

    #[test]
    fn tailnet_names_dedupes_override_matching_magicdns() {
        let node = parse_tailscale_self(STATUS_JSON.as_bytes());
        let names = tailnet_names(Some("ZCNODE.tail1234.ts.net"), &node);
        assert_eq!(names[0], "ZCNODE.tail1234.ts.net");
        assert_eq!(names[1], "zcnode");
        assert_eq!(names.len(), 4);
    }

    #[test]
    fn tailnet_names_empty_without_identity() {
        assert!(tailnet_names(None, &TailscaleSelf::default()).is_empty());
    }

    #[tokio::test]
    async fn tailscale_server_sans_skips_query_when_tailnet_unused() {
        // No tunnel, LAN bind: returns before ever invoking `tailscale`.
        let sans = tailscale_server_sans(
            &TunnelConfig::default(),
            &wss_enabled("0.0.0.0"),
            &EnrollConfig::default(),
        )
        .await;
        assert!(sans.is_empty());
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
