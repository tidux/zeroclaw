use super::Tunnel;
use anyhow::{Result, bail};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;

/// How long `start` waits to see whether the CLI exited instead of staying
/// in the foreground. Instant failures (permission, etag, overwrite) show
/// up in this window; a process that is still running afterward is assumed
/// to be serving.
const IMMEDIATE_EXIT_WINDOW: Duration = Duration::from_millis(150);

/// Cap on serve stderr kept for an unexpected-exit or start-failure report.
const SERVE_STDERR_CAP: u64 = 8 * 1024;

/// Give up after this many unexpected exits / failed respawns in a row.
const MAX_CONSECUTIVE_FAILURES: u32 = 5;

/// Delay after the first unexpected exit; doubles after each consecutive
/// failure until [`MAX_CONSECUTIVE_FAILURES`].
const RESTART_BACKOFF_INITIAL: Duration = Duration::from_millis(250);

/// A serve that stays in the foreground this long is treated as healthy, so
/// a later crash starts the consecutive-failure count over.
const STABLE_AFTER: Duration = Duration::from_secs(5);

/// Delay before the next restart attempt, or `None` to stop trying.
/// `consecutive_failures` is the number of failures already observed,
/// including the one that just happened.
fn restart_backoff(
    consecutive_failures: u32,
    initial: Duration,
    max_consecutive_failures: u32,
) -> Option<Duration> {
    if consecutive_failures == 0 || consecutive_failures >= max_consecutive_failures {
        return None;
    }
    let shift = consecutive_failures.saturating_sub(1).min(31);
    Some(initial.saturating_mul(1u32 << shift))
}

/// Tailscale Tunnel — uses `tailscale serve` (tailnet-only) or
/// `tailscale funnel` (public internet).
/// Requires Tailscale installed and authenticated (`tailscale up`).
///
/// Foreground `tailscale serve` *is* the serve: when the CLI exits,
/// tailscaled withdraws the config. `--bg` would leave the publish up
/// after this process dies, so the tunnel is supervised as a child
/// instead of fire-and-forget.
pub struct TailscaleTunnel {
    funnel: bool,
    hostname: Option<String>,
    /// Binary invoked for `serve`/`funnel`/`status`/`reset`. Overridable in
    /// tests so process-lifecycle coverage does not need a real tailscaled.
    program: PathBuf,
    serve: Mutex<Option<ServeProcess>>,
}

/// Arguments needed to respawn a foreground serve after an unexpected exit.
struct ServeSpec {
    program: PathBuf,
    subcommand: String,
    local_port: u16,
}

/// A published foreground serve, owned by its watcher task.
struct ServeProcess {
    public_url: String,
    /// True while a confirmed foreground child is alive. False during
    /// backoff and after the supervisor gives up. Distinct from the
    /// watcher task, which stays alive across restarts.
    serving: Arc<AtomicBool>,
    /// Sending `true`, or dropping it, ends the serve (see `supervise_serve`).
    stop: Option<watch::Sender<bool>>,
    task: Option<JoinHandle<()>>,
}

impl ServeProcess {
    fn spawn(public_url: String, child: Child, spec: ServeSpec) -> Self {
        let serving = Arc::new(AtomicBool::new(true));
        let (stop, stop_rx) = watch::channel(false);
        let serving_task = Arc::clone(&serving);
        let task = zeroclaw_spawn::spawn!(supervise_serve(child, stop_rx, serving_task, spec));
        Self {
            public_url,
            serving,
            stop: Some(stop),
            task: Some(task),
        }
    }

    fn is_serving(&self) -> bool {
        self.serving.load(Ordering::SeqCst)
    }

    async fn shutdown(mut self) {
        self.request_stop();
        if let Some(task) = self.task.take() {
            task.await.ok();
        }
    }

    fn request_stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            stop.send(true).ok();
        }
    }
}

impl Drop for ServeProcess {
    fn drop(&mut self) {
        self.request_stop();
        if let Some(task) = self.task.take() {
            if task.is_finished() {
                return;
            }
            // JoinHandle::drop aborts. Detach so the watcher can kill+wait
            // even when the gateway drops the tunnel without an explicit stop().
            std::mem::forget(task);
        }
    }
}

impl TailscaleTunnel {
    pub fn new(funnel: bool, hostname: Option<String>) -> Self {
        Self {
            funnel,
            hostname,
            program: PathBuf::from("tailscale"),
            serve: Mutex::new(None),
        }
    }

    #[cfg(all(test, unix))]
    fn with_program(mut self, program: PathBuf) -> Self {
        self.program = program;
        self
    }
}

/// Own one foreground serve until it exits or is told to stop. An unexpected
/// exit is retried with exponential backoff, up to [`MAX_CONSECUTIVE_FAILURES`]
/// in a row. A stop request (or dropping the tunnel, which drops the sender)
/// kills the child and waits so it cannot stay `<defunct>`.
async fn supervise_serve(
    mut child: Child,
    mut stop: watch::Receiver<bool>,
    serving: Arc<AtomicBool>,
    spec: ServeSpec,
) {
    let mut consecutive_failures = 0u32;
    loop {
        match run_until_exit_or_stop(&mut child, &mut stop).await {
            ServeOutcome::Stopped => {
                serving.store(false, Ordering::SeqCst);
                child.kill().await.ok();
                child.wait().await.ok();
                return;
            }
            ServeOutcome::Exited {
                status,
                stderr,
                ran_for,
            } => {
                serving.store(false, Ordering::SeqCst);
                if ran_for >= STABLE_AFTER {
                    consecutive_failures = 0;
                }
                if !record_failure_and_wait(
                    &mut consecutive_failures,
                    &mut stop,
                    serde_json::json!({
                        "status": status,
                        "stderr": stderr,
                    }),
                    "tailscale serve exited after publication; retrying with backoff",
                    "tailscale serve exited after publication; giving up after consecutive failures",
                )
                .await
                {
                    return;
                }
            }
        }

        loop {
            match spawn_confirmed_serve(&spec.program, &spec.subcommand, spec.local_port).await {
                Ok(next) => {
                    child = next;
                    serving.store(true, Ordering::SeqCst);
                    break;
                }
                Err(e) => {
                    if !record_failure_and_wait(
                        &mut consecutive_failures,
                        &mut stop,
                        serde_json::json!({"error": e.to_string()}),
                        "tailscale serve respawn failed; retrying with backoff",
                        "tailscale serve respawn failed; giving up after consecutive failures",
                    )
                    .await
                    {
                        serving.store(false, Ordering::SeqCst);
                        return;
                    }
                }
            }
        }
    }
}

/// Count one consecutive failure and wait its backoff, unless stop is
/// requested or the budget is exhausted. Returns `true` to retry.
async fn record_failure_and_wait(
    consecutive_failures: &mut u32,
    stop: &mut watch::Receiver<bool>,
    extra: serde_json::Value,
    retry_msg: &'static str,
    give_up_msg: &'static str,
) -> bool {
    *consecutive_failures = consecutive_failures.saturating_add(1);
    let delay = restart_backoff(
        *consecutive_failures,
        RESTART_BACKOFF_INITIAL,
        MAX_CONSECUTIVE_FAILURES,
    );
    let mut attrs = extra;
    if let Some(obj) = attrs.as_object_mut() {
        obj.insert(
            "consecutive_failures".into(),
            serde_json::json!(*consecutive_failures),
        );
        obj.insert(
            "retry_ms".into(),
            serde_json::json!(delay.map(|d| d.as_millis())),
        );
    }
    ::zeroclaw_log::record!(
        WARN,
        ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Fail)
            .with_outcome(::zeroclaw_log::EventOutcome::Failure)
            .with_attrs(attrs),
        if delay.is_some() {
            retry_msg
        } else {
            give_up_msg
        }
    );
    let Some(delay) = delay else {
        return false;
    };
    tokio::select! {
        _ = tokio::time::sleep(delay) => true,
        _ = wait_stop(stop) => false,
    }
}

enum ServeOutcome {
    Stopped,
    Exited {
        status: String,
        stderr: String,
        ran_for: Duration,
    },
}

async fn wait_stop(stop: &mut watch::Receiver<bool>) {
    let _ = stop.wait_for(|stop| *stop).await;
}

async fn run_until_exit_or_stop(
    child: &mut Child,
    stop: &mut watch::Receiver<bool>,
) -> ServeOutcome {
    let started = tokio::time::Instant::now();
    let stderr = child.stderr.take();
    let stdout = child.stdout.take();
    if let Some(stdout) = stdout {
        zeroclaw_spawn::spawn!(drain_pipe(stdout));
    }
    tokio::select! {
        status = child.wait() => {
            let mut captured = String::new();
            if let Some(stderr) = stderr {
                stderr
                    .take(SERVE_STDERR_CAP)
                    .read_to_string(&mut captured)
                    .await
                    .ok();
            }
            ServeOutcome::Exited {
                status: match status {
                    Ok(status) => status.to_string(),
                    Err(e) => e.to_string(),
                },
                stderr: captured.trim().to_string(),
                ran_for: started.elapsed(),
            }
        }
        _ = wait_stop(stop) => ServeOutcome::Stopped,
    }
}

async fn spawn_confirmed_serve(program: &Path, subcommand: &str, local_port: u16) -> Result<Child> {
    let mut child = Command::new(program)
        .args([subcommand, &local_port.to_string()])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    if let Err(e) = confirm_foreground_serve(&mut child, IMMEDIATE_EXIT_WINDOW).await {
        child.kill().await.ok();
        child.wait().await.ok();
        return Err(e);
    }
    Ok(child)
}

async fn drain_pipe<R: tokio::io::AsyncRead + Unpin>(mut pipe: R) {
    let mut buf = [0u8; 1024];
    loop {
        match pipe.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

/// Fail if the CLI has already left the foreground. A pid that is merely
/// still assigned is not proof it is serving: an exited child stays
/// `<defunct>` until waited.
async fn confirm_foreground_serve(child: &mut Child, window: Duration) -> Result<()> {
    let deadline = tokio::time::Instant::now() + window;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stderr = String::new();
                if let Some(pipe) = child.stderr.take() {
                    pipe.take(SERVE_STDERR_CAP)
                        .read_to_string(&mut stderr)
                        .await
                        .ok();
                }
                bail!(
                    "tailscale serve exited before publishing ({status}): {}",
                    stderr.trim()
                );
            }
            Ok(None) => {
                if tokio::time::Instant::now() >= deadline {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(e) => bail!("tailscale serve status check failed: {e}"),
        }
    }
}

#[async_trait::async_trait]
impl Tunnel for TailscaleTunnel {
    fn name(&self) -> &str {
        "tailscale"
    }

    async fn start(&self, _local_host: &str, local_port: u16) -> Result<String> {
        let subcommand = if self.funnel { "funnel" } else { "serve" };

        // Get the tailscale hostname for URL construction
        let hostname = if let Some(ref h) = self.hostname {
            h.clone()
        } else {
            // Query tailscale for the current hostname
            let output = Command::new(&self.program)
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

        let child = spawn_confirmed_serve(&self.program, subcommand, local_port).await?;

        let public_url = format!("https://{hostname}:{local_port}");
        let spec = ServeSpec {
            program: self.program.clone(),
            subcommand: subcommand.to_string(),
            local_port,
        };

        let mut guard = self.serve.lock().await;
        *guard = Some(ServeProcess::spawn(public_url.clone(), child, spec));

        Ok(public_url)
    }

    async fn stop(&self) -> Result<()> {
        let serve = self.serve.lock().await.take();
        if let Some(serve) = serve {
            // Stop the child first so the watcher treats this as a requested
            // shutdown rather than an unexpected exit. Reset then clears any
            // leftover serve config; a failed start never reaches here, so
            // we cannot wipe an unrelated host config.
            serve.shutdown().await;
            let subcommand = if self.funnel { "funnel" } else { "serve" };
            Command::new(&self.program)
                .args([subcommand, "reset"])
                .output()
                .await
                .ok();
        }
        Ok(())
    }

    /// Healthy while a confirmed foreground child is alive. The supervisor
    /// task stays up across restarts, so health is the child flag, not the
    /// join handle. `Child::id` stays `Some` on a zombie.
    async fn health_check(&self) -> bool {
        self.serve
            .lock()
            .await
            .as_ref()
            .is_some_and(ServeProcess::is_serving)
    }

    fn public_url(&self) -> Option<String> {
        self.serve.try_lock().ok().and_then(|g| {
            g.as_ref()
                .filter(|s| s.is_serving())
                .map(|s| s.public_url.clone())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn restart_backoff_doubles_until_the_fifth_consecutive_failure() {
        let initial = Duration::from_millis(250);
        let max = 5;
        assert_eq!(
            restart_backoff(1, initial, max),
            Some(Duration::from_millis(250))
        );
        assert_eq!(
            restart_backoff(2, initial, max),
            Some(Duration::from_millis(500))
        );
        assert_eq!(
            restart_backoff(3, initial, max),
            Some(Duration::from_millis(1000))
        );
        assert_eq!(
            restart_backoff(4, initial, max),
            Some(Duration::from_millis(2000))
        );
        assert_eq!(restart_backoff(5, initial, max), None);
        assert_eq!(restart_backoff(6, initial, max), None);
        assert_eq!(restart_backoff(0, initial, max), None);
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

    #[cfg(unix)]
    #[tokio::test]
    async fn start_fails_when_the_cli_exits_immediately() {
        let fake = FakeBin::script(
            r#"
if [ "$2" = reset ]; then exit 0; fi
echo "Access denied: serve config denied" >&2
exit 1
"#,
        );
        let tunnel = TailscaleTunnel::new(false, Some("node.example.ts.net".into()))
            .with_program(fake.path.clone());

        let err = tunnel
            .start("127.0.0.1", 42617)
            .await
            .expect_err("an immediately-exiting serve must fail start");
        let msg = err.to_string();
        assert!(
            msg.contains("Access denied: serve config denied"),
            "start error should surface serve stderr, got: {msg}"
        );
        assert!(!tunnel.health_check().await);
        assert!(tunnel.public_url().is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn restart_restores_health_after_one_exit() {
        let fake = FakeBin::script(
            r#"
if [ "$2" = reset ]; then exit 0; fi
count_file="$(dirname "$0")/count"
echo x >> "$count_file"
if [ "$(wc -l < "$count_file")" -eq 1 ]; then
  sleep 0.4
  echo "lost etag" >&2
  exit 1
fi
sleep 30
"#,
        );
        let count_file = fake.path.parent().unwrap().join("count");
        let tunnel = TailscaleTunnel::new(false, Some("node.example.ts.net".into()))
            .with_program(fake.path.clone());

        let url = tunnel.start("127.0.0.1", 42617).await.unwrap();
        assert_eq!(url, "https://node.example.ts.net:42617");
        assert!(
            tunnel.health_check().await,
            "serve must look healthy while it is still in the foreground"
        );

        wait_until(
            || async { !tunnel.health_check().await },
            Duration::from_secs(2),
        )
        .await;
        wait_until(
            || async { tunnel.health_check().await },
            Duration::from_secs(2),
        )
        .await;
        let count = fs::read_to_string(&count_file).unwrap();
        assert!(
            count.lines().count() >= 2,
            "watcher should respawn serve after an unexpected exit, got {count:?}"
        );
        assert_eq!(
            tunnel.public_url().as_deref(),
            Some("https://node.example.ts.net:42617")
        );
        tunnel.stop().await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn restart_gives_up_after_five_consecutive_failures() {
        let fake = FakeBin::script(
            r#"
if [ "$2" = reset ]; then exit 0; fi
count_file="$(dirname "$0")/count"
echo x >> "$count_file"
sleep 0.2
echo "lost etag" >&2
exit 1
"#,
        );
        let count_file = fake.path.parent().unwrap().join("count");
        let tunnel = TailscaleTunnel::new(false, Some("node.example.ts.net".into()))
            .with_program(fake.path.clone());

        tunnel.start("127.0.0.1", 42617).await.unwrap();
        wait_until(
            || {
                let count_file = count_file.clone();
                async move {
                    fs::read_to_string(&count_file)
                        .map(|c| c.lines().count() >= 5)
                        .unwrap_or(false)
                }
            },
            Duration::from_secs(8),
        )
        .await;
        tokio::time::sleep(Duration::from_millis(800)).await;
        let count = fs::read_to_string(&count_file).unwrap().lines().count();
        assert_eq!(
            count, 5,
            "exactly five serve attempts then give up, got {count}"
        );
        assert!(!tunnel.health_check().await);
        assert!(tunnel.public_url().is_none());
        tunnel.stop().await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stop_reaps_a_live_serve() {
        let fake = FakeBin::script(
            r#"
if [ "$2" = reset ]; then exit 0; fi
sleep 30
"#,
        );
        let tunnel = TailscaleTunnel::new(false, Some("node.example.ts.net".into()))
            .with_program(fake.path.clone());

        tunnel.start("127.0.0.1", 42617).await.unwrap();
        assert!(tunnel.health_check().await);
        assert_eq!(
            tunnel.public_url().as_deref(),
            Some("https://node.example.ts.net:42617")
        );

        tunnel.stop().await.unwrap();
        assert!(!tunnel.health_check().await);
        assert!(tunnel.public_url().is_none());
    }

    #[tokio::test]
    async fn confirm_foreground_serve_rejects_an_exited_child() {
        let mut child = spawn_exiting("serve failed", 1).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let err = confirm_foreground_serve(&mut child, Duration::from_millis(100))
            .await
            .expect_err("exited child must fail the confirm window");
        assert!(
            err.to_string().contains("serve failed"),
            "confirm should include stderr, got: {err}"
        );
    }

    #[tokio::test]
    async fn confirm_foreground_serve_accepts_a_live_child() {
        let mut child = spawn_sleeping().await;
        confirm_foreground_serve(&mut child, Duration::from_millis(80))
            .await
            .expect("a live child must pass the confirm window");
        child.kill().await.ok();
        child.wait().await.ok();
    }

    #[cfg(unix)]
    async fn wait_until<F, Fut>(mut pred: F, timeout: Duration)
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if pred().await {
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                panic!("timed out waiting for condition after {timeout:?}");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[cfg(unix)]
    struct FakeBin {
        path: PathBuf,
        _dir: tempfile::TempDir,
    }

    #[cfg(unix)]
    impl FakeBin {
        fn script(body: &str) -> Self {
            let dir = tempfile::tempdir().expect("tempdir for fake tailscale");
            let tmp = dir.path().join("tailscale.tmp");
            let path = dir.path().join("tailscale");
            fs::write(&tmp, format!("#!/bin/sh\n{body}\n")).expect("write fake tailscale");
            let mut perms = fs::metadata(&tmp)
                .expect("stat fake tailscale")
                .permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&tmp, perms).expect("chmod fake tailscale");
            fs::rename(&tmp, &path).expect("publish fake tailscale");
            Self { path, _dir: dir }
        }
    }

    #[cfg(windows)]
    async fn spawn_exiting(stderr: &str, code: i32) -> Child {
        Command::new("cmd")
            .args(["/C", &format!("echo {stderr} 1>&2 & exit {code}")])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("cmd should spawn an exiting fixture")
    }

    #[cfg(not(windows))]
    async fn spawn_exiting(stderr: &str, code: i32) -> Child {
        Command::new("sh")
            .args(["-c", &format!("echo {stderr} >&2; exit {code}")])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("sh should spawn an exiting fixture")
    }

    #[cfg(windows)]
    async fn spawn_sleeping() -> Child {
        Command::new("cmd")
            .args(["/C", "ping -n 30 127.0.0.1 >nul"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("cmd should spawn a sleeping fixture")
    }

    #[cfg(not(windows))]
    async fn spawn_sleeping() -> Child {
        Command::new("sleep")
            .arg("30")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("sleep should spawn")
    }
}
