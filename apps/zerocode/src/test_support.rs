//! Shared test-only helpers.
//!
//! `std::env` is process-global, so every test that mutates or *reads through*
//! an environment variable must serialize on the same lock — a per-module lock
//! only protects that module and lets values leak across suites.

/// Global guard for synchronous tests that set, remove, or resolve
/// configuration through environment variables.
pub(crate) fn env_test_lock() -> std::sync::MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Async counterpart of [`env_test_lock`] for `#[tokio::test]` cases, which
/// hold the guard across await points. Uses a separate async-aware mutex, so
/// sync and async env tests must not run concurrently with each other; the
/// async side additionally serializes on [`env_test_lock`] internally.
///
/// Only the binary target has async env-dependent tests (`chat`), so this is
/// unused in the lib target.
#[allow(dead_code)]
pub(crate) async fn env_test_lock_async() -> (
    tokio::sync::MutexGuard<'static, ()>,
    std::sync::MutexGuard<'static, ()>,
) {
    static ASYNC_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let async_guard = ASYNC_LOCK.lock().await;
    let sync_guard = env_test_lock();
    (async_guard, sync_guard)
}
