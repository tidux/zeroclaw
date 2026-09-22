# ZeroCode Session Root Selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make fresh ZeroCode sessions default to the selected agent workspace while allowing explicit Code directory selection, preserving saved Code roots on resume, and exposing `/change-directory` as a safe new-session transition.

**Architecture:** Keep session-root authority in the daemon's existing `session/new` response and `workspace_dir`. ZeroCode sends `cwd: null` for fresh default local sessions and for resumed sessions, sends a path only for explicit selection (which remote Code always has, because its fresh and restart paths open the daemon-side picker first), and stores the returned root in existing `ChatState`. Add a dedicated `PickChangeDirectory` phase so the current Code state can be stashed in the existing background-session machinery while a new root is selected; never mutate a running session's root.

**Tech Stack:** Rust, Tokio, JSON-RPC client, Ratatui/Crossterm TUI, Fluent localization, mdBook documentation, co-located `#[cfg(test)]` tests.

---

## File Map

- Modify: `apps/zerocode/src/input_bar.rs` — register and parse `/change-directory`, expose a dedicated input action, and update parser/registry tests.
- Modify: `apps/zerocode/src/chat.rs` — add the change-directory phase, picker transition, explicit path conversion, default/resume cwd precedence, session restoration, and request-boundary tests.
- Modify: `apps/zerocode/locales/en/zerocode.ftl` — add English change-directory help and error strings.
- Modify: `apps/zerocode/locales/es/zerocode.ftl` — add Spanish translations for the same identifiers.
- Modify: `apps/zerocode/locales/fr/zerocode.ftl` — add French translations for the same identifiers.
- Modify: `apps/zerocode/locales/ja/zerocode.ftl` — add Japanese translations for the same identifiers.
- Modify: `apps/zerocode/locales/zh-CN/zerocode.ftl` — add Simplified Chinese translations for the same identifiers.
- Modify: `docs/book/src/zerocode/running.md` — document agent-workspace defaults, explicit Code roots, Code resume roots, and Chat reattachment wording.

---

### Task 1: Add the `/change-directory` input contract

**Files:**
- Modify: `apps/zerocode/src/input_bar.rs:35-185,197-271,1582-1680,3030-3220,3745-3765`
- Test: `apps/zerocode/src/input_bar.rs` co-located tests

- [ ] **Step 1: Add failing parser/action tests**

Append this test beside `slash_restart_session_returns_action`:

```rust
#[test]
fn slash_change_directory_returns_action() {
    let mut bar = input_bar_with_shared_commands();
    bar.insert_text("/change-directory");
    assert!(matches!(bar.handle_enter(), InputBarAction::ChangeDirectory));
    assert_eq!(bar.input(), "");
}
```

In `parse_slash_commands`, add:

```rust
assert!(matches!(
    parse_slash_command("/change-directory"),
    SlashCommand::ChangeDirectory
));
assert!(matches!(
    parse_slash_command("/change-directory /tmp/project"),
    SlashCommand::NotACommand
));
```

In `derived_slash_command_set_matches_expected_twelve_entries`, rename the test to `derived_slash_command_set_matches_expected_thirteen_entries` and add `"/change-directory"` between `"/clear-queue"` and `"/detach"`.

- [ ] **Step 2: Run the focused test and verify the expected failure**

Run:

```bash
cargo test -p zerocode --bin zerocode -- input_bar::tests::slash_change_directory_returns_action
```

Expected: compilation failure because `InputBarAction::ChangeDirectory` and `SlashCommand::ChangeDirectory` do not exist.

- [ ] **Step 3: Implement the command**

Make these exact additions:

```rust
// SlashCommandId
ChangeDirectory,

// LOCAL_COMMANDS, after ClearQueue
LocalCommandDescriptor {
    id: SlashCommandId::ChangeDirectory,
    name: "change-directory",
    aliases: &[],
},

// SlashCommand
ChangeDirectory,

// InputBarAction, next to RestartSession
ChangeDirectory,
```

Add parser arms:

```rust
(SlashCommandId::ChangeDirectory, None) => SlashCommand::ChangeDirectory,
(SlashCommandId::ChangeDirectory, Some(_)) => SlashCommand::NotACommand,
```

Add the action conversion:

```rust
SlashCommand::ChangeDirectory => InputBarAction::ChangeDirectory,
```

- [ ] **Step 4: Run the focused parser tests and verify they pass**

Run:

```bash
cargo test -p zerocode --bin zerocode -- input_bar::tests::parse_slash_commands
cargo test -p zerocode --bin zerocode -- input_bar::tests::slash_change_directory_returns_action
cargo test -p zerocode --bin zerocode -- input_bar::tests::every_advertised_command_is_recognized_by_parser
```

Expected: all selected tests pass.

- [ ] **Step 5: Commit the command contract**

```bash
git add apps/zerocode/src/input_bar.rs
git commit -m "feat(zerocode): add change-directory command"
```

---

### Task 2: Add the dedicated Code directory-picker phase

**Files:**
- Modify: `apps/zerocode/src/chat.rs:69-95,1350-1430,2880-3030,3300-3460,4065-4080,4580-4750`
- Test: `apps/zerocode/src/chat.rs` co-located tests

- [ ] **Step 1: Add the phase and localized keys**

Extend `ChatPhase` with a distinct variant immediately after `PickCwd`:

```rust
/// Code-only picker opened by `/change-directory`; the current session is
/// stashed in `background` until the new session succeeds or the picker closes.
PickChangeDirectory {
    agent_alias: String,
    explorer: FileExplorerState,
},
```

Add these identifiers to all five locale files, preserving the `{ $error }` placeholder:

```ftl
zc-chat-help-change-directory = Choose a directory and start a new Code session
zc-chat-change-directory-error = Failed to start a session in the selected directory: { $error }
```

A rejected selection reuses the existing `zc-chat-code-cwd-not-utf8` and
`zc-chat-code-cwd-not-absolute` keys through `LocalCodeCwdError::localized()`,
which name the rejected path; no separate change-directory path key is added.

Use natural translations for values in non-English catalogues; keep identifiers and placeholder names identical.

- [ ] **Step 2: Add a failing chat parser test**

Add beside `command_action_from_initialize` tests:

```rust
#[test]
fn change_directory_command_is_a_dedicated_input_action() {
    assert!(matches!(
        command_action_from_initialize(
            serde_json::json!({"server_version": env!("CARGO_PKG_VERSION")}),
            "/change-directory",
        ),
        InputBarAction::ChangeDirectory
    ));
}
```

- [ ] **Step 3: Run the test and verify the expected failure**

Run:

```bash
cargo test -p zerocode --bin zerocode -- chat::tests::change_directory_command_is_a_dedicated_input_action
```

Expected: compilation failure until the new action and phase compile.

- [ ] **Step 4: Add helpers for explicit paths and the Code-only picker**

Add this pure helper near the existing CWD helpers:

```rust
fn explicit_cwd(path: &std::path::Path) -> Result<String, LocalCodeCwdError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| LocalCodeCwdError::NotUtf8(path.display().to_string()))
}
```

Add this method next to `pick_or_start_session`:

```rust
async fn begin_change_directory(&mut self) {
    if self.pane_kind != PaneKind::Acp {
        return;
    }
    let ChatPhase::Active(state) = &self.phase else {
        return;
    };
    let alias = state.agent_alias.clone();
    let start_dir = state
        .cwd
        .as_deref()
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    self.stash_active();
    let explorer = if self.rpc.transport() == crate::client::Transport::Wss {
        FileExplorerState::new_dir_picker_remote(start_dir, Arc::clone(&self.rpc))
    } else {
        FileExplorerState::new(start_dir)
    };
    self.phase = ChatPhase::PickChangeDirectory {
        agent_alias: alias,
        explorer,
    };
}
```

- [ ] **Step 5: Handle the command and new phase**

In the active `InputBarAction` match, add:

```rust
InputBarAction::ChangeDirectory => {
    self.begin_change_directory().await;
    return false;
}
```

Add a `ChatPhase::PickChangeDirectory` arm in `draw`, delegating to `explorer.render`. In `wants_text_input`, `selected_agent`, and `help_context`, treat it as a directory-picker modal.

In `handle_key`, process the new phase as follows:

```rust
ChatPhase::PickChangeDirectory { agent_alias, explorer } => {
    let action = explorer.handle_key(key);
    match action {
        ExplorerAction::ConfirmDir(path) => {
            let alias = agent_alias.clone();
            match explicit_cwd(&path) {
                Ok(cwd) => {
                    self.start_session(&alias, Some(&cwd)).await;
                    if let ChatPhase::Error(error) = &self.phase {
                        let error = error.clone();
                        let _ = self.restore_last_focused().await;
                        if let ChatPhase::Active(state) = &mut self.phase {
                            state.set_info_notice(crate::i18n::t_args(
                                "zc-chat-change-directory-error",
                                &[("error", error.as_str())],
                            ));
                        }
                    }
                }
                Err(error) => {
                    let _ = self.restore_last_focused().await;
                    if let ChatPhase::Active(state) = &mut self.phase {
                        state.info_message =
                            Some(crate::widgets::InfoMessage::error(error.localized()));
                        state.mark_dirty_full();
                    } else {
                        self.phase = ChatPhase::Error(error.localized());
                    }
                }
            }
        }
        ExplorerAction::Cancel => {
            let _ = self.restore_last_focused().await;
        }
        ExplorerAction::Confirm(_) | ExplorerAction::None => {}
    }
    return false;
}
```

If `start_session` leaves the pane in `ChatPhase::Error`, restore the stashed state and replace the error with the localized change-directory notice. If the picker is cancelled, restore the stashed state without sending `session/new`. On success, the old state remains in `background` and the new state becomes active.

- [ ] **Step 6: Add localized help text**

Add `E::desc(crate::i18n::t("zc-chat-help-change-directory"))` to the active Code help entries only; do not add it to Chat help.

- [ ] **Step 7: Run focused tests and compile checks**

Run:

```bash
cargo test -p zerocode --bin zerocode -- chat::tests::change_directory_command_is_a_dedicated_input_action
cargo test -p zerocode --bin zerocode -- input_bar::tests
cargo check -p zerocode --bin zerocode
```

Expected: selected tests pass and the binary checks successfully.

- [ ] **Step 8: Commit the picker phase**

```bash
git add apps/zerocode/src/chat.rs apps/zerocode/src/input_bar.rs apps/zerocode/locales
git commit -m "feat(zerocode): add Code directory picker flow"
```

---

### Task 3: Default fresh sessions to the agent workspace and preserve explicit/resumed roots

**Files:**
- Modify: `apps/zerocode/src/chat.rs:102-163,1646-1690,2031-2115`
- Test: `apps/zerocode/src/chat.rs` existing cwd tests around `15100-15510`

- [ ] **Step 1: Change request precedence and update the existing regression tests**

Replace the current `local_code_session_cwd` call in `start_session_with_cancel` with:

```rust
let cwd_str = if resume_id.is_some() {
    None
} else {
    cwd_override
        .filter(|cwd| !cwd.trim().is_empty())
        .map(str::to_owned)
};
```

Remove the process-CWD capture path, because fresh local Code sessions now default to the agent workspace. Retain `LocalCodeCwdError::NotUtf8` and `explicit_cwd` for explicit picker paths.

Update the existing tests as follows:

- Keep `fresh_local_chat_session_omits_cwd_so_agent_workspace_wins` and its `cwd: null` assertion.
- Rename `fresh_local_acp_session_sends_process_cwd` to `fresh_local_acp_session_omits_cwd_so_agent_workspace_wins`, assert `params["cwd"].is_null()`, and retain the daemon-returned workspace assertion.
- Rename `restart_local_acp_session_sends_process_cwd` to `restart_local_acp_session_omits_cwd_so_agent_workspace_wins` and assert `params["cwd"].is_null()`.
- Rewrite the launch-directory capture tests so `explicit_cwd(Path::new("/tmp/project"))` returns `"/tmp/project"` and a Unix non-UTF-8 `PathBuf` returns `LocalCodeCwdError::NotUtf8`.

- [ ] **Step 2: Run the focused tests and verify the expected failures**

Run:

```bash
cargo test -p zerocode --bin zerocode -- chat::tests::fresh_local_acp_session_omits_cwd_so_agent_workspace_wins
cargo test -p zerocode --bin zerocode -- chat::tests::restart_local_acp_session_omits_cwd_so_agent_workspace_wins
cargo test -p zerocode --bin zerocode -- chat::tests::local_code_cwd_rejects_non_utf8_launch_path
```

Expected: the renamed local-Code tests fail before the implementation change because the current code still sends the process cwd; the rewritten non-UTF-8 test fails until explicit path conversion exists.

- [ ] **Step 3: Add explicit and resume request tests**

Add this complete explicit-path test using the existing `next_rpc_request` and `respond_ok` helpers:

```rust
#[tokio::test]
async fn fresh_local_acp_session_sends_explicit_cwd() {
    let (tx, mut rx) = mpsc::channel::<String>(16);
    let rpc = Arc::new(RpcOutbound::new(tx));
    let client = Arc::new(RpcClient::with_rpc_transport(
        Arc::clone(&rpc),
        crate::client::Transport::Local,
    ));
    let mut chat = Chat::new(client, PaneKind::Acp);
    let task = tokio::spawn(async move {
        chat.start_session("alpha", Some("/selected/project")).await;
        chat
    });
    let request = next_rpc_request(&mut rx, "explicit local Code session should start").await;
    assert_eq!(request["method"], method::SESSION_NEW);
    assert_eq!(request["params"]["cwd"], "/selected/project");
    respond_ok(
        &rpc,
        &request,
        serde_json::json!({"session_id":"sess-selected","workspace_dir":"/selected/project"}),
    );
    let request = next_rpc_request(&mut rx, "new session refreshes identity").await;
    assert_eq!(request["method"], method::CONFIG_LIST);
    respond_ok(&rpc, &request, serde_json::json!([]));
    assert_eq!(task.await.unwrap().current_cwd(), Some("/selected/project"));
}
```

Add a resume test that calls `chat.set_resume_sessions(vec![resume_entry("sess-saved", "alpha", true)])`, starts `chat.start_session("alpha", None)`, asserts `session_id == "sess-saved"` and `cwd` is null, returns `workspace_dir: "/saved/project"`, responds to `CONFIG_LIST` and `SESSION_MESSAGES` with the existing helper protocol, and asserts `current_cwd() == Some("/saved/project")`.

- [ ] **Step 4: Run the request-boundary tests and verify they pass**

Run:

```bash
cargo test -p zerocode --bin zerocode -- chat::tests::fresh_local_acp_session_sends_explicit_cwd
cargo test -p zerocode --bin zerocode -- chat::tests::resumed_local_acp_session_keeps_saved_cwd
cargo test -p zerocode --bin zerocode -- chat::tests::restart_local_acp_session_omits_cwd_so_agent_workspace_wins
```

Expected: all three tests pass and no request contains the process launch directory unless it was explicitly supplied by a picker.

- [ ] **Step 5: Commit cwd precedence and resume coverage**

```bash
git add apps/zerocode/src/chat.rs
git commit -m "fix(zerocode): default fresh sessions to agent workspace"
```

---

### Task 4: Update documentation and verify the complete focused surface

**Files:**
- Modify: `docs/book/src/zerocode/running.md`
- Modify: `apps/zerocode/src/chat.rs` transition tests

- [ ] **Step 1: Add transition regression tests**

Add a failure test that drives the real input action and picker phase:

```rust
#[tokio::test]
async fn change_directory_failure_restores_existing_session() {
    // Build an active local Code ChatState with session_id "sess-old",
    // agent_alias "alpha", and cwd "/old/project". Submit the real
    // /change-directory action through handle_key, confirm a local directory,
    // return an RPC error for session/new, and assert the restored active
    // session remains "sess-old" at "/old/project" with no close request.
}
```

Add a cancellation test that opens `PickChangeDirectory`, sends Escape, and asserts the old session is focused and no `session/new` request was emitted.

- [ ] **Step 2: Run the transition tests and verify the expected failures**

Run:

```bash
cargo test -p zerocode --bin zerocode -- chat::tests::change_directory_failure_restores_existing_session
cargo test -p zerocode --bin zerocode -- chat::tests::change_directory_cancel_restores_existing_session
```

Expected: the tests fail until the dedicated phase restores the stashed state on both paths.

- [ ] **Step 3: Verify successful distinct-session behavior**

Extend the transition test with a successful response (`session_id: "sess-new"`, `workspace_dir: "/selected/project"`), respond to `CONFIG_LIST`, then assert `current_session_id() == Some("sess-new")`, `current_cwd() == Some("/selected/project")`, and `state_for_session("sess-old").unwrap().cwd == Some("/old/project")`.

Run:

```bash
cargo test -p zerocode --bin zerocode -- chat::tests::change_directory_starts_distinct_session_and_keeps_old_root
```

Expected: the success transition passes with both sessions tracked.

- [ ] **Step 4: Update `running.md`**

Replace the current local Code launch-directory paragraph with:

```markdown
Fresh Chat sessions, and fresh local Code sessions, use the selected agent's
configured workspace by default. Fresh or restarted remote (WSS) Code always
opens the daemon-side directory picker instead, so it has no default root. In
the **Code** pane, `/change-directory` opens a directory picker (local or
daemon-side, matching the connection) and starts a new session in the selected
directory; the existing session remains available at its saved root. Resumed
Code sessions keep their own working directory even if the launch directory or
agent workspace later changes. Chat can use the selected agent's current
workspace when it is reattached.
```

Keep the session-switching section consistent: it may say that switching resumes a saved Code root, but it must not say that an active session is re-rooted.

- [ ] **Step 5: Run focused tests and docs gates**

Run:

```bash
cargo test -p zerocode --bin zerocode -- chat::tests
cargo test -p zerocode --bin zerocode -- input_bar::tests
scripts/ci/docs_quality_gate.sh
scripts/ci/docs_links_gate.sh
```

Expected: zero failed tests, zero docs-quality errors, and no docs-link failures.

- [ ] **Step 6: Commit the documentation and transition coverage**

```bash
git add apps/zerocode/src/chat.rs docs/book/src/zerocode/running.md
git commit -m "docs(zerocode): document explicit session roots"
```

---

### Task 5: Final verification and review checkpoint

**Files:**
- No new files; verify the committed changes and repository state.

- [ ] **Step 1: Inspect implementation diff and issue linkage**

Run:

```bash
git status --short --branch
git diff upstream/master...HEAD --stat
git log --oneline upstream/master..HEAD
gh issue view 10826 --repo zeroclaw-labs/zeroclaw --json number,state,title
```

Confirm the diff is limited to ZeroCode root selection, localization, tests, docs, and the design/plan records.

- [ ] **Step 2: Run formatting and strict lint checks**

Run:

```bash
cargo fmt -p zerocode -- --check
cargo clippy -p zerocode --all-targets -- -D warnings
```

Expected: exit 0 with no formatting or Clippy errors.

- [ ] **Step 3: Run the full ZeroCode package tests**

Run:

```bash
cargo test -p zerocode
```

Expected: exit 0 with zero failed tests.

- [ ] **Step 4: Run final docs gates**

Run:

```bash
scripts/ci/docs_quality_gate.sh
scripts/ci/docs_links_gate.sh
```

Expected: zero documentation-quality errors and no broken/new-link failures.

- [ ] **Step 5: Request code review before completion claims**

Use the code-review workflow with base SHA `upstream/master` and the final `HEAD` SHA. Include #10826, the exact focused/full test commands, and whether a live interactive TUI smoke test was possible. Address Critical and Important findings before reporting completion.

- [ ] **Step 6: Report evidence**

Report the existing issue number, design and plan paths, implementation commits, exact command results, and any remaining user-boundary test gap. Do not claim completion without fresh verification output.
