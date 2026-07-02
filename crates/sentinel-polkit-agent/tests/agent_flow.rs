// SPDX-FileCopyrightText: 2025 Atay Özcan <atay@oezcan.me>
// SPDX-License-Identifier: GPL-3.0-or-later
//! Integration tests for the agent's session state machine, driving
//! `session::run` end-to-end with a mock helper + mock polkit-agent-
//! helper-1.
//!
//! Test seams:
//! - `SENTINEL_TEST_HELPER_OUTCOME` short-circuits `helper_ui::run`
//!   to a canned `Outcome` (Allow / Deny / Timeout).
//! - `SENTINEL_TEST_HELPER1_OUTCOME` short-circuits `helper1::run`
//!   to a canned bool ("SUCCESS" → true, anything else → false).
//!
//! Cargo test runs separate `#[tokio::test]` functions in parallel
//! threads sharing process env, so the path-coverage cases live in
//! a single `serialised_session_paths` test that walks Allow → Deny
//! → Timeout sequentially with explicit env var rotation. The
//! cancel-drain test runs in parallel because it doesn't touch env
//! vars.
//!
//! What's NOT covered (deferred to v0.8 with python-dbusmock):
//! - The zbus `#[zbus::interface]` dispatch (D-Bus marshalling).
//! - The bypass-socket peer-uid + comm verification (needs uid 0).
//! - Polkit's session-equality check at registration.

use sentinel_polkit_agent::{
    approval_queue::ApprovalQueue,
    remember::RememberCache,
    session::{self, AuthInputs},
};
use sentinel_shared::{HeadlessAction, ServiceConfig};

fn cfg() -> ServiceConfig {
    ServiceConfig {
        enabled: true,
        timeout: 30,
        randomize_buttons: false,
        headless_action: HeadlessAction::Password,
        show_process_info: true,
        log_attempts: false,
        min_display_time_ms: 0,
        title: "Test Auth".into(),
        message: "test".into(),
        secondary: String::new(),
        sound_name: String::new(),
        policy: Default::default(),
        notify_on_deny: false,
        notify_on_timeout: false,
        remember_seconds: 0,
        remember_scope: sentinel_shared::RememberScope::Command,
    }
}

fn inputs<'a>(action_id: &'a str, cookie: &'a str, cfg: &'a ServiceConfig) -> AuthInputs<'a> {
    AuthInputs {
        action_id,
        cookie,
        username: "testuser",
        cfg,
        process_exe: Some("/usr/bin/true"),
        process_cmdline: Some("true"),
        process_pid: Some(1),
        process_cwd: Some("/"),
        requesting_user: Some("testuser"),
    }
}

/// Runs the three outcome paths sequentially in one tokio runtime so
/// the shared process env-var test seams don't race.
#[tokio::test(flavor = "current_thread")]
async fn serialised_session_paths() {
    // ---- Allow: dialog → push → helper-1 SUCCESS → Ok(true) ----
    unsafe {
        std::env::set_var("SENTINEL_TEST_HELPER_OUTCOME", "ALLOW");
        std::env::set_var("SENTINEL_TEST_HELPER1_OUTCOME", "SUCCESS");
    }
    let cfg = cfg();
    {
        let queue = ApprovalQueue::new();
        let result = session::run(
            queue.clone(),
            RememberCache::new(),
            inputs("a.allow", "ck-a", &cfg),
        )
        .await;
        assert!(result.is_ok(), "allow path: session::run should succeed");
        assert!(result.unwrap(), "allow path returns Ok(true)");
    }

    // ---- Deny: dialog → no push, no helper-1 → Ok(false) ----
    unsafe {
        std::env::set_var("SENTINEL_TEST_HELPER_OUTCOME", "DENY");
        // Leave HELPER1 set; if a regression accidentally calls
        // helper1::run on the deny path, the canned SUCCESS would
        // mask the bug. Remove it explicitly.
        std::env::remove_var("SENTINEL_TEST_HELPER1_OUTCOME");
    }
    {
        let queue = ApprovalQueue::new();
        let result = session::run(
            queue.clone(),
            RememberCache::new(),
            inputs("a.deny", "ck-d", &cfg),
        )
        .await;
        assert!(result.is_ok(), "deny path: session::run should succeed");
        assert!(!result.unwrap(), "deny path returns Ok(false)");
        assert!(
            queue.take_one().await.is_none(),
            "deny path must not enqueue an approval"
        );
    }

    // ---- Timeout: same shape as Deny ----
    unsafe {
        std::env::set_var("SENTINEL_TEST_HELPER_OUTCOME", "TIMEOUT");
    }
    {
        let queue = ApprovalQueue::new();
        let result = session::run(
            queue.clone(),
            RememberCache::new(),
            inputs("a.timeout", "ck-t", &cfg),
        )
        .await;
        assert!(result.is_ok(), "timeout path: session::run should succeed");
        assert!(!result.unwrap(), "timeout path returns Ok(false)");
        assert!(
            queue.take_one().await.is_none(),
            "timeout path must not enqueue an approval"
        );
    }

    // ---- Remember opt-in: plain ALLOW does NOT record; ALLOW REMEMBER does ----
    {
        let mut rcfg = cfg.clone();
        rcfg.remember_seconds = 60;
        let remember = RememberCache::new();
        unsafe {
            std::env::set_var("SENTINEL_TEST_HELPER_OUTCOME", "ALLOW");
            std::env::set_var("SENTINEL_TEST_HELPER1_OUTCOME", "SUCCESS");
        }
        let _ = session::run(
            ApprovalQueue::new(),
            remember.clone(),
            inputs("a.rem", "ck-r1", &rcfg),
        )
        .await;
        assert!(
            !remember.is_fresh("a.rem", "true", 60).await,
            "plain ALLOW must NOT remember"
        );

        unsafe { std::env::set_var("SENTINEL_TEST_HELPER_OUTCOME", "ALLOW REMEMBER") };
        let _ = session::run(
            ApprovalQueue::new(),
            remember.clone(),
            inputs("a.rem", "ck-r2", &rcfg),
        )
        .await;
        assert!(
            remember.is_fresh("a.rem", "true", 60).await,
            "ALLOW REMEMBER must record the grant"
        );
    }

    // ---- pkexec is remembered PER-COMMAND (not carved out, not blanket) ----
    // The incident fix: a ticked `pkexec true` must auto-allow only
    // `pkexec true`, never a different pkexec command.
    {
        let mut rcfg = cfg.clone();
        rcfg.remember_seconds = 60;
        let remember = RememberCache::new();
        let exec = "org.freedesktop.policykit.exec";
        unsafe { std::env::set_var("SENTINEL_TEST_HELPER_OUTCOME", "ALLOW REMEMBER") };
        let _ = session::run(
            ApprovalQueue::new(),
            remember.clone(),
            inputs(exec, "ck-px", &rcfg), // fixture cmdline = "true"
        )
        .await;
        assert!(
            remember.is_fresh(exec, "true", 60).await,
            "pkexec true was remembered → it should auto-allow pkexec true"
        );
        assert!(
            !remember.is_fresh(exec, "rm -rf /", 60).await,
            "a remembered pkexec command must NOT blanket other pkexec commands"
        );
    }

    // Cleanup process env so concurrent tests don't see stale values.
    unsafe {
        std::env::remove_var("SENTINEL_TEST_HELPER_OUTCOME");
        std::env::remove_var("SENTINEL_TEST_HELPER1_OUTCOME");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn cancel_drains_pending_approval() {
    // Direct test of `ApprovalQueue::drain` — the API
    // `Agent::cancel_authentication` uses to invalidate stale
    // approvals when polkit cancels mid-auth. No env vars needed,
    // so this is parallel-safe.
    let queue = ApprovalQueue::new();
    queue.push("org.example.test".to_string()).await;
    queue.drain().await;
    assert!(
        queue.take_one().await.is_none(),
        "drain must clear pending approvals"
    );
}
