// SPDX-FileCopyrightText: 2025 Atay Özcan <atay@oezcan.me>
// SPDX-License-Identifier: GPL-3.0-or-later
//! One in-flight authentication: drive `sentinel-helper-kde` for the user
//! decision, then satisfy polkit's cookie validation by enqueueing an
//! approval (consumed by `pam_sentinel.so` via the agent's Unix
//! socket) and connecting to `/run/polkit/agent-helper.socket`.

use crate::approval_queue::ApprovalQueue;
use crate::helper_ui;
use crate::helper1;
use crate::remember::RememberCache;
use anyhow::{Context, Result};
use log::{info, warn};
use sentinel_shared::log_kv::quote as q;
use sentinel_shared::logfmt_session_for_pid;
use sentinel_shared::{Outcome, PolicyDecision, ServiceConfig};
use std::time::Instant;

pub struct AuthInputs<'a> {
    pub action_id: &'a str,
    pub cookie: &'a str,
    pub username: &'a str,
    /// Effective `polkit-1` config loaded by the caller (per-call, so
    /// edits to `/etc/security/sentinel.conf` take effect on the next
    /// auth without restarting the agent).
    pub cfg: &'a ServiceConfig,
    pub process_exe: Option<&'a str>,
    pub process_cmdline: Option<&'a str>,
    pub process_pid: Option<i32>,
    pub process_cwd: Option<&'a str>,
    pub requesting_user: Option<&'a str>,
}

pub async fn run(
    queue: ApprovalQueue,
    remember: RememberCache,
    inputs: AuthInputs<'_>,
) -> Result<bool> {
    // Static [policy] allow/deny, evaluated before the dialog. Matches
    // on the subject's resolved exe path and/or the polkit action id;
    // `deny` wins over `allow`. An allow short-circuits straight to the
    // helper-1 hand-off (no dialog); a deny rejects without one.
    match inputs
        .cfg
        .policy
        .decide(inputs.process_exe, Some(inputs.action_id))
    {
        PolicyDecision::Deny => {
            let process_name = inputs
                .process_exe
                .and_then(sentinel_shared::process_basename)
                .unwrap_or("unknown");
            let session = inputs
                .process_pid
                .map(logfmt_session_for_pid)
                .unwrap_or_default();
            info!(
                "event=auth.deny source=policy user={} action={} process={}{}",
                q(inputs.username),
                q(inputs.action_id),
                q(process_name),
                session
            );
            if inputs.cfg.notify_on_deny {
                sentinel_shared::desktop_notify(
                    "Privilege request blocked",
                    &format!("Policy denied an elevation request from {process_name}."),
                );
            }
            return Ok(false);
        }
        PolicyDecision::Allow => {
            let process_name = inputs
                .process_exe
                .and_then(sentinel_shared::process_basename)
                .unwrap_or("unknown");
            let session = inputs
                .process_pid
                .map(logfmt_session_for_pid)
                .unwrap_or_default();
            info!(
                "event=auth.allow source=policy user={} action={} process={}{}",
                q(inputs.username),
                q(inputs.action_id),
                q(process_name),
                session
            );
            queue.push(inputs.action_id.to_string()).await;
            let success = helper1::run(helper1::Run {
                username: inputs.username,
                cookie: inputs.cookie,
            })
            .await
            .context("run polkit-agent-helper-1")?;
            if !success {
                warn!(
                    "event=auth.error source=agent.helper1 action={} note=\"helper-1 reported FAILURE — PAM stack rejected policy approval?\"",
                    q(inputs.action_id)
                );
            }
            return Ok(success);
        }
        PolicyDecision::Ask => {}
    }

    // Effective remember window for this request. The grant is keyed by
    // the FULL elevated command, and shells / interpreters / arbitrary-
    // code gateways are excluded (the denylist shared with the PAM path),
    // so a remembered `pkexec true` can never auto-allow `pkexec rm` — no
    // blanket pkexec carve-out needed. An ineligible or empty command
    // collapses the window to 0, disabling the checkbox, the auto-allow,
    // and the recording.
    let remember_command = inputs.process_cmdline.unwrap_or_default();
    let remember_secs = if sentinel_shared::remember_eligible_command(remember_command) {
        inputs.cfg.remember_seconds
    } else {
        0
    };
    // Grant key per the configured scope: the full command (default) or
    // just the program token (`remember_scope = "program"`, opt-in).
    let remember_command =
        sentinel_shared::remember_key_command(remember_command, inputs.cfg.remember_scope);

    // In-memory "remember" cache (the polkit-path complement to the root
    // timestamp store, which the PAM module owns for sudo/su). A fresh
    // grant for this (action, full command) auto-allows without a dialog.
    if remember_secs > 0
        && remember
            .is_fresh(inputs.action_id, remember_command, remember_secs)
            .await
    {
        let process_name = inputs
            .process_exe
            .and_then(sentinel_shared::process_basename)
            .unwrap_or("unknown");
        let session = inputs
            .process_pid
            .map(logfmt_session_for_pid)
            .unwrap_or_default();
        info!(
            "event=auth.allow source=remember user={} action={} process={}{}",
            q(inputs.username),
            q(inputs.action_id),
            q(process_name),
            session
        );
        queue.push(inputs.action_id.to_string()).await;
        let success = helper1::run(helper1::Run {
            username: inputs.username,
            cookie: inputs.cookie,
        })
        .await
        .context("run polkit-agent-helper-1")?;
        return Ok(success);
    }

    let req = helper_ui::Request::for_action(helper_ui::ForAction {
        action_id: inputs.action_id,
        cfg: inputs.cfg,
        remember_secs,
        username: inputs.username,
        process_exe: inputs.process_exe,
        process_cmdline: inputs.process_cmdline,
        process_pid: inputs.process_pid,
        process_cwd: inputs.process_cwd,
        requesting_user: inputs.requesting_user,
    });
    let dialog_started = Instant::now();
    let verdict = helper_ui::run(req)
        .await
        .context("run sentinel-helper-kde")?;
    let outcome = verdict.outcome;
    let latency_ms = dialog_started.elapsed().as_millis();

    let process_name = inputs
        .process_exe
        .and_then(sentinel_shared::process_basename)
        .unwrap_or("unknown");
    // Session enrichment via the polkit subject's process env. The
    // subject is the user's actual process (the GUI app or shell
    // requesting the privileged action), which is what we want.
    let session = inputs
        .process_pid
        .map(logfmt_session_for_pid)
        .unwrap_or_default();

    match outcome {
        Outcome::Deny => {
            info!(
                "event=auth.deny source=agent user={} action={} process={} latency_ms={}{}",
                q(inputs.username),
                q(inputs.action_id),
                q(process_name),
                latency_ms,
                session
            );
            if inputs.cfg.notify_on_deny {
                sentinel_shared::desktop_notify(
                    "Authentication denied",
                    &format!("You denied an elevation request from {process_name}."),
                );
            }
            return Ok(false);
        }
        Outcome::Timeout => {
            info!(
                "event=auth.timeout source=agent user={} action={} process={} latency_ms={}{}",
                q(inputs.username),
                q(inputs.action_id),
                q(process_name),
                latency_ms,
                session
            );
            if inputs.cfg.notify_on_timeout {
                sentinel_shared::desktop_notify(
                    "Authentication timed out",
                    &format!(
                        "An elevation request from {process_name} was auto-denied (no response)."
                    ),
                );
            }
            return Ok(false);
        }
        Outcome::Allow => {
            info!(
                "event=auth.allow source=agent user={} action={} process={} latency_ms={}{}",
                q(inputs.username),
                q(inputs.action_id),
                q(process_name),
                latency_ms,
                session
            );
        }
    }

    // Record this Allow so a repeat of the SAME (action, full command)
    // within the window skips the dialog — but only if the user ticked
    // the "remember" checkbox (verdict.remember), not on every allow.
    if verdict.remember && remember_secs > 0 {
        remember.remember(inputs.action_id, remember_command).await;
    }

    // Pre-approve before handing off to helper-1. helper-1 → PAM →
    // pam_sentinel.so will dequeue this from our socket within a few
    // milliseconds.
    queue.push(inputs.action_id.to_string()).await;

    let success = helper1::run(helper1::Run {
        username: inputs.username,
        cookie: inputs.cookie,
    })
    .await
    .context("run polkit-agent-helper-1")?;

    if !success {
        warn!(
            "event=auth.error source=agent.helper1 action={} note=\"helper-1 reported FAILURE — PAM stack rejected approval?\"",
            q(inputs.action_id)
        );
    }
    Ok(success)
}
