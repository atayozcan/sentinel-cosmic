// SPDX-FileCopyrightText: 2025 Atay Özcan <atay@oezcan.me>
// SPDX-License-Identifier: GPL-3.0-or-later
//! `pam_sentinel.so` — the PAM module half of Sentinel.
//!
//! Loaded by libpam on every authentication attempt for whatever
//! services have it wired in (`/etc/pam.d/polkit-1`, `/etc/pam.d/sudo`,
//! …). For each call we either:
//!
//! * **bypass**: the Sentinel polkit agent already pre-approved this
//!   auth (we connect to its Unix socket and read "OK"). Return
//!   `PAM_SUCCESS` immediately. See [`agent_bypass`].
//! * **dialog**: spawn `sentinel-helper-kde` to render the confirmation UI;
//!   return `PAM_SUCCESS` on Allow, `PAM_AUTH_ERR` on Deny / timeout.
//! * **headless**: no Wayland display; return whatever
//!   `headless_action` says (default `PAM_IGNORE` so the next module
//!   can prompt for a password).
//! * **disabled**: `enabled = false` in config; `PAM_IGNORE`.
//!
//! # `unsafe` policy
//!
//! This crate runs as **root** inside the privileged binary, so its
//! `unsafe` surface is its blast radius. The crate `#![deny(unsafe_code)]`
//! makes any new `unsafe` a compile error; the handful of genuinely
//! unsafe operations that remain — `fork(2)` and post-`fork`/pre-`exec`
//! `std::env::set_var` (both unavoidably `unsafe`) — opt back in with a
//! narrowly-scoped `#[allow(unsafe_code)]` and a `SAFETY:` note. Audit
//! them with `grep -rn 'allow(unsafe_code)' crates/pam-sentinel`. (We use
//! `deny`, not `forbid`, precisely so those audited sites can opt in.)

#![deny(unsafe_code)]

mod agent_bypass;
mod broker_client;
mod display;
mod helper;
mod locale;
mod proc_info;

use helper::{HelperRequest, run as run_helper};
use pam::constants::{PamFlag, PamResultCode};
use pam::module::{PamHandle, PamHooks};
use proc_info::ProcessInfo;
use sentinel_broker_proto::RememberKey;
use sentinel_shared::audit;
use sentinel_shared::log_kv::quote as q;
use sentinel_shared::logfmt_session_for_pid;
use sentinel_shared::{
    HeadlessAction, Outcome, PolicyDecision, ServiceConfig, format_message, load,
};
use std::ffi::CStr;
use std::time::Instant;

const MODULE_NAME: &str = "pam_sentinel";

struct PamSentinel;
pam::pam_hooks!(PamSentinel);

impl PamHooks for PamSentinel {
    fn sm_authenticate(pamh: &mut PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let debug = args.iter().any(|a| a.to_bytes() == b"debug");
        init_logger(debug);

        if let Some(rc) = agent_bypass::check_agent_bypass(pamh) {
            return rc;
        }

        let service = pam_service(pamh);
        let cfg = load(&service);
        if !cfg.enabled {
            log::debug!("{MODULE_NAME}: disabled for service {service}");
            return PamResultCode::PAM_IGNORE;
        }

        // The PAM module is dlopen'd inside the privileged binary
        // (`sudo`, `polkit-agent-helper-1`, `su`). `getpid()` therefore
        // yields *that* process — which is what we want to display:
        // `/proc/<sudo-pid>/cmdline` is the full command sudo is about
        // to run, while `getppid()` would point at sudo's parent shell.
        // For loginuid lookup we still walk via the parent because the
        // loginuid is inherited from login, not set on the privileged
        // binary itself.
        let process_pid = getpid();
        let requesting_uid = caller_uid(getppid());
        let user = resolve_user(pamh, requesting_uid);

        if !display::detect_for_user(requesting_uid) {
            return handle_headless(&cfg, &service, &user);
        }

        let process = ProcessInfo::for_pid(process_pid);

        // Static [policy] allow/deny, evaluated before the dialog.
        if let Some(rc) = check_policy(&cfg, &service, &user, &process, requesting_uid) {
            return rc;
        }

        // "Remember" window: a fresh grant for this (loginuid, session,
        // service, FULL command) short-circuits to allow without a dialog.
        // The decision is owned by the sandboxed, unprivileged
        // `sentinel-broker` daemon (see `broker_client`) — this module no
        // longer keeps a root store of its own. The grant binds to the
        // whole elevated command (not just the program) and excludes
        // bare-elevation root shells / arbitrary-code gateways, so a grant
        // for `sudo pacman -Syu` can't auto-allow `sudo pacman -U /tmp/evil`
        // (see `ProcessInfo::remember_command`). `None` = not rememberable
        // (always dialog, never record). Fail-closed: an unreachable broker
        // means "show the dialog", never "let in".
        let ppid = getppid();
        let loginuid = read_proc_u32(ppid, "loginuid");
        let sessionid = read_proc_u32(ppid, "sessionid");
        // A request with no audit session leaves loginuid/sessionid at the
        // kernel's `u32::MAX` "unset" sentinel. Never key a grant on the
        // sentinel: two distinct sessions that both lack an audit id would
        // otherwise collide on `{MAX, MAX, service, command}`, letting a
        // grant made in one auto-allow the other. No session ⇒ never
        // remembered (matches the documented contract).
        let remember_key = if loginuid == u32::MAX || sessionid == u32::MAX {
            None
        } else {
            process
                .remember_command
                .as_deref()
                .map(|command| RememberKey {
                    loginuid,
                    sessionid,
                    service: service.clone(),
                    command: sentinel_shared::remember_key_command(command, cfg.remember_scope)
                        .to_string(),
                })
        };
        if cfg.remember_seconds > 0 {
            if let Some(key) = &remember_key {
                if broker_client::check_remember(key.clone(), cfg.remember_seconds) {
                    if cfg.log_attempts {
                        log::info!(
                            "event=auth.allow source=remember user={} service={} process={} exe={} uid={}",
                            q(&user),
                            q(&service),
                            q(&process.name),
                            q(&process.exe),
                            requesting_uid
                        );
                    }
                    return PamResultCode::PAM_SUCCESS;
                }
            }
        }

        // Offer the "remember" checkbox only when a tick can actually be
        // recorded: a non-rememberable request (`sudo -v`, `su`, an
        // ineligible gateway) has no key, so showing the checkbox would
        // be a lie the user discovers on the next prompt.
        let remember_secs = if remember_key.is_some() {
            cfg.remember_seconds
        } else {
            0
        };
        let (rc, remember) = spawn_dialog(
            &cfg,
            &service,
            &user,
            &process,
            process_pid,
            requesting_uid,
            remember_secs,
        );
        // Record the grant only when the user ticked the "remember"
        // checkbox (the helper sets this on an opt-in Allow), not on every
        // allow. `remember_seconds == 0` hides the checkbox, and a
        // non-rememberable request has no key, so neither can record.
        if remember && remember_secs > 0 {
            if let Some(key) = remember_key {
                broker_client::record_remember(key);
            }
        }
        rc
    }

    fn sm_setcred(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        // We're an auth-only module — we don't issue or revoke
        // credentials. Returning PAM_SUCCESS would be a lie that says
        // "yes I established/destroyed credentials"; PAM_IGNORE tells
        // the stack to skip us, which is correct.
        PamResultCode::PAM_IGNORE
    }
}

// -------------- per-stage helpers ------------------------------------------

fn pam_service(pamh: &PamHandle) -> String {
    pamh.get_item::<pam::items::Service>()
        .ok()
        .flatten()
        .and_then(|s| s.to_str().ok().map(str::to_owned))
        .unwrap_or_else(|| "unknown".into())
}

/// Resolve the requesting user's name.
///
/// Order of preference:
/// 1. `pamh.get_user()` — the authoritative answer when PAM has it. In
///    the polkit-agent-helper-1 path the requesting user is set as
///    `PAM_USER` even though our `/proc/<ppid>/loginuid` walk would
///    collapse to root (helper-1's parent is systemd PID 1).
/// 2. `User::from_uid(uid)` — for the sudo / su path where loginuid
///    actually points at the human user, this still yields the right
///    name and is a useful sanity cross-check.
/// 3. `"unknown"` literal — last-resort placeholder; shouldn't happen
///    in practice.
fn resolve_user(pamh: &mut PamHandle, uid: u32) -> String {
    if let Ok(name) = pamh.get_user(None) {
        if !name.is_empty() {
            return name;
        }
    }
    if let Ok(Some(u)) = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid)) {
        return u.name;
    }
    "unknown".into()
}

fn handle_headless(cfg: &ServiceConfig, service: &str, user: &str) -> PamResultCode {
    // The user's actual process (their shell, typically) is the
    // parent of the privileged binary that dlopened us. That's the
    // env we want for session enrichment.
    let session = logfmt_session_for_pid(getppid());

    // Emit a `auth.headless` discriminator before the action-specific
    // line so journalctl filters distinguish "we tried to dialog the
    // user but couldn't find their Wayland display" from "we
    // successfully dialoged and the user denied". Without this, both
    // produce `event=auth.deny source=...` and the cause is opaque.
    if cfg.log_attempts {
        log::info!(
            "event=auth.headless reason=no-wayland user={} service={}{}",
            q(user),
            q(service),
            session
        );
    }

    match cfg.headless_action {
        HeadlessAction::Allow => {
            if cfg.log_attempts {
                log::warn!(
                    "event=auth.allow source=headless user={} service={}{}",
                    q(user),
                    q(service),
                    session
                );
            }
            PamResultCode::PAM_SUCCESS
        }
        HeadlessAction::Deny => {
            if cfg.log_attempts {
                log::info!(
                    "event=auth.deny source=headless user={} service={}{}",
                    q(user),
                    q(service),
                    session
                );
            }
            PamResultCode::PAM_AUTH_ERR
        }
        HeadlessAction::Password => {
            log::debug!(
                "{MODULE_NAME}: no display, falling through to password (service {service})"
            );
            PamResultCode::PAM_IGNORE
        }
    }
}

/// Static `[policy]` allow/deny, evaluated *before* spawning the dialog.
/// Matches on `process.exe`: for a normal process that is the resolved
/// `/proc/<pid>/exe`; for an elevation wrapper (`sudo CMD …`) it is the
/// *elevated program* parsed from the wrapper's cmdline (e.g. `pacman`,
/// not `/usr/bin/sudo`). Either way it is never the spoofable `argv[0]`.
/// (So a `[policy]` entry for an elevated target should be the program
/// **basename**, e.g. `pacman`, not an absolute path.) Returns
/// `Some(rc)` to short-circuit, `None` to fall through to the dialog.
///
/// An `allow` match is passwordless elevation (admin opt-in, like a
/// `sudoers` NOPASSWD line); `deny` wins over `allow`.
fn check_policy(
    cfg: &ServiceConfig,
    service: &str,
    user: &str,
    process: &ProcessInfo,
    requesting_uid: u32,
) -> Option<PamResultCode> {
    // Match on `policy_exe`, not the display `exe`: for a bare-elevation
    // root shell the two differ (`exe` is the originating tool), and
    // `policy_exe` is `None` there so a `[policy] allow` can't be tricked
    // into passwordlessly granting a root shell. `decide(None, None)`
    // matches nothing → `Ask` → dialog.
    let (event, rc) = match cfg.policy.decide(process.policy_exe.as_deref(), None) {
        PolicyDecision::Allow => ("auth.allow", PamResultCode::PAM_SUCCESS),
        PolicyDecision::Deny => ("auth.deny", PamResultCode::PAM_AUTH_ERR),
        PolicyDecision::Ask => return None,
    };
    if cfg.log_attempts {
        let session = logfmt_session_for_pid(getppid());
        log::info!(
            "event={event} source=policy user={} service={} process={} exe={} uid={}{}",
            q(user),
            q(service),
            q(&process.name),
            q(&process.exe),
            requesting_uid,
            session
        );
    }
    Some(rc)
}

fn spawn_dialog(
    cfg: &ServiceConfig,
    service: &str,
    user: &str,
    process: &ProcessInfo,
    requesting_pid: i32,
    requesting_uid: u32,
    remember_secs: u32,
) -> (PamResultCode, bool) {
    let formatted_title = format_message(&cfg.title, user, service, &process.name);
    let formatted_message = format_message(&cfg.message, user, service, &process.name);
    let formatted_secondary = format_message(&cfg.secondary, user, service, &process.name);

    let req = HelperRequest {
        cfg,
        user,
        service,
        process,
        formatted_title: &formatted_title,
        formatted_message: &formatted_message,
        formatted_secondary: &formatted_secondary,
        sound_name: &cfg.sound_name,
        target_uid: requesting_uid,
        requesting_pid,
        remember_secs,
    };

    let dialog_started = Instant::now();
    let result = run_helper(&req);
    let latency_ms = dialog_started.elapsed().as_millis();
    // Session enrichment via the user's process env (getppid() of
    // the privileged binary we're loaded into). Empty string on
    // any failure — see logfmt_session_for_pid.
    let session = logfmt_session_for_pid(getppid());

    if cfg.log_attempts {
        match &result {
            Ok(v) => {
                let event = match v.outcome {
                    Outcome::Allow => "auth.allow",
                    Outcome::Deny => "auth.deny",
                    Outcome::Timeout => "auth.timeout",
                };
                log::info!(
                    "event={event} source=dialog user={} service={} process={} uid={} latency_ms={}{}",
                    q(user),
                    q(service),
                    q(&process.name),
                    requesting_uid,
                    latency_ms,
                    session
                );
            }
            Err(e) => log::warn!(
                "event=auth.error source=dialog user={} service={} error={} latency_ms={}{}",
                q(user),
                q(service),
                q(&e.to_string()),
                latency_ms,
                session
            ),
        }
    }

    match result {
        Ok(v) if v.outcome.is_allow() => (PamResultCode::PAM_SUCCESS, v.remember),
        _ => (PamResultCode::PAM_AUTH_ERR, false),
    }
}

// -------------- module init -----------------------------------------------

fn init_logger(debug: bool) {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let level = if debug {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Info
        };
        audit::init_syslog(MODULE_NAME, level)
    });
}

// -------------- pid/uid lookup + caller-uid lookup ------------------------

// `getpid`/`getppid`/`getuid` via `nix` — always-safe syscall wrappers,
// so no `unsafe` (and no hand-rolled `extern "C"`) is needed. Thin
// adapters to the `i32`/`u32` the call sites want.
fn getpid() -> i32 {
    nix::unistd::getpid().as_raw()
}

fn getppid() -> i32 {
    nix::unistd::getppid().as_raw()
}

fn getuid() -> u32 {
    nix::unistd::getuid().as_raw()
}

/// Identify the calling (human) user, even when the immediate PAM
/// caller is a setuid binary or socket-activated systemd service.
///
/// Strategy, in order:
/// 1. `/proc/<ppid>/loginuid` — set by login/PAM at session start,
///    inherited through forks, immune to setuid transitions. Returns
///    `(uint32_t)-1` for processes not in a login session.
/// 2. `/proc/<ppid>/status` — `Uid:` line, real-uid (first field).
///    Works for non-login processes (e.g. systemd services).
/// 3. Fall back to our own real uid.
pub(crate) fn caller_uid(ppid: i32) -> u32 {
    if ppid > 0
        && let Ok(s) = std::fs::read_to_string(format!("/proc/{ppid}/loginuid"))
        && let Ok(uid) = s.trim().parse::<u32>()
        && uid != u32::MAX
    {
        return uid;
    }
    if ppid > 0
        && let Ok(s) = std::fs::read_to_string(format!("/proc/{ppid}/status"))
    {
        for line in s.lines() {
            if let Some(rest) = line.strip_prefix("Uid:")
                && let Some(real) = rest.split_whitespace().next()
                && let Ok(uid) = real.parse::<u32>()
            {
                return uid;
            }
        }
    }
    getuid()
}

/// Read a single-`u32` `/proc/<ppid>/<field>` such as `loginuid` or
/// `sessionid`. Returns `u32::MAX` (the kernel's "unset" sentinel) when
/// absent or unparseable. Used to bind remember records to the session.
fn read_proc_u32(ppid: i32, field: &str) -> u32 {
    if ppid > 0
        && let Ok(s) = std::fs::read_to_string(format!("/proc/{ppid}/{field}"))
        && let Ok(v) = s.trim().parse::<u32>()
    {
        return v;
    }
    u32::MAX
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(exe: &str, policy_exe: Option<&str>) -> ProcessInfo {
        ProcessInfo {
            name: exe.into(),
            exe: exe.into(),
            cmdline: String::new(),
            cwd: String::new(),
            remember_command: None,
            policy_exe: policy_exe.map(str::to_owned),
        }
    }

    fn cfg_allow(prog: &str) -> ServiceConfig {
        let mut cfg = sentinel_shared::Document::defaults().for_service("sudo");
        cfg.policy.allow = vec![prog.to_string()];
        // Keep the test off the syslog/proc-read path.
        cfg.log_attempts = false;
        cfg
    }

    #[test]
    fn policy_allow_does_not_match_bare_elevation_originator() {
        // The H2 regression: a bare-elevation root shell displays the
        // originating tool (e.g. `topgrade`) as `exe`, but `policy_exe`
        // is None. An `allow = ["topgrade"]` must NOT passwordlessly grant
        // that root shell — it must fall through to the dialog.
        let cfg = cfg_allow("topgrade");
        let bare = proc("topgrade", None);
        assert_eq!(check_policy(&cfg, "sudo", "root", &bare, 1000), None);

        // Sanity: when the elevated target really IS the allowed program
        // (policy_exe = Some), the allow still short-circuits as intended.
        let real = proc("topgrade", Some("topgrade"));
        assert_eq!(
            check_policy(&cfg, "sudo", "root", &real, 1000),
            Some(PamResultCode::PAM_SUCCESS)
        );
    }
}
