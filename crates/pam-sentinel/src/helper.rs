// SPDX-FileCopyrightText: 2025 Atay Özcan <atay@oezcan.me>
// SPDX-License-Identifier: GPL-3.0-or-later
use crate::proc_info::ProcessInfo;
use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::signal::{Signal, kill};
use nix::sys::wait::waitpid;
use nix::unistd::{
    ForkResult, Pid, User, dup2_stdout, execv, fork, initgroups, pipe, setgid, setuid,
};
use sentinel_shared::{Outcome, ServiceConfig, Verdict};
use std::ffi::CString;
use std::os::fd::{AsFd, OwnedFd};

pub const HELPER_PATH: &str = env!("SENTINEL_HELPER_PATH");

/// Grace period (in seconds) added on top of the helper's own auto-deny
/// timeout when computing the parent's `poll(2)` deadline. The helper
/// races us to its own timeout; this slack lets the helper's verdict
/// arrive even if `poll` returns slightly after the helper's clock.
const HELPER_GRACE_SECS: u32 = 5;

pub struct HelperRequest<'a> {
    pub cfg: &'a ServiceConfig,
    pub user: &'a str,
    pub service: &'a str,
    pub process: &'a ProcessInfo,
    /// Title with `%u`/`%s`/`%p` already substituted. Lives outside
    /// `cfg` so we don't need to clone the whole `ServiceConfig` just
    /// to swap one field in the caller.
    pub formatted_title: &'a str,
    pub formatted_message: &'a str,
    pub formatted_secondary: &'a str,
    /// Freedesktop sound name to pass to the helper, or empty for
    /// silent. Sourced from `[audio].sound_name` in the config.
    pub sound_name: &'a str,
    pub target_uid: u32,
    pub requesting_pid: i32,
    /// Effective remember window for THIS request: `0` (checkbox hidden)
    /// when the request is not rememberable (`sudo -v`, `su`, ineligible
    /// gateway), `cfg.remember_seconds` otherwise. Not read from `cfg`
    /// so the checkbox can never be offered when a tick has nowhere to
    /// be recorded.
    pub remember_secs: u32,
}

// `fork(2)` is unavoidably `unsafe`; contained here (crate is
// `#![deny(unsafe_code)]`). See the SAFETY note at the call.
#[allow(unsafe_code)]
pub fn run(req: &HelperRequest<'_>) -> Result<Verdict, String> {
    let (read_fd, write_fd) = pipe().map_err(|e| format!("pipe: {e}"))?;

    // SAFETY: fork in a PAM module called from a process not yet using threads
    // for this auth attempt. The child uses only async-signal-safe operations.
    match unsafe { fork() }.map_err(|e| format!("fork: {e}"))? {
        ForkResult::Child => {
            drop(read_fd);
            child_exec(req, write_fd);
        }
        ForkResult::Parent { child } => {
            drop(write_fd);
            parent_wait(child, read_fd, req)
        }
    }
}

// Post-`fork` child: `std::env::set_var` is `unsafe` (edition 2024);
// safe here because the child is single-threaded before `exec`.
#[allow(unsafe_code)]
fn child_exec(req: &HelperRequest<'_>, write_fd: OwnedFd) -> ! {
    let user = match User::from_uid(nix::unistd::Uid::from_raw(req.target_uid)) {
        Ok(Some(u)) => u,
        _ => std::process::exit(1),
    };

    if initgroups(
        &CString::new(user.name.clone()).unwrap_or_else(|_| CString::new("").unwrap()),
        user.gid,
    )
    .is_err()
    {
        std::process::exit(1);
    }
    if setgid(user.gid).is_err() {
        std::process::exit(1);
    }
    if setuid(user.uid).is_err() {
        std::process::exit(1);
    }

    // SAFETY: setting env in the post-fork child before exec; no other threads.
    unsafe {
        std::env::set_var("HOME", &user.dir);
        std::env::set_var("USER", &user.name);
        std::env::set_var("LOGNAME", &user.name);

        // Forward locale-relevant env vars from the requesting user's
        // own process so the helper picks the right translation. This
        // env was scrubbed by sudo / polkit-agent-helper-1, so we have
        // to recover it from /proc/<requesting_pid>/environ. Values
        // are validated against a strict whitelist before use — see
        // `crate::locale` for the threat model.
        for (key, value) in crate::locale::read_locale_env(req.requesting_pid) {
            std::env::set_var(key, value);
        }
    }

    if dup2_stdout(write_fd.as_fd()).is_err() {
        std::process::exit(1);
    }
    drop(write_fd);

    let mut argv: Vec<CString> = Vec::with_capacity(20);
    let push = |argv: &mut Vec<CString>, s: &str| {
        if let Ok(c) = CString::new(s) {
            argv.push(c);
        }
    };
    push(&mut argv, HELPER_PATH);
    push(&mut argv, "--title");
    push(&mut argv, req.formatted_title);
    push(&mut argv, "--message");
    push(&mut argv, req.formatted_message);
    push(&mut argv, "--secondary");
    push(&mut argv, req.formatted_secondary);
    push(&mut argv, "--timeout");
    push(&mut argv, &req.cfg.timeout.to_string());
    push(&mut argv, "--min-time");
    push(&mut argv, &req.cfg.min_display_time_ms.to_string());
    push(&mut argv, "--remember-secs");
    push(&mut argv, &req.remember_secs.to_string());
    if !req.sound_name.is_empty() {
        push(&mut argv, "--sound-name");
        push(&mut argv, req.sound_name);
    }
    if req.cfg.randomize_buttons {
        push(&mut argv, "--randomize");
    }
    if req.cfg.show_process_info {
        push(&mut argv, "--process-exe");
        push(&mut argv, &req.process.exe);
        if !req.process.cmdline.is_empty() {
            push(&mut argv, "--process-cmdline");
            push(&mut argv, &req.process.cmdline);
        }
        push(&mut argv, "--process-pid");
        push(&mut argv, &req.requesting_pid.to_string());
        if !req.process.cwd.is_empty() {
            push(&mut argv, "--process-cwd");
            push(&mut argv, &req.process.cwd);
        }
        push(&mut argv, "--requesting-user");
        push(&mut argv, req.user);
        push(&mut argv, "--action");
        push(&mut argv, req.service);
    }

    let prog = match CString::new(HELPER_PATH) {
        Ok(c) => c,
        Err(_) => std::process::exit(1),
    };
    let _ = execv(&prog, &argv);
    // exec failed; signal DENY via the dup'd stdout pipe.
    let _ = nix::unistd::write(std::io::stdout(), b"DENY\n");
    std::process::exit(1);
}

fn read_pipe(fd: &OwnedFd, buf: &mut [u8]) -> nix::Result<usize> {
    nix::unistd::read(fd, buf)
}

/// `timeout = 0` in the config means "no auto-deny — wait for the user
/// as long as it takes". Mirror that on the parent's `poll(2)` side
/// with `PollTimeout::NONE`. Otherwise add `HELPER_GRACE_SECS` slack on
/// top of the helper's own auto-deny so the verdict can arrive even if
/// the helper's clock ticks slightly after ours.
fn parent_poll_timeout(timeout_secs: u32) -> PollTimeout {
    if timeout_secs == 0 {
        return PollTimeout::NONE;
    }
    let timeout_ms = (i32::try_from(timeout_secs).unwrap_or(30)
        + i32::try_from(HELPER_GRACE_SECS).unwrap_or(5))
        * 1000;
    PollTimeout::try_from(timeout_ms).unwrap_or(PollTimeout::MAX)
}

fn parent_wait(child: Pid, read_fd: OwnedFd, req: &HelperRequest<'_>) -> Result<Verdict, String> {
    let mut fds = [PollFd::new(read_fd.as_fd(), PollFlags::POLLIN)];

    let timeout = parent_poll_timeout(req.cfg.timeout);
    let n = match poll(&mut fds, timeout) {
        Ok(n) => n,
        Err(e) => {
            let _ = kill(child, Signal::SIGKILL);
            let _ = waitpid(child, None);
            return Err(format!("poll: {e}"));
        }
    };

    if n == 0 {
        let _ = kill(child, Signal::SIGKILL);
        let _ = waitpid(child, None);
        return Err("helper timeout".into());
    }

    // Longest legitimate verdict is "ALLOW REMEMBER\n" = 15 bytes; 16
    // holds it with the newline. Anything longer is malformed → parsed
    // as Deny below (fail-safe).
    let mut buf = [0u8; 16];
    let read_n = match read_pipe(&read_fd, &mut buf) {
        Ok(n) => n,
        Err(Errno::EINTR) => 0,
        Err(e) => {
            let _ = waitpid(child, None);
            return Err(format!("read: {e}"));
        }
    };

    let _ = waitpid(child, None);

    if read_n == 0 {
        return Err("helper produced no output".into());
    }

    let s = std::str::from_utf8(&buf[..read_n])
        .unwrap_or("")
        .split(['\n', '\r'])
        .next()
        .unwrap_or("");

    // Parse the wire verdict (outcome + remember opt-in). Anything
    // unrecognized maps to a bare `Deny` — the PAM caller treats
    // anything other than Allow as `PAM_AUTH_ERR`.
    Ok(s.parse::<Verdict>().unwrap_or(Verdict {
        outcome: Outcome::Deny,
        remember: false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_zero_yields_none() {
        // `timeout = 0` (no auto-deny) must NOT cap the parent's poll —
        // otherwise a long-open dialog gets killed at the grace window.
        assert_eq!(parent_poll_timeout(0), PollTimeout::NONE);
    }

    #[test]
    fn timeout_nonzero_adds_grace() {
        // 30s timeout + 5s grace = 35_000 ms.
        let pt = parent_poll_timeout(30);
        // PollTimeout doesn't expose its inner i32 directly, but
        // round-tripping through TryFrom gives us the comparison value.
        assert_eq!(pt, PollTimeout::try_from(35_000).unwrap());
    }

    #[test]
    fn timeout_overflow_falls_back_to_default_grace() {
        // u32::MAX doesn't fit in i32; the `try_from` fallback drops in
        // the 30s default + 5s grace = 35_000 ms rather than panicking.
        // (A nonsensical timeout in the config shouldn't crash the
        // module; quietly using a sane bound is the friendlier failure.)
        assert_eq!(
            parent_poll_timeout(u32::MAX),
            PollTimeout::try_from(35_000).unwrap()
        );
    }
}
