// SPDX-FileCopyrightText: 2025 Atay Özcan <atay@oezcan.me>
// SPDX-License-Identifier: GPL-3.0-or-later
//! Eagerly-populated snapshot of a process's `/proc/<pid>/*` data.
//!
//! Just a typed bundle around `sentinel_shared::procfs::*` lookups
//! with the unknown / empty defaults the dialog renderer expects.
//! New /proc readers go in `sentinel_shared::procfs`, not here.

use sentinel_shared::{procfs, strip_elevation_prefix};

/// The full command a remember grant should bind to, or `None` if this
/// request must never be remembered (empty, or an ineligible gateway — see
/// [`sentinel_shared::remember_eligible_command`], the denylist shared with
/// the polkit agent so both paths apply the same rule).
fn remember_command_for(cmd: &str) -> Option<String> {
    let cmd = cmd.trim();
    (!cmd.is_empty() && sentinel_shared::remember_eligible_command(cmd)).then(|| cmd.to_string())
}

pub struct ProcessInfo {
    pub name: String,
    pub exe: String,
    pub cmdline: String,
    pub cwd: String,
    /// Full command a terminal "remember" grant binds to (the elevated
    /// command, e.g. `pacman -Syu`), or `None` when this request is not
    /// rememberable: a bare-elevation root shell (`sudo -s`/`-i`/`-v`,
    /// `su`), an arbitrary-code gateway (see
    /// [`sentinel_shared::remember_eligible_command`]), or an empty
    /// cmdline. Binding the grant to the **whole** command — not
    /// just the program name — is what stops a grant for `pacman -Syu`
    /// from authorizing `pacman -U /tmp/evil`.
    pub remember_command: Option<String>,
    /// The program name `[policy]` allow/deny should match against, or
    /// `None` when there is no safe target to match. This equals `exe`
    /// for a normal process (Path 3) and for an elevation wrapper with a
    /// concrete target (Path 1, the elevated program). It is deliberately
    /// `None` for a **bare-elevation root shell** (`sudo -i`/`-s`/`-v`,
    /// `su`): there `exe` is the *originating* tool (e.g. `topgrade`,
    /// `paru`), NOT the elevated target, so matching a `[policy] allow`
    /// against it would passwordlessly grant a root shell to whatever
    /// launched sudo. `None` forces such requests to the dialog.
    pub policy_exe: Option<String>,
}

impl ProcessInfo {
    pub fn for_pid(pid: i32) -> Self {
        let raw_exe = procfs::read_exe(pid).unwrap_or_else(|| "unknown".into());
        let raw_cmdline = procfs::read_cmdline(pid).unwrap_or_default();

        // Resolve what to display. Three paths, in order:
        //
        // 1. The cmdline is `sudo X args…` (or pkexec/su/doas). Strip
        //    the elevation prefix and use the elevated program — the
        //    dialog says "pacman", not "sudo-rs".
        //
        // 2. The cmdline is just `sudo` with flags but NO target
        //    (e.g. `sudo -v` for credential caching, common in
        //    `topgrade` and `paru`). `strip_elevation_prefix` returns
        //    an empty string. Walk up to `PPid` and use the parent's
        //    exe/cmdline — the dialog shows the user-facing
        //    originator (`paru`, `topgrade`, the user's shell) rather
        //    than just `sudo-rs` which is uninformative.
        //
        // 3. Not an elevation tool at all (the PAM module loaded into
        //    something else). Use the binary's own /proc info as-is.
        let stripped = strip_elevation_prefix(&raw_cmdline);
        let was_elevation = !raw_cmdline.is_empty() && stripped != raw_cmdline;
        // `policy_exe` is the program `[policy]` may match: the elevated
        // target for Paths 1/3, and `None` for the Path-2 root shell (see
        // the field docs — matching the originator there is an escalation).
        let (exe, cmdline, remember_command, policy_exe) = if was_elevation && !stripped.is_empty()
        {
            // Path 1: elevation wrapper with a target. The remember grant
            // binds to the FULL elevated command, so `sudo pacman -Syu`
            // can't later authorize `sudo pacman -U /tmp/evil`.
            let target_exe = stripped
                .split_whitespace()
                .next()
                .unwrap_or("unknown")
                .to_string();
            let remember = remember_command_for(&stripped);
            let policy_exe = Some(target_exe.clone());
            (target_exe, stripped, remember, policy_exe)
        } else if was_elevation {
            // Path 2: elevation wrapper with NO target (`sudo -s`/`-i`/
            // `-v`, `su`). That's an interactive root shell / cred cache
            // — NEVER remembered (a grant would silently re-open root).
            // Display still walks up to the user-facing originator, but
            // `policy_exe` is None: the originator is NOT the elevated
            // target, so `[policy] allow` must not match it.
            let parent = procfs::read_ppid(pid).and_then(|ppid| {
                let pexe = procfs::read_exe(ppid)?;
                let pcmdline = procfs::read_cmdline(ppid).unwrap_or_default();
                Some((pexe, pcmdline))
            });
            match parent {
                Some((pexe, pcmdline)) => (pexe, pcmdline, None, None),
                None => (raw_exe, raw_cmdline, None, None),
            }
        } else {
            // Path 3: not an elevation tool. Remember binds to the
            // process's own full cmdline (still subject to the carve-out).
            let remember = remember_command_for(&raw_cmdline);
            let policy_exe = Some(raw_exe.clone());
            (raw_exe, raw_cmdline, remember, policy_exe)
        };

        Self {
            name: sentinel_shared::process_basename(&exe)
                .map(str::to_owned)
                .or_else(|| procfs::read_comm(pid))
                .unwrap_or_else(|| "unknown".into()),
            exe,
            cmdline,
            cwd: procfs::read_cwd(pid).unwrap_or_default(),
            remember_command,
            policy_exe,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The eligibility denylist itself is tested in `sentinel-shared`;
    // here we only cover the local trim/gate wrapper.
    #[test]
    fn remember_command_for_trims_and_gates() {
        assert_eq!(
            remember_command_for("  pacman -Syu "),
            Some("pacman -Syu".to_string())
        );
        assert_eq!(
            remember_command_for("systemctl restart foo"),
            Some("systemctl restart foo".to_string())
        );
        assert_eq!(remember_command_for(""), None);
        assert_eq!(remember_command_for("   "), None);
        assert_eq!(remember_command_for("bash"), None);
        assert_eq!(remember_command_for("sudo bash"), None);
    }
}
