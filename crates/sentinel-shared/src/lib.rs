// SPDX-FileCopyrightText: 2025 Atay Özcan <atay@oezcan.me>
// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared configuration schema for the Sentinel PAM module
//! (`pam-sentinel`) and the polkit authentication agent
//! (`sentinel-polkit-agent`).
//!
//! The on-disk format is TOML at `/etc/security/sentinel.conf`
//! (`SENTINEL_CONFIG_PATH`, baked at compile time by this crate's
//! `build.rs`). The file is root-owned and intentionally NOT
//! user-editable: a per-user override layer would defeat the whole
//! UAC contract by letting an unprivileged user lower their own
//! `timeout` to zero.
//!
//! # Public API
//!
//! - [`load`] — read the file, return the effective [`ServiceConfig`]
//!   for one PAM service. The hot path for both consumers.
//! - [`Document`] — full parsed view; lets the upcoming settings UI
//!   walk all sections without re-implementing the schema.
//! - [`format_message`] — `%u`/`%s`/`%p`/`%%` substitution for dialog
//!   message templates.
//!
//! # Failure handling
//!
//! `load` is infallible by design: missing-file falls back silently to
//! defaults; malformed-file falls back to defaults *and logs a WARN*.
//! That asymmetry is deliberate — you don't want a typo in the config
//! to silently revert your security settings without a trail in
//! `journalctl -t pam_sentinel` (or the agent's syslog identifier).

use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub mod audit;

/// UI-string localization for the KDE helper: keyed lookups for the
/// dialog's UI chrome, with English as the source/fallback.
pub mod ui_i18n;

/// CLI surface for the KDE helper frontend (`sentinel-helper-kde`).
/// Gated behind the `cli` feature so the PAM module and polkit agent —
/// which never parse these args — don't pull in `clap`.
#[cfg(feature = "cli")]
pub mod cli;

/// Compile-time absolute path to the system config file. Set by this
/// crate's `build.rs` from `$SENTINEL_SYSCONFDIR/security/sentinel.conf`.
pub const CONFIG_PATH: &str = env!("SENTINEL_CONFIG_PATH");

/// PAM service name polkit's `polkit-agent-helper-1` uses, and the
/// section the agent looks up (`[services."polkit-1"]`) in
/// `/etc/security/sentinel.conf`. Shared so the agent's
/// `BeginAuthentication` handler and `helper_ui::Request::for_action`
/// can't drift apart.
pub const POLKIT_PAM_SERVICE: &str = "polkit-1";

/// The bypass coordination channel is the **system D-Bus**, not a unix
/// socket. polkit 121+ forks `polkit-agent-helper-1` from polkitd, and on
/// SELinux systems (openSUSE Tumbleweed) the helper runs as `policykit_t`,
/// which is denied writing an arbitrary unix socket — but `policykit_t` is
/// already permitted `dbus send_msg` to user domains (it's how the polkit
/// agent protocol works, and how `pam_fprintd` authenticates). So the agent
/// exposes a tiny method here that the PAM module calls. This rides existing
/// SELinux/AppArmor permissions with no custom policy.
///
/// The user's agent claims [`AGENT_BUS_NAME`]; `pam_sentinel` (running as
/// root inside the helper) first checks the name's owner uid matches the user
/// being authenticated — defeating a same-name squatter — then calls
/// `TakeApproval` to consume a one-shot pre-approval.
pub const AGENT_BUS_NAME: &str = "org.sentinel.Agent";
/// Object path the bypass interface is published at.
pub const AGENT_OBJECT_PATH: &str = "/org/sentinel/Agent";
/// Interface name of the bypass service (same string as the bus name).
pub const AGENT_INTERFACE: &str = "org.sentinel.Agent";

/// Verdict the helper writes on stdout, parsed back by both the PAM
/// module's pipe reader and the polkit agent's child-process line
/// reader. The Display + FromStr impls are the *only* source of truth
/// for the wire format — keep this enum and those impls in sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Allow,
    Deny,
    Timeout,
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Allow => "ALLOW",
            Self::Deny => "DENY",
            Self::Timeout => "TIMEOUT",
        })
    }
}

/// `Err(())` for unrecognized input. Callers decide the policy: the
/// PAM module treats anything-not-Allow as `PAM_AUTH_ERR`; the agent
/// surfaces Timeout separately for logging.
impl std::str::FromStr for Outcome {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "ALLOW" => Ok(Self::Allow),
            "DENY" => Ok(Self::Deny),
            "TIMEOUT" => Ok(Self::Timeout),
            _ => Err(()),
        }
    }
}

impl Outcome {
    /// Process exit code matching the verdict: 0 for Allow (auth ok),
    /// 1 for Deny / Timeout (auth refused). The helper exits with this.
    pub fn exit_code(self) -> i32 {
        match self {
            Self::Allow => 0,
            Self::Deny | Self::Timeout => 1,
        }
    }

    pub fn is_allow(self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// The full verdict line the helper writes: an [`Outcome`] plus whether
/// the user ticked the "remember" checkbox.
///
/// Wire form (single line, whitespace-separated): the outcome token,
/// optionally followed by `REMEMBER`. e.g. `ALLOW`, `ALLOW REMEMBER`,
/// `DENY`. Old helpers that only write the bare outcome parse with
/// `remember = false`, so the format is backward-compatible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    pub outcome: Outcome,
    /// User opted into the remember window. Only meaningful with
    /// `Outcome::Allow`; ignored otherwise.
    pub remember: bool,
}

impl Verdict {
    /// Marker token appended after the outcome when the user opted in.
    pub const REMEMBER_TOKEN: &str = "REMEMBER";
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.outcome)?;
        if self.remember && self.outcome.is_allow() {
            write!(f, " {}", Self::REMEMBER_TOKEN)?;
        }
        Ok(())
    }
}

impl std::str::FromStr for Verdict {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut tokens = s.split_whitespace();
        let outcome = tokens.next().unwrap_or_default().parse::<Outcome>()?;
        let remember = tokens.any(|t| t == Self::REMEMBER_TOKEN);
        Ok(Self { outcome, remember })
    }
}

/// What to do when no Wayland display is reachable from the PAM call site.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HeadlessAction {
    /// Silently `PAM_SUCCESS`. Dangerous; only for tightly controlled boxes.
    Allow,
    /// `PAM_AUTH_ERR`. Caller (sudo, polkit) sees a hard fail.
    Deny,
    /// `PAM_IGNORE`. Next module in the stack runs (typically pam_unix
    /// → password prompt). Default.
    #[default]
    Password,
}

/// Top-level parsed config. Public so the settings UI can walk it.
#[derive(Debug, Clone, Deserialize)]
pub struct Document {
    #[serde(default)]
    pub general: General,
    #[serde(default)]
    pub appearance: Appearance,
    #[serde(default)]
    pub audio: Audio,
    #[serde(default)]
    pub services: HashMap<String, ServiceOverride>,
    #[serde(default)]
    pub policy: Policy,
    #[serde(default)]
    pub notifications: Notifications,
}

/// Desktop-notification settings (`[notifications]`). The agent posts a
/// notification on the polkit/GUI auth path; terminal `sudo`/`su`
/// denials are already visible in the terminal, so they're not covered.
/// Both default off.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Notifications {
    #[serde(default)]
    pub on_deny: bool,
    #[serde(default)]
    pub on_timeout: bool,
}

/// Best-effort desktop notification via `notify-send` (libnotify). No-op
/// if `notify-send` isn't installed or the spawn fails — never blocks or
/// errors the auth path. Must be called from a process in the user's
/// session (the agent), not the root PAM module.
pub fn desktop_notify(summary: &str, body: &str) {
    let _ = std::process::Command::new("notify-send")
        .args([
            "--app-name=Sentinel",
            "--icon=system-lock-screen",
            "--urgency=normal",
        ])
        .arg(summary)
        .arg(body)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

#[derive(Debug, Clone, Deserialize)]
pub struct General {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_timeout")]
    pub timeout: u32,
    #[serde(default = "default_true")]
    pub randomize_buttons: bool,
    #[serde(default)]
    pub headless_action: HeadlessAction,
    #[serde(default = "default_true")]
    pub show_process_info: bool,
    #[serde(default = "default_true")]
    pub log_attempts: bool,
    #[serde(default = "default_min_display_time")]
    pub min_display_time_ms: u32,
    /// "Remember" window in seconds for the **polkit/GUI** auth path:
    /// after an Allow with the checkbox ticked, repeat requests from the
    /// same session for the same action+binary auto-allow without a
    /// dialog for this long. Defaults to `300` (5 min), so the dialog
    /// shows the opt-in checkbox by default; `0` hides it / disables the
    /// feature on the GUI path. Hard-capped at 900s regardless of value.
    ///
    /// This is the base value for the `polkit-1` service only. The
    /// terminal `sudo`/`su` paths default to **off** regardless of this
    /// value and must be opted in per-service via
    /// `[services.<name>].remember_seconds` — see [`Document::for_service`]
    /// and the timestamp store in `pam-sentinel` for the security model.
    #[serde(default = "default_remember_seconds")]
    pub remember_seconds: u32,
    /// Granularity of a remember grant — see [`RememberScope`]. The
    /// default (`"command"`) binds the grant to the full elevated
    /// command; `"program"` binds it to the program only, so one tick
    /// covers different invocations of the same tool (e.g. topgrade's
    /// `zypper refresh` + `zypper dist-upgrade`). Program scope trades
    /// away the argv binding — opt in knowingly.
    #[serde(default)]
    pub remember_scope: RememberScope,
}

impl Default for General {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout: default_timeout(),
            randomize_buttons: true,
            headless_action: HeadlessAction::default(),
            show_process_info: true,
            log_attempts: true,
            min_display_time_ms: default_min_display_time(),
            remember_seconds: default_remember_seconds(),
            remember_scope: RememberScope::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Appearance {
    #[serde(default = "default_title")]
    pub title: String,
    #[serde(default = "default_message")]
    pub message: String,
    #[serde(default = "default_secondary")]
    pub secondary: String,
}

/// UAC-style audio cue when the dialog appears. Optional; respects
/// the freedesktop sound naming spec (so the user's
/// system theme controls the actual sample).
#[derive(Debug, Clone, Deserialize)]
pub struct Audio {
    /// Freedesktop sound name (NOT a file path) played when the
    /// dialog appears. Empty string = silent. Common names:
    /// `dialog-warning`, `bell`, `message`, `dialog-question`.
    /// See <https://specifications.freedesktop.org/sound-naming-spec/>.
    #[serde(default = "default_sound_name")]
    pub sound_name: String,
}

impl Default for Audio {
    fn default() -> Self {
        Self {
            sound_name: default_sound_name(),
        }
    }
}

fn default_sound_name() -> String {
    "dialog-warning".to_string()
}

impl Default for Appearance {
    fn default() -> Self {
        Self {
            title: default_title(),
            message: default_message(),
            secondary: default_secondary(),
        }
    }
}

/// Per-service override block (`[services.<name>]`). Any `None` field
/// inherits its base value (see [`Document::for_service`]).
///
/// `deny_unknown_fields` makes a typo'd key (e.g. `ramdomize`) a loud
/// parse error — logged, fail-soft to defaults — rather than a silently
/// dropped override. This matters most for `remember_seconds`, a
/// security knob: a silently-ignored `remember_seconds = 0` would be a
/// footgun.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceOverride {
    pub enabled: Option<bool>,
    pub timeout: Option<u32>,
    pub randomize: Option<bool>,
    /// Per-service "remember" window in seconds. `None` (the default)
    /// inherits the base value from [`Document::for_service`]: the
    /// `polkit-1` GUI path inherits `[general].remember_seconds`, while
    /// terminal paths (`sudo`/`su`/…) and unknown services default to
    /// `0` (off). Set a non-zero value to opt a terminal service into
    /// the remember window, or `0` to force a service off. Hard-capped
    /// at 900s downstream.
    pub remember_seconds: Option<u32>,
    /// Per-service override of `[general].remember_scope` — see
    /// [`RememberScope`]. `None` inherits the general value.
    pub remember_scope: Option<RememberScope>,
}

/// What a [`Policy`] match resolves to for a given request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Short-circuit to allow without showing a dialog.
    Allow,
    /// Short-circuit to deny without showing a dialog.
    Deny,
    /// No policy match — fall through to the normal dialog flow.
    Ask,
}

/// Static allow/deny policy (`[policy]`), evaluated *before* the dialog.
///
/// Entries match against:
/// - the requesting executable's **resolved path** (`/proc/<pid>/exe`,
///   e.g. `/usr/bin/pacman`) — NOT the spoofable `argv[0]`;
/// - that path's **basename** when the entry contains no `/`
///   (e.g. `pacman`); or
/// - the **polkit action id** on the agent path
///   (e.g. `org.freedesktop.color-manager.create-profile`).
///
/// `deny` takes precedence over `allow` (fail-safe). An empty policy
/// (the default) never matches, so behaviour is unchanged until an
/// admin opts in.
///
/// # Security
///
/// An `allow` entry means **passwordless elevation** for that target —
/// it is exactly as load-bearing as a `sudoers` `NOPASSWD` line. Prefer
/// absolute paths over basenames, and keep the list short.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

impl Policy {
    /// Decide an outcome for a request identified by its resolved exe
    /// path (always available) and optional polkit action id (agent
    /// path only). `deny` wins over `allow`.
    pub fn decide(&self, exe: Option<&str>, action: Option<&str>) -> PolicyDecision {
        if Self::list_matches(&self.deny, exe, action) {
            PolicyDecision::Deny
        } else if Self::list_matches(&self.allow, exe, action) {
            PolicyDecision::Allow
        } else {
            PolicyDecision::Ask
        }
    }

    fn list_matches(list: &[String], exe: Option<&str>, action: Option<&str>) -> bool {
        list.iter().any(|entry| {
            // Exact polkit action id.
            if action == Some(entry.as_str()) {
                return true;
            }
            match exe {
                Some(path) => {
                    if entry.contains('/') {
                        // Absolute/relative path: full-path match only.
                        entry == path
                    } else {
                        // Bare name: match the exe's basename.
                        process_basename(path) == Some(entry.as_str())
                    }
                }
                None => false,
            }
        })
    }
}

/// Effective config for a single PAM service after applying overrides
/// on top of `[general]` + `[appearance]` + `[audio]`. This is what
/// consumers actually drive the dialog with.
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    pub enabled: bool,
    pub timeout: u32,
    pub randomize_buttons: bool,
    pub headless_action: HeadlessAction,
    pub show_process_info: bool,
    pub log_attempts: bool,
    pub min_display_time_ms: u32,
    pub title: String,
    pub message: String,
    pub secondary: String,
    /// Mirrors `[audio].sound_name`. Carried on ServiceConfig so
    /// consumers don't need a second config read; the value isn't
    /// per-service overridable (audio is a global UX choice).
    pub sound_name: String,
    /// Static allow/deny policy from `[policy]`, evaluated before the
    /// dialog. Not per-service overridable.
    pub policy: Policy,
    /// Post a desktop notification when this request is denied
    /// (`[notifications].on_deny`). Agent/polkit path only.
    pub notify_on_deny: bool,
    /// Post a desktop notification when this request times out
    /// (`[notifications].on_timeout`).
    pub notify_on_timeout: bool,
    /// Effective auto-allow "remember" window in seconds (0 = off).
    /// Resolved by [`Document::for_service`]: the `polkit-1` GUI path
    /// inherits `[general].remember_seconds`; terminal paths default to
    /// `0` unless opted in via `[services.<name>].remember_seconds`.
    pub remember_seconds: u32,
    /// Granularity of a remember grant (`[general].remember_scope`,
    /// per-service overridable). See [`RememberScope`].
    pub remember_scope: RememberScope,
}

impl Document {
    pub fn defaults() -> Self {
        Self {
            general: General::default(),
            appearance: Appearance::default(),
            audio: Audio::default(),
            services: HashMap::new(),
            policy: Policy::default(),
            notifications: Notifications::default(),
        }
    }

    /// Compute the effective [`ServiceConfig`] for a PAM service name
    /// (e.g. `"sudo"`, `"polkit-1"`). Unknown service names fall through
    /// to plain `[general]` + `[appearance]` defaults.
    pub fn for_service(&self, service: &str) -> ServiceConfig {
        let mut cfg = ServiceConfig {
            enabled: self.general.enabled,
            timeout: self.general.timeout,
            randomize_buttons: self.general.randomize_buttons,
            headless_action: self.general.headless_action,
            show_process_info: self.general.show_process_info,
            log_attempts: self.general.log_attempts,
            min_display_time_ms: self.general.min_display_time_ms,
            title: self.appearance.title.clone(),
            message: self.appearance.message.clone(),
            secondary: self.appearance.secondary.clone(),
            sound_name: self.audio.sound_name.clone(),
            policy: self.policy.clone(),
            notify_on_deny: self.notifications.on_deny,
            notify_on_timeout: self.notifications.on_timeout,
            // The remember window is GUI-path-only by default: the
            // `polkit-1` service inherits `[general].remember_seconds`
            // (default 300), while terminal services (sudo/su/…) and
            // unknown services default to 0 (off). This keeps the
            // dangerous root-owned terminal timestamp store off by
            // default while the in-memory GUI cache defaults on; terminal
            // services opt in explicitly via the per-service override
            // below. See the security review for issue #22.
            remember_seconds: if service == POLKIT_PAM_SERVICE {
                self.general.remember_seconds
            } else {
                0
            },
            remember_scope: self.general.remember_scope,
        };
        if let Some(over) = self.services.get(service) {
            if let Some(v) = over.enabled {
                cfg.enabled = v;
            }
            if let Some(v) = over.timeout {
                cfg.timeout = v;
            }
            if let Some(v) = over.randomize {
                cfg.randomize_buttons = v;
            }
            if let Some(v) = over.remember_seconds {
                cfg.remember_seconds = v;
            }
            if let Some(v) = over.remember_scope {
                cfg.remember_scope = v;
            }
        }
        cfg
    }

    /// Read + parse the system config file. Falls back to defaults on
    /// any error; logs a warning on parse failure (silent only on
    /// missing file).
    pub fn load() -> Self {
        Self::load_from(Path::new(CONFIG_PATH))
    }

    /// Read + parse a specific path. Same fail-soft semantics as
    /// [`Document::load`]; intended for the settings app reading from a
    /// staging location, or for tests.
    pub fn load_from(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(contents) => match toml::from_str::<Document>(&contents) {
                Ok(parsed) => parsed,
                Err(e) => {
                    log::warn!(
                        "sentinel-shared: failed to parse {}: {e} — falling back to defaults",
                        path.display()
                    );
                    Document::defaults()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                log::debug!(
                    "sentinel-shared: {} not present — using defaults",
                    path.display()
                );
                Document::defaults()
            }
            Err(e) => {
                log::warn!(
                    "sentinel-shared: cannot read {}: {e} — using defaults",
                    path.display()
                );
                Document::defaults()
            }
        }
    }
}

/// Convenience: parse the system config and return the effective
/// per-service config in one call. The hot path used by both
/// `pam_sentinel.so` and `sentinel-polkit-agent`.
pub fn load(service: &str) -> ServiceConfig {
    Document::load().for_service(service)
}

/// Where the system config file lives at runtime. Useful for the
/// settings UI ("save to PathBuf").
pub fn config_path() -> PathBuf {
    PathBuf::from(CONFIG_PATH)
}

/// Substitute `%u` (user), `%s` (service), `%p` (process), and `%%`
/// (literal `%`) into a template. Unknown `%x` sequences are preserved
/// verbatim so a typo is visible to the admin in the rendered dialog
/// rather than silently dropped.
pub fn format_message(template: &str, user: &str, service: &str, process: &str) -> String {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('u') => out.push_str(user),
            Some('s') => out.push_str(service),
            Some('p') => out.push_str(process),
            Some('%') => out.push('%'),
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
    out
}

// Default appearance strings, exposed as `pub const` so the helper can
// detect "this is still the built-in default, translate it" vs "admin
// customized this, use as-is". If you change a const here, update the
// matching default translations in the KDE helper's `ui_i18n` module.
pub const DEFAULT_TITLE: &str = "Authentication Required";
pub const DEFAULT_MESSAGE: &str = "The application \"%p\" is requesting elevated privileges.";
/// Empty by default. The original 0.5.x default named the buttons
/// ("Click Allow… or Deny…"), which created a left-button-bias when
/// `randomize_buttons = true` swapped the order. Admins who want a
/// hint line can set `secondary = "..."` in `/etc/security/sentinel.conf`;
/// the helper renders it verbatim and skips the row when empty.
pub const DEFAULT_SECONDARY: &str = "";

/// Recognised elevation-tool basenames. When the requesting process's
/// argv[0] matches one of these, we strip the elevation prefix from
/// the cmdline so the dialog shows the user-facing target instead of
/// the elevation tool itself.
///
/// Both pkexec (used by polkit-agent) and sudo / su / doas (used by
/// the PAM module's sudo path) hide the user's actual command behind
/// their own argv[0]. Without this stripping, every `sudo foo` shows
/// "sudo-rs" or "sudo" in the dialog, useless for confirmation.
pub const ELEVATION_TOOLS: &[&str] = &["pkexec", "sudo", "sudo-rs", "su", "doas"];

/// Flags shared across elevation tools that take a single value as
/// the next argv slot. `strip_elevation_prefix` skips both the flag
/// and its value when it sees one of these.
const ELEVATION_FLAGS_WITH_VALUE: &[&str] = &[
    // pkexec
    "--user",
    "-u",
    // sudo (--user/-u shared)
    "--group",
    "-g",
    "--host",
    "-h",
    "--chdir",
    "-D",
    "--prompt",
    "-p",
    "--command-timeout",
    "-T",
    "--close-from",
    "-C",
    "--type",
    "-t",
    "--role",
    "-r",
    "--other-user",
    "-U",
    "--chroot",
    "-R",
];

/// Strip an elevation tool's `argv[0]` and any of its option flags
/// from a `/proc/<pid>/cmdline` reading, leaving the elevated
/// command. Returns the joined remainder (whitespace-separated,
/// matching what `procfs::read_cmdline` produces). Empty if nothing
/// remains (e.g. `sudo -i` with no command).
///
/// `argv[0]` matching is by basename (so `/usr/bin/sudo-rs` and
/// `sudo-rs` both qualify), against [`ELEVATION_TOOLS`].
///
/// Examples:
///   "sudo true"                           → "true"
///   "sudo-rs systemctl restart foo"       → "systemctl restart foo"
///   "sudo -u root /bin/sh"                → "/bin/sh"
///   "sudo -E -u root systemctl x"         → "systemctl x"
///   "pkexec --user root /usr/bin/cat /e"  → "/usr/bin/cat /e"
///   "ls -la"                              → "ls -la"   (not an elevation tool)
///   "sudo -i"                             → ""         (no command)
pub fn strip_elevation_prefix(cmdline: &str) -> String {
    let parts: Vec<&str> = cmdline.split_whitespace().collect();
    let Some(first) = parts.first() else {
        return String::new();
    };
    let basename = process_basename(first).unwrap_or(first);
    if !ELEVATION_TOOLS.contains(&basename) {
        // Not an elevation tool — pass through unchanged.
        return cmdline.to_string();
    }
    let mut i = 1; // skip argv[0]
    while i < parts.len() {
        let p = parts[i];
        if ELEVATION_FLAGS_WITH_VALUE.contains(&p) {
            i += 2;
        } else if p.starts_with('-') {
            // Standalone flag (-i, -s, -E, -n, -v, -l, -K, ...) or
            // `--user=root`-style. Skip one slot.
            i += 1;
        } else {
            break;
        }
    }
    if i >= parts.len() {
        String::new()
    } else {
        parts[i..].join(" ")
    }
}

/// Basename of an executable path, suitable for `%p` substitution
/// in dialog messages and for icon-theme lookup. Returns `None` for
/// paths with no file component or non-UTF-8 names. Does not borrow
/// the input as a Path (to keep the lifetime story trivial for
/// caller chains like `Option::and_then`).
pub fn process_basename(exe: &str) -> Option<&str> {
    std::path::Path::new(exe)
        .file_name()
        .and_then(|s| s.to_str())
}

/// Programs whose whole job is to run *other* code as the elevated user —
/// interactive shells, language interpreters, nested elevation wrappers,
/// and common shell-escapers (editors / pagers / tools that can spawn a
/// shell). Excluded from the "remember" window on **both** auth paths:
/// even with full-command binding, a grant for one of them re-opens an
/// arbitrary-code root session on a verbatim repeat (`pkexec bash` again,
/// `sudo vim` then `:!sh`, …). Erring toward re-prompting is safe; the
/// cost of over-excluding is just an extra dialog.
///
/// Deliberately conservative and **non-exhaustive** (a complete
/// GTFOBins-style list is a policy concern). The primary bound is
/// full-command binding; this closes the most obvious gateways on top.
pub const REMEMBER_INELIGIBLE: &[&str] = &[
    // shells
    "sh", "bash", "dash", "zsh", "fish", "ksh", "tcsh", "csh", "ash", "busybox", //
    // interpreters
    "python", "python2", "python3", "perl", "ruby", "node", "nodejs", "lua", "php", "gdb", "tclsh",
    "expect", //
    // nested elevation / arg-runners
    "su", "sudo", "sudo-rs", "doas", "pkexec", "run0", "env", //
    // common shell-escapers (editors / pagers / tools)
    "vi", "vim", "nvim", "view", "emacs", "nano", "less", "more", "man", "ed", "awk", "find",
];

/// Whether a full command is eligible for a "remember" grant. False when
/// the leading program (by basename) is in [`REMEMBER_INELIGIBLE`], or the
/// command is empty/whitespace. Shared by the polkit agent and the PAM
/// module so both paths apply the *same* rule. The grant itself is keyed
/// by the **full** command (args included) by each caller, so this only
/// gates *which programs* may be remembered, not the granularity.
pub fn remember_eligible_command(cmd: &str) -> bool {
    let Some(first) = cmd.split_whitespace().next() else {
        return false;
    };
    let base = process_basename(first).unwrap_or(first);
    !REMEMBER_INELIGIBLE.contains(&base)
}

/// Granularity of a "remember" grant (`remember_scope` in the config).
///
/// `Command` (the default) binds the grant to the **full** elevated
/// command, args included — a grant for `pacman -Syu` never covers
/// `pacman -U /tmp/evil`. `Program` binds it to the leading program
/// token only, so one tick covers *any* invocation of that program for
/// the window (topgrade's `zypper refresh` + `zypper dist-upgrade`
/// become one prompt). Program scope deliberately gives up the argv
/// binding; [`REMEMBER_INELIGIBLE`] still applies either way, and the
/// grant stays bound to the login session and service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RememberScope {
    #[default]
    Command,
    Program,
}

/// The command string a remember grant is keyed on, per `scope`. Callers
/// pass an eligibility-vetted full command ([`remember_eligible_command`]);
/// this only narrows it for [`RememberScope::Program`]. The token is used
/// verbatim (no basename normalization): `/usr/bin/zypper` and `zypper`
/// are distinct keys, which errs toward re-prompting.
pub fn remember_key_command(command: &str, scope: RememberScope) -> &str {
    match scope {
        RememberScope::Command => command.trim(),
        RememberScope::Program => command.split_whitespace().next().unwrap_or(""),
    }
}

/// Generic shield icon shown when the requesting binary's basename has
/// no icon-theme match. Present in every standard freedesktop theme
/// (Breeze, Adwaita, Pop, …). Frontends use this as the fallback name.
pub const FALLBACK_ICON_NAME: &str = "system-lock-screen";

/// Icon-theme name to display for a requesting executable: the exe's
/// basename (e.g. `/usr/bin/firefox` → `firefox`). `None` when there's
/// no exe to derive a name from. The helper applies its own theme
/// fallback ([`FALLBACK_ICON_NAME`]) when the name doesn't resolve.
pub fn resolve_icon_name(process_exe: Option<&str>) -> Option<String> {
    process_exe.and_then(process_basename).map(str::to_string)
}

/// systemd-logind session/user metadata, read from the plain
/// `KEY=value` files under `/run/systemd/sessions/<id>` and
/// `/run/systemd/users/<uid>`.
///
/// systemd warns "do not parse" in those files because the schema
/// isn't formally stable, but the relevant keys (`STATE`, `TYPE`,
/// `CLASS`, `REMOTE`, `TTY`) have been stable for over a decade
/// and are exactly what `loginctl show-session` exposes too. The
/// parser here is defensive: unknown keys are ignored, missing
/// values become `None`, malformed lines are skipped.
///
/// We avoid the D-Bus path (which would force async + zbus into the
/// PAM module) and we avoid the libsystemd C dependency.
pub mod logind {
    use std::collections::HashMap;

    /// What we surface from `/run/systemd/sessions/<id>`. Values are
    /// the verbatim systemd strings (e.g. `kind = Some("wayland")`,
    /// `class = Some("user")`).
    #[derive(Debug, Default, Clone)]
    pub struct SessionInfo {
        pub state: Option<String>,
        pub kind: Option<String>,
        pub class: Option<String>,
        pub remote: Option<bool>,
        pub tty: Option<String>,
    }

    pub fn session_info(session_id: &str) -> Option<SessionInfo> {
        if !is_safe_session_id(session_id) {
            return None;
        }
        let path = format!("/run/systemd/sessions/{session_id}");
        let raw = std::fs::read_to_string(&path).ok()?;
        let kv = parse_kv(&raw);
        Some(SessionInfo {
            state: kv.get("STATE").cloned(),
            kind: kv.get("TYPE").cloned(),
            class: kv.get("CLASS").cloned(),
            remote: kv.get("REMOTE").map(|v| v == "1"),
            tty: kv.get("TTY").cloned(),
        })
    }

    /// `session_id` is normally a small integer like "1" / "2" but
    /// can be a string in some seat configurations. Whitelist what
    /// we'll use as a path component.
    fn is_safe_session_id(s: &str) -> bool {
        !s.is_empty() && s.len() <= 16 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    }

    fn parse_kv(s: &str) -> HashMap<String, String> {
        s.lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .filter_map(|l| {
                let (k, v) = l.split_once('=')?;
                Some((k.to_string(), v.to_string()))
            })
            .collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parse_kv_ignores_comments_and_blanks() {
            let raw = "# header\nFOO=bar\n\nBAZ=qux\n# tail";
            let kv = parse_kv(raw);
            assert_eq!(kv.get("FOO"), Some(&"bar".to_string()));
            assert_eq!(kv.get("BAZ"), Some(&"qux".to_string()));
            assert_eq!(kv.len(), 2);
        }

        #[test]
        fn parse_kv_handles_values_with_equals() {
            // `=` after the first one belongs to the value.
            let kv = parse_kv("KEY=a=b=c");
            assert_eq!(kv.get("KEY"), Some(&"a=b=c".to_string()));
        }

        #[test]
        fn safe_session_id_accepts_typical() {
            assert!(is_safe_session_id("1"));
            assert!(is_safe_session_id("42"));
            assert!(is_safe_session_id("c1"));
            assert!(is_safe_session_id("session-1"));
        }

        #[test]
        fn safe_session_id_rejects_path_traversal_and_garbage() {
            assert!(!is_safe_session_id(""));
            assert!(!is_safe_session_id("../etc/shadow"));
            assert!(!is_safe_session_id("1/../foo"));
            assert!(!is_safe_session_id(&"x".repeat(17)));
            assert!(!is_safe_session_id("a b"));
        }
    }
}

/// Best-effort `/proc/<pid>/*` readers shared by the PAM module and
/// the polkit agent. Each function returns `None` on any error
/// (missing pid, permission denied, decode failure) — these are
/// diagnostic lookups whose absence is acceptable, not security
/// checks.
pub mod procfs {
    /// `/proc/<pid>/comm` — the kernel-tracked process name (15 chars
    /// max + NUL, kernel-truncated if longer). Trailing newline is
    /// stripped.
    pub fn read_comm(pid: i32) -> Option<String> {
        if pid <= 0 {
            return None;
        }
        std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .ok()
            .map(|s| s.trim().to_owned())
    }

    /// `/proc/<pid>/status` PPid line — parent process id. Used by the
    /// PAM module to walk up from a sudo/su/pkexec wrapper that has
    /// no explicit elevated command (e.g. `sudo -v` for credential
    /// caching, common pattern in `topgrade` / `paru`) so the dialog
    /// can show the user-facing originator instead of "sudo".
    pub fn read_ppid(pid: i32) -> Option<i32> {
        if pid <= 0 {
            return None;
        }
        let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        for line in s.lines() {
            if let Some(rest) = line.strip_prefix("PPid:") {
                return rest.trim().parse::<i32>().ok();
            }
        }
        None
    }

    /// `/proc/<pid>/exe` — readlink of the absolute path to the
    /// running binary. Returns `None` if the link is unreadable
    /// (e.g. `PR_SET_DUMPABLE=0` cross-uid).
    pub fn read_exe(pid: i32) -> Option<String> {
        if pid <= 0 {
            return None;
        }
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .and_then(|p| p.into_os_string().into_string().ok())
    }

    /// `/proc/<pid>/cwd` — readlink of the process's current working
    /// directory.
    pub fn read_cwd(pid: i32) -> Option<String> {
        if pid <= 0 {
            return None;
        }
        std::fs::read_link(format!("/proc/{pid}/cwd"))
            .ok()
            .and_then(|p| p.into_os_string().into_string().ok())
    }

    /// `/proc/<pid>/cmdline` — NUL-separated argv joined into a
    /// shell-printable single line. Returns `None` for kernel threads
    /// and processes with empty cmdlines.
    pub fn read_cmdline(pid: i32) -> Option<String> {
        if pid <= 0 {
            return None;
        }
        let bytes = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
        let parts: Vec<String> = bytes
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();
        if parts.is_empty() {
            None
        } else {
            Some(parts.join(" "))
        }
    }

    /// Look up a single environment variable from
    /// `/proc/<pid>/environ` (NUL-separated `KEY=value` entries).
    /// Used by the PAM module to recover values like `XDG_SESSION_ID`
    /// from the requesting process — the privileged binary that
    /// dlopened us scrubbed its own copy.
    ///
    /// Caller must validate the returned string before using it as a
    /// path component or shell argument — `/proc/<pid>/environ` is
    /// user-controlled.
    pub fn read_environ_var(pid: i32, key: &str) -> Option<String> {
        if pid <= 0 {
            return None;
        }
        let bytes = std::fs::read(format!("/proc/{pid}/environ")).ok()?;
        for entry in bytes.split(|b| *b == 0) {
            if entry.is_empty() {
                continue;
            }
            let Ok(s) = std::str::from_utf8(entry) else {
                continue;
            };
            let Some((k, v)) = s.split_once('=') else {
                continue;
            };
            if k == key {
                return Some(v.to_string());
            }
        }
        None
    }
}

/// Compose a logfmt fragment with logind session metadata for a
/// given pid. Returns either an empty string (no XDG_SESSION_ID,
/// no logind session file, or any read error) or a leading-space
/// string like ` session_type=wayland session_class=user
/// session_remote=0` ready to append to an existing log line.
///
/// Used by both `pam-sentinel` and `sentinel-polkit-agent` to
/// enrich `event=auth.*` lines with the session context, so
/// `journalctl ... | grep session_remote=1` finds remote
/// escalations across the whole system.
pub fn logfmt_session_for_pid(pid: i32) -> String {
    use std::fmt::Write;
    let Some(sid) = procfs::read_environ_var(pid, "XDG_SESSION_ID") else {
        return String::new();
    };
    let Some(info) = logind::session_info(&sid) else {
        return String::new();
    };
    let mut out = String::new();
    if let Some(t) = info.kind {
        let _ = write!(out, " session_type={}", log_kv::quote(&t));
    }
    if let Some(c) = info.class {
        let _ = write!(out, " session_class={}", log_kv::quote(&c));
    }
    if let Some(r) = info.remote {
        let _ = write!(out, " session_remote={}", if r { 1 } else { 0 });
    }
    out
}

/// Logfmt-style helpers for structured audit log lines.
///
/// We intentionally don't pull in a logfmt crate — the format is
/// trivial and the helper is two functions. The output goes to
/// syslog via the existing `log::info!` etc. calls, lands in the
/// systemd journal, and is queryable with `journalctl -t pam_sentinel
/// -t sentinel-polkit-agent --output=json` (the line ends up in the
/// `MESSAGE` field; downstream tooling can split on whitespace +
/// `key=value`).
///
/// # Convention
///
/// Auth-outcome events use `event=auth.{allow,deny,timeout,error}`
/// plus a `source=` discriminator (`dialog` / `bypass` / `headless` /
/// `agent` / `agent.bypass`). Diagnostic messages stay unstructured.
pub mod log_kv {
    /// Quote a value for logfmt: bare token if it contains no
    /// whitespace / `"` / `=`, otherwise wrapped in double quotes
    /// with internal `"` and `\` escaped. Empty values become `""`
    /// so they're visually distinguishable from missing keys.
    pub fn quote(value: &str) -> String {
        if value.is_empty() {
            return "\"\"".into();
        }
        let needs_quoting = value
            .chars()
            .any(|c| c.is_whitespace() || c == '"' || c == '=');
        if !needs_quoting {
            return value.to_string();
        }
        let mut out = String::with_capacity(value.len() + 2);
        out.push('"');
        for c in value.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                _ => out.push(c),
            }
        }
        out.push('"');
        out
    }
}

fn default_true() -> bool {
    true
}
fn default_timeout() -> u32 {
    30
}
fn default_min_display_time() -> u32 {
    500
}
/// Default "remember" window for the polkit/GUI path (5 min, `sudo`
/// `timestamp_timeout` parity, well under the 900s hard cap). Referenced
/// by both the `#[serde(default = ...)]` on [`General::remember_seconds`]
/// and [`General::default`] so the two default paths cannot diverge — a
/// bare `#[serde(default)]` would resolve to `u32::default() == 0`
/// whenever `[general]` is present but the key is absent (the shipped
/// state), silently defeating the default-on behaviour.
fn default_remember_seconds() -> u32 {
    300
}
fn default_title() -> String {
    DEFAULT_TITLE.into()
}
fn default_message() -> String {
    DEFAULT_MESSAGE.into()
}
fn default_secondary() -> String {
    DEFAULT_SECONDARY.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Policy -----------------------------------------------------------

    fn policy(allow: &[&str], deny: &[&str]) -> Policy {
        Policy {
            allow: allow.iter().map(|s| s.to_string()).collect(),
            deny: deny.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn policy_empty_always_asks() {
        let p = Policy::default();
        assert_eq!(p.decide(Some("/usr/bin/pacman"), None), PolicyDecision::Ask);
        assert_eq!(
            p.decide(Some("/usr/bin/x"), Some("org.example.act")),
            PolicyDecision::Ask
        );
    }

    #[test]
    fn policy_allow_matches_basename_and_full_path() {
        let p = policy(&["pacman", "/usr/bin/topgrade"], &[]);
        assert_eq!(
            p.decide(Some("/usr/bin/pacman"), None),
            PolicyDecision::Allow
        );
        assert_eq!(
            p.decide(Some("/usr/bin/topgrade"), None),
            PolicyDecision::Allow
        );
        // basename entry must not match a different path's basename
        assert_eq!(
            p.decide(Some("/opt/evil/pacman"), None),
            PolicyDecision::Allow
        );
        // full-path entry must not match by basename alone
        assert_eq!(p.decide(Some("/opt/topgrade"), None), PolicyDecision::Ask);
    }

    #[test]
    fn policy_deny_wins_over_allow() {
        let p = policy(&["pacman"], &["pacman"]);
        assert_eq!(
            p.decide(Some("/usr/bin/pacman"), None),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn policy_matches_polkit_action_id() {
        let p = policy(&["org.freedesktop.policykit.exec"], &[]);
        assert_eq!(
            p.decide(
                Some("/usr/bin/pkexec"),
                Some("org.freedesktop.policykit.exec")
            ),
            PolicyDecision::Allow
        );
        // action-only entry, no exe match
        assert_eq!(p.decide(Some("/usr/bin/other"), None), PolicyDecision::Ask);
    }

    #[test]
    fn policy_parses_from_toml() {
        let doc: Document = toml::from_str(
            r#"
            [policy]
            allow = ["pacman", "/usr/bin/topgrade"]
            deny = ["org.freedesktop.systemd1.manage-units"]
            "#,
        )
        .unwrap();
        assert_eq!(doc.policy.allow.len(), 2);
        assert_eq!(
            doc.policy
                .decide(None, Some("org.freedesktop.systemd1.manage-units")),
            PolicyDecision::Deny
        );
    }

    // ---- format_message ---------------------------------------------------

    #[test]
    fn format_message_substitutes_all_tokens() {
        let out = format_message("%u %s %p", "alice", "sudo", "/usr/bin/cat");
        assert_eq!(out, "alice sudo /usr/bin/cat");
    }

    #[test]
    fn format_message_handles_literal_percent() {
        let out = format_message("100%% done by %u", "alice", "sudo", "cat");
        assert_eq!(out, "100% done by alice");
    }

    #[test]
    fn format_message_preserves_unknown_tokens() {
        // Unknown %x — neither a known token nor an escape — stays as-is so
        // admins see their typo rather than silently losing characters.
        let out = format_message("%x %u", "alice", "sudo", "cat");
        assert_eq!(out, "%x alice");
    }

    #[test]
    fn format_message_trailing_percent_is_kept() {
        let out = format_message("hello %", "u", "s", "p");
        assert_eq!(out, "hello %");
    }

    #[test]
    fn format_message_empty_template() {
        assert_eq!(format_message("", "u", "s", "p"), "");
    }

    #[test]
    fn format_message_no_substitutions() {
        assert_eq!(format_message("plain text", "u", "s", "p"), "plain text");
    }

    // ---- Document::for_service -------------------------------------------

    fn doc_with_services(services: HashMap<String, ServiceOverride>) -> Document {
        Document {
            general: General::default(),
            appearance: Appearance::default(),
            audio: Audio::default(),
            services,
            policy: Policy::default(),
            notifications: Notifications::default(),
        }
    }

    #[test]
    fn service_config_uses_general_defaults_for_unknown_service() {
        let doc = doc_with_services(HashMap::new());
        let cfg = doc.for_service("anything");
        assert!(cfg.enabled);
        assert_eq!(cfg.timeout, 30);
        assert!(cfg.randomize_buttons);
    }

    #[test]
    fn service_config_per_service_override_wins() {
        let mut services = HashMap::new();
        services.insert(
            "sudo".to_string(),
            ServiceOverride {
                enabled: Some(false),
                timeout: Some(99),
                randomize: Some(false),
                remember_seconds: None,
                remember_scope: None,
            },
        );
        let doc = doc_with_services(services);
        let cfg = doc.for_service("sudo");
        assert!(!cfg.enabled);
        assert_eq!(cfg.timeout, 99);
        assert!(!cfg.randomize_buttons);
    }

    #[test]
    fn service_config_partial_override_inherits_rest() {
        let mut services = HashMap::new();
        services.insert(
            "su".to_string(),
            ServiceOverride {
                enabled: Some(false),
                timeout: None,
                randomize: None,
                remember_seconds: None,
                remember_scope: None,
            },
        );
        let doc = doc_with_services(services);
        let cfg = doc.for_service("su");
        assert!(!cfg.enabled);
        assert_eq!(cfg.timeout, 30);
        assert!(cfg.randomize_buttons);
    }

    #[test]
    fn service_config_other_services_unaffected() {
        let mut services = HashMap::new();
        services.insert(
            "sudo".to_string(),
            ServiceOverride {
                enabled: Some(false),
                timeout: Some(1),
                randomize: Some(false),
                remember_seconds: None,
                remember_scope: None,
            },
        );
        let doc = doc_with_services(services);
        let polkit_cfg = doc.for_service("polkit-1");
        assert!(polkit_cfg.enabled);
        assert_eq!(polkit_cfg.timeout, 30);
        assert!(polkit_cfg.randomize_buttons);
    }

    // ---- remember_seconds default + key split (issue #22) ----------------

    #[test]
    fn remember_default_is_300_on_gui_path() {
        let doc = Document::defaults();
        assert_eq!(doc.general.remember_seconds, 300);
        assert_eq!(doc.for_service(POLKIT_PAM_SERVICE).remember_seconds, 300);
    }

    #[test]
    fn remember_terminal_paths_default_off() {
        // The point of the key split: GUI on, terminal off by default,
        // even though [general].remember_seconds defaults to 300.
        let doc = Document::defaults();
        assert_eq!(doc.for_service("sudo").remember_seconds, 0);
        assert_eq!(doc.for_service("su").remember_seconds, 0);
        assert_eq!(doc.for_service("sudo-i").remember_seconds, 0);
        assert_eq!(doc.for_service("anything").remember_seconds, 0);
    }

    #[test]
    fn remember_terminal_opt_in_via_service_override() {
        let mut services = HashMap::new();
        services.insert(
            "sudo".to_string(),
            ServiceOverride {
                remember_seconds: Some(60),
                remember_scope: None,
                ..Default::default()
            },
        );
        let doc = doc_with_services(services);
        assert_eq!(doc.for_service("sudo").remember_seconds, 60);
        // a different terminal service stays off
        assert_eq!(doc.for_service("su").remember_seconds, 0);
    }

    #[test]
    fn remember_gui_off_switch_via_service_override() {
        let mut services = HashMap::new();
        services.insert(
            POLKIT_PAM_SERVICE.to_string(),
            ServiceOverride {
                remember_seconds: Some(0),
                remember_scope: None,
                ..Default::default()
            },
        );
        let doc = doc_with_services(services);
        assert_eq!(doc.for_service(POLKIT_PAM_SERVICE).remember_seconds, 0);
    }

    #[test]
    fn remember_serde_default_applies_when_key_absent() {
        // Guards the bare-#[serde(default)] trap: [general] present but
        // the key absent must yield 300 (NOT u32::default() == 0). This
        // is the shipped state (config ships the key commented out).
        let doc: Document = toml::from_str("[general]\ntimeout = 30\n").expect("parse");
        assert_eq!(doc.general.remember_seconds, 300);
        assert_eq!(doc.for_service(POLKIT_PAM_SERVICE).remember_seconds, 300);
        // terminal still off despite the GUI default
        assert_eq!(doc.for_service("sudo").remember_seconds, 0);
    }

    #[test]
    fn remember_explicit_zero_is_preserved() {
        // Escape hatch: explicit 0 stays 0 (feature off on the GUI path).
        let doc: Document = toml::from_str("[general]\nremember_seconds = 0\n").expect("parse");
        assert_eq!(doc.general.remember_seconds, 0);
        assert_eq!(doc.for_service(POLKIT_PAM_SERVICE).remember_seconds, 0);
    }

    #[test]
    fn service_override_unknown_field_is_a_parse_error() {
        // deny_unknown_fields: a typo'd per-service key fails loudly
        // rather than being silently dropped.
        let r: Result<Document, _> = toml::from_str("[services.sudo]\nramdomize = true\n");
        assert!(r.is_err(), "typo'd per-service key must be a parse error");
    }

    // ---- TOML round-trip -------------------------------------------------

    #[test]
    fn parses_full_config_toml() {
        let src = r#"
            [general]
            enabled = true
            timeout = 45
            randomize_buttons = false
            headless_action = "deny"
            min_display_time_ms = 1000

            [appearance]
            title = "Custom"
            message = "msg %u"

            [services.sudo]
            timeout = 5
        "#;
        let doc: Document = toml::from_str(src).expect("parse");
        let cfg = doc.for_service("sudo");
        assert_eq!(cfg.timeout, 5);
        assert_eq!(cfg.headless_action, HeadlessAction::Deny);
        assert!(!cfg.randomize_buttons);
        assert_eq!(cfg.min_display_time_ms, 1000);
        assert_eq!(cfg.title, "Custom");
    }

    #[test]
    fn malformed_toml_is_a_parse_error_not_a_panic() {
        let result: Result<Document, _> = toml::from_str("this is not [valid toml");
        assert!(result.is_err());
    }

    #[test]
    fn headless_action_default_is_password() {
        assert_eq!(HeadlessAction::default(), HeadlessAction::Password);
    }

    // ---- load_from --------------------------------------------------------

    #[test]
    fn load_from_missing_file_returns_defaults() {
        let doc = Document::load_from(Path::new("/nonexistent/sentinel.conf"));
        assert_eq!(doc.general.timeout, 30);
        assert!(doc.services.is_empty());
    }

    #[test]
    fn load_from_real_file_round_trips() {
        // Write a minimal config to a tempfile and load it back.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("sentinel-shared-test-{}.toml", std::process::id()));
        std::fs::write(&path, "[general]\ntimeout = 12\n").unwrap();
        let doc = Document::load_from(&path);
        let _ = std::fs::remove_file(&path);
        assert_eq!(doc.general.timeout, 12);
    }

    // ---- log_kv::quote ---------------------------------------------------

    #[test]
    fn log_kv_bare_token_unquoted() {
        assert_eq!(log_kv::quote("alice"), "alice");
        assert_eq!(log_kv::quote("/usr/bin/sudo"), "/usr/bin/sudo");
        assert_eq!(log_kv::quote("polkit-1"), "polkit-1");
    }

    #[test]
    fn log_kv_whitespace_gets_quoted() {
        assert_eq!(log_kv::quote("hello world"), "\"hello world\"");
        assert_eq!(log_kv::quote("a\tb"), "\"a\tb\"");
    }

    #[test]
    fn log_kv_internal_quotes_escaped() {
        assert_eq!(log_kv::quote("a\"b"), "\"a\\\"b\"");
    }

    #[test]
    fn log_kv_empty_becomes_quoted_empty() {
        // Distinguishes "key=" from "key" — the latter would parse
        // ambiguously in some logfmt implementations.
        assert_eq!(log_kv::quote(""), "\"\"");
    }

    #[test]
    fn log_kv_equals_sign_gets_quoted() {
        // = inside a value would otherwise look like a key boundary.
        assert_eq!(log_kv::quote("a=b"), "\"a=b\"");
    }

    #[test]
    fn log_kv_backslash_escaped() {
        assert_eq!(log_kv::quote("a\\b"), "a\\b"); // bare backslash without quoting trigger stays
        assert_eq!(log_kv::quote("a b\\c"), "\"a b\\\\c\""); // gets escaped when wrapping
    }

    // ---- Outcome ----------------------------------------------------------

    #[test]
    fn outcome_display_strings_are_stable_protocol() {
        // The wire format the helper writes and consumers parse. Bumping
        // these is a wire-protocol break.
        assert_eq!(Outcome::Allow.to_string(), "ALLOW");
        assert_eq!(Outcome::Deny.to_string(), "DENY");
        assert_eq!(Outcome::Timeout.to_string(), "TIMEOUT");
    }

    #[test]
    fn outcome_round_trips_through_str() {
        for v in [Outcome::Allow, Outcome::Deny, Outcome::Timeout] {
            assert_eq!(v.to_string().parse::<Outcome>().unwrap(), v);
        }
    }

    #[test]
    fn outcome_from_str_strips_whitespace() {
        assert_eq!("ALLOW\n".parse::<Outcome>(), Ok(Outcome::Allow));
        assert_eq!(" DENY ".parse::<Outcome>(), Ok(Outcome::Deny));
    }

    #[test]
    fn outcome_unknown_is_error() {
        assert!("MAYBE".parse::<Outcome>().is_err());
        assert!("".parse::<Outcome>().is_err());
        assert!("allow".parse::<Outcome>().is_err()); // case-sensitive on purpose
    }

    #[test]
    fn outcome_exit_code_allow_is_zero() {
        assert_eq!(Outcome::Allow.exit_code(), 0);
        assert_eq!(Outcome::Deny.exit_code(), 1);
        assert_eq!(Outcome::Timeout.exit_code(), 1);
    }

    #[test]
    fn outcome_is_allow_helper() {
        assert!(Outcome::Allow.is_allow());
        assert!(!Outcome::Deny.is_allow());
        assert!(!Outcome::Timeout.is_allow());
    }

    #[test]
    fn verdict_wire_round_trips_and_is_backward_compatible() {
        // bare outcome (old helpers) → remember = false
        let v: Verdict = "ALLOW".parse().unwrap();
        assert_eq!(v.outcome, Outcome::Allow);
        assert!(!v.remember);
        // opt-in
        let v: Verdict = "ALLOW REMEMBER".parse().unwrap();
        assert!(v.remember);
        assert_eq!(v.to_string(), "ALLOW REMEMBER");
        // REMEMBER only matters on Allow (Display drops it otherwise)
        let v = Verdict {
            outcome: Outcome::Deny,
            remember: true,
        };
        assert_eq!(v.to_string(), "DENY");
        // round-trip + whitespace tolerance
        assert_eq!(
            "  DENY  ".parse::<Verdict>().unwrap().outcome,
            Outcome::Deny
        );
        assert!("NONSENSE".parse::<Verdict>().is_err());
    }

    // ---- process_basename -------------------------------------------------

    #[test]
    fn process_basename_strips_dirname() {
        assert_eq!(process_basename("/usr/bin/firefox"), Some("firefox"));
        assert_eq!(process_basename("/bin/true"), Some("true"));
    }

    #[test]
    fn process_basename_handles_no_directory() {
        assert_eq!(process_basename("bash"), Some("bash"));
    }

    #[test]
    fn process_basename_returns_none_for_path_only_dots() {
        // `Path::file_name()` returns None for "/", "..", "."
        assert_eq!(process_basename("/"), None);
        assert_eq!(process_basename(""), None);
    }

    // ---- strip_elevation_prefix --------------------------------------

    #[test]
    fn strip_elevation_passes_through_non_elevation_cmdline() {
        // Plain `ls -la` has no elevation prefix; return as-is.
        assert_eq!(strip_elevation_prefix("ls -la"), "ls -la");
        assert_eq!(
            strip_elevation_prefix("/usr/bin/firefox"),
            "/usr/bin/firefox"
        );
    }

    #[test]
    fn strip_elevation_handles_pkexec() {
        assert_eq!(strip_elevation_prefix("pkexec true"), "true");
        assert_eq!(
            strip_elevation_prefix("pkexec /usr/bin/cat /etc/hosts"),
            "/usr/bin/cat /etc/hosts"
        );
        assert_eq!(
            strip_elevation_prefix("pkexec --user root systemctl restart foo"),
            "systemctl restart foo"
        );
        assert_eq!(
            strip_elevation_prefix("pkexec --disable-internal-agent --user root /bin/sh"),
            "/bin/sh"
        );
    }

    #[test]
    fn strip_elevation_handles_sudo() {
        // The motivating case: sudo / sudo-rs with a single command.
        assert_eq!(strip_elevation_prefix("sudo true"), "true");
        assert_eq!(strip_elevation_prefix("sudo-rs true"), "true");
        // Common multi-arg form.
        assert_eq!(
            strip_elevation_prefix("sudo systemctl restart foo"),
            "systemctl restart foo"
        );
        // sudo-specific value-taking flags.
        assert_eq!(strip_elevation_prefix("sudo -u root /bin/sh"), "/bin/sh");
        assert_eq!(
            strip_elevation_prefix("sudo -E -u root systemctl daemon-reload"),
            "systemctl daemon-reload"
        );
        assert_eq!(
            strip_elevation_prefix("sudo --user root --group docker docker ps"),
            "docker ps"
        );
    }

    #[test]
    fn strip_elevation_skips_chroot_value() {
        // `-R`/`--chroot` take a directory value. If the value flag isn't
        // recognised, the directory is mistaken for the command — the
        // dialog then shows `/srv` and a `deny = ["pacman"]` is evaded.
        assert_eq!(
            strip_elevation_prefix("sudo -R /srv pacman -U /tmp/x"),
            "pacman -U /tmp/x"
        );
        assert_eq!(
            strip_elevation_prefix("sudo --chroot /srv systemctl restart foo"),
            "systemctl restart foo"
        );
    }

    #[test]
    fn strip_elevation_handles_su() {
        assert_eq!(strip_elevation_prefix("su -c whoami"), "whoami");
    }

    #[test]
    fn strip_elevation_handles_doas() {
        assert_eq!(strip_elevation_prefix("doas pacman -Syu"), "pacman -Syu");
    }

    #[test]
    fn strip_elevation_with_absolute_path() {
        // Argv[0] could be the absolute path; we match by basename.
        assert_eq!(strip_elevation_prefix("/usr/bin/sudo true"), "true");
        assert_eq!(
            strip_elevation_prefix("/usr/bin/pkexec /usr/bin/gparted"),
            "/usr/bin/gparted"
        );
    }

    #[test]
    fn strip_elevation_returns_empty_for_no_command() {
        // `sudo -i` runs a login shell with no specific command.
        assert_eq!(strip_elevation_prefix("sudo -i"), "");
        assert_eq!(strip_elevation_prefix("sudo"), "");
        assert_eq!(strip_elevation_prefix("pkexec"), "");
    }

    #[test]
    fn strip_elevation_empty_input() {
        assert_eq!(strip_elevation_prefix(""), "");
    }

    // ---- remember_eligible_command (shared by both auth paths) -----------

    #[test]
    fn remember_eligible_accepts_concrete_commands() {
        assert!(remember_eligible_command("pacman -Syu"));
        assert!(remember_eligible_command("systemctl restart nginx"));
        assert!(remember_eligible_command("/usr/bin/pacman -Syu"));
        assert!(remember_eligible_command("id"));
        assert!(remember_eligible_command("cat /etc/hosts"));
    }

    #[test]
    fn remember_eligible_rejects_shells_interpreters_nesting() {
        for cmd in [
            "bash",
            "sh -c whoami",
            "/usr/bin/zsh",
            "fish",
            "python3 -c x",
            "perl -e x",
            "node app.js",
            "su",
            "sudo bash",
            "pkexec id",
            "doas sh",
            "env X=1 evil",
        ] {
            assert!(
                !remember_eligible_command(cmd),
                "{cmd:?} must be ineligible"
            );
        }
    }

    #[test]
    fn remember_eligible_rejects_shell_escapers() {
        for cmd in [
            "vim /etc/hosts",
            "less /var/log/x",
            "man 5 sudoers",
            "find / -exec sh ;",
            "nano /etc/fstab",
        ] {
            assert!(
                !remember_eligible_command(cmd),
                "{cmd:?} must be ineligible"
            );
        }
    }

    #[test]
    fn remember_eligible_rejects_empty() {
        assert!(!remember_eligible_command(""));
        assert!(!remember_eligible_command("   "));
    }

    // ---- remember_key_command / remember_scope ---------------------------

    #[test]
    fn remember_key_command_scopes() {
        // Default scope: the full command, trimmed.
        assert_eq!(
            remember_key_command(" zypper dist-upgrade ", RememberScope::Command),
            "zypper dist-upgrade"
        );
        // Program scope: leading token only, so `zypper refresh` and
        // `zypper dist-upgrade` share one grant (the topgrade case).
        assert_eq!(
            remember_key_command("zypper dist-upgrade", RememberScope::Program),
            "zypper"
        );
        assert_eq!(
            remember_key_command("zypper refresh", RememberScope::Program),
            "zypper"
        );
        // Verbatim token: path and bare name stay distinct keys.
        assert_eq!(
            remember_key_command("/usr/bin/zypper ref", RememberScope::Program),
            "/usr/bin/zypper"
        );
        assert_eq!(remember_key_command("", RememberScope::Program), "");
    }

    #[test]
    fn remember_scope_parses_and_inherits() {
        // Default is per-command.
        let doc: Document = toml::from_str("[general]\n").expect("parse");
        assert_eq!(doc.general.remember_scope, RememberScope::Command);
        assert_eq!(
            doc.for_service("sudo").remember_scope,
            RememberScope::Command
        );

        // [general] value inherits into every service…
        let doc: Document =
            toml::from_str("[general]\nremember_scope = \"program\"\n").expect("parse");
        assert_eq!(
            doc.for_service("sudo").remember_scope,
            RememberScope::Program
        );
        assert_eq!(
            doc.for_service(POLKIT_PAM_SERVICE).remember_scope,
            RememberScope::Program
        );

        // …and a per-service override wins over [general].
        let doc: Document = toml::from_str(
            "[general]\nremember_scope = \"program\"\n[services.sudo]\nremember_scope = \"command\"\n",
        )
        .expect("parse");
        assert_eq!(
            doc.for_service("sudo").remember_scope,
            RememberScope::Command
        );
        assert_eq!(
            doc.for_service(POLKIT_PAM_SERVICE).remember_scope,
            RememberScope::Program
        );

        // A typo'd value is a loud parse error, not a silent default.
        assert!(toml::from_str::<Document>("[general]\nremember_scope = \"prgram\"\n").is_err());
    }

    #[test]
    fn remember_eligible_matches_by_basename_not_substring() {
        // Absolute path to a shell is still caught (basename match)…
        assert!(!remember_eligible_command("/usr/bin/bash -l"));
        // …but a program that merely *contains* a shell name is NOT
        // falsely excluded (guards against substring over-matching).
        assert!(remember_eligible_command("bashtop")); // != "bash"
        assert!(remember_eligible_command("shellcheck x")); // != "sh"
        assert!(remember_eligible_command("findutils-thing")); // != "find"
    }
}
