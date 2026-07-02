# Changelog

All notable changes per release. Detailed prose for each version lives
in `.github/release-notes/v*.md` and is mirrored on the GitHub
[Releases](https://github.com/atayoez/sentinel/releases) page.

The format loosely follows
[Keep a Changelog](https://keepachangelog.com/), with version numbers
following [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- **The "remember" checkbox is no longer offered for requests that can
  never be remembered** (`sudo -v`, `su`, shells and other ineligible
  gateways) on the terminal path. Previously the dialog showed the
  checkbox but the tick was silently dropped — e.g. topgrade's leading
  `sudo -v` cred-cache prompt pretended to be rememberable. The PAM path
  now collapses the window to `0` exactly like the polkit path already
  did.
- **`[policy] allow` can no longer be tricked into passwordlessly
  granting a root shell.** For a bare-elevation request (`sudo -i`/`-s`/
  `-v`, `su`) the dialog shows the *originating* tool (e.g. `topgrade`),
  but policy now matches on a separate `policy_exe` that is unset for
  those requests, so an `allow = ["topgrade"]` entry no longer matches
  the root shell that tool spawns — such requests always go to the
  dialog.
- **`sudo -R`/`--chroot <dir>` is parsed correctly.** The chroot
  directory was previously mistaken for the elevated command, so the
  dialog showed the wrong program and a `deny` entry could be evaded.
- **Remember grants are no longer keyed on the `u32::MAX` "no audit
  session" sentinel.** Two sessions that both lack a loginuid/sessionid
  could otherwise collide on one grant; such requests are now never
  remembered, matching the documented contract.
- **polkit path: the confirmation dialog is killed on cancel and bounded
  by a timeout.** `CancelAuthentication` no longer orphans the dialog on
  screen, and a wedged helper can't block every future auth by holding
  the agent's serialization guard forever.
- **polkit path: a `CancelAuthentication` racing session startup now
  aborts it reliably** (the session handle is registered before the task
  can run), and a pre-approval left behind by a failed `helper-1` hand-off
  is dropped so a later auth can't claim it.

### Added

- **`remember_scope = "command" | "program"`** (`[general]` or per
  service): opt-in granularity for remember grants. The default
  (`"command"`) keeps the full-command binding; `"program"` binds a
  grant to the program token only, so multi-command tools (topgrade's
  `zypper refresh` + `zypper dist-upgrade`) prompt once per window
  instead of once per distinct command line. Shell/interpreter
  exclusions and session binding are unchanged.

## [0.13.0] — 2026-06-27

KDE-only. The COSMIC frontend is removed — Sentinel now ships a single KDE
Plasma helper.

### Removed

- **COSMIC frontend dropped.** The `sentinel-helper` (libcosmic) crate and
  its fluent locale bundles, the COSMIC root `install.sh` / `uninstall.sh`,
  the `sentinel-cosmic` Arch package, and the `build-cosmic` /
  `publish-aur-cosmic` release jobs are all removed. The shared auth backend
  (PAM module, polkit agent, broker) is unchanged; the KDE helper
  (`sentinel-helper-kde`, AUR package `sentinel-kde`) is now the only
  frontend. This collapses the two divergent installers into one, drops the
  entire libcosmic dependency tree (and its `deny.toml` / `cargo audit`
  carve-outs), and makes `sentinel-helper-kde` the default baked helper
  path. No config or auth-path behavior change.

## [0.12.0] — 2026-06-27

Privilege-separation broker, a reworked per-command "remember" model, and
a tighter root `unsafe` surface.

### Remember window

- **Checkbox shown by default (polkit/GUI).** `[general].remember_seconds`
  now defaults to `300` (was `0`), so the polkit auth dialog shows the
  opt-in "Remember" checkbox on every prompt. The box still defaults
  unchecked — nothing is auto-allowed unless you tick it per prompt. Set
  `[general].remember_seconds = 0` to hide it / disable. (#22)
- **Grants bind to the full command — on both paths.** The remember record
  is keyed by the *whole* elevated command, not the program name, so a
  grant can never authorize a different invocation: `sudo pacman -Syu` will
  not auto-allow `sudo pacman -U /tmp/evil`, and `pkexec id` never covers
  `pkexec rm`. This fixes a real bug where the polkit path's command-blind
  key let one ticked `pkexec` silently auto-allow *any* later pkexec
  command (seen in the wild as `source=remember action=…policykit.exec`);
  `pkexec` is now remembered per command like everything else, with no
  blanket carve-out.
- **Per-service window; shipped config enables terminal.** Remember is a
  per-service knob (`[services.<name>].remember_seconds`). The *compiled*
  default is `300` for `polkit-1` and `0` for terminal services, but the
  shipped `config/sentinel.conf` opts `sudo`/`sudo-i`/`su` into `300` (set
  a service to `0` to require confirmation every time). Unknown
  `[services.*]` keys are now a parse error (`deny_unknown_fields`) so a
  typo'd security knob fails loudly.
- **Arbitrary-code gateways are never remembered (both paths).** Commands
  whose target is a shell, language interpreter, or common shell-escaper
  (editors, pagers, `find`, …) — plus bare-elevation root shells / cred
  caches (`sudo -s`/`-i`/`-v`, `su`) on the terminal path — always
  re-prompt, via a shared denylist
  (`sentinel_shared::remember_eligible_command`). Conservative,
  non-exhaustive; the primary bound is full-command binding.

### Hardening

- **Hardened the PAM module's `unsafe` surface.** `pam-sentinel` (root
  code) is now `#![deny(unsafe_code)]`. The hand-rolled `extern "C"`
  `getpid`/`getppid`/`getuid` shims are replaced with safe `nix`
  wrappers, leaving only two genuinely-unsafe operations — `fork(2)` and
  post-fork `set_var` — behind narrowly-scoped, `SAFETY`-documented
  `#[allow(unsafe_code)]` sites. New `unsafe` anywhere else is now a
  compile error.
- **Fuzz harnesses for the parsing surfaces.** Added `cargo-fuzz`
  (libFuzzer) targets under `fuzz/` for the inputs that cross into the
  auth path: `Verdict::from_str` (helper→backend wire verdict),
  `strip_elevation_prefix` (untrusted `/proc/<pid>/cmdline`), and
  `format_message` (`%`-token substitution). A `fuzz` CI workflow
  smoke-fuzzes each target 60 s per push (5 min weekly). No crashes found
  in initial runs (~2.2M/660K/980K execs).

### Privilege-separation broker

- **Typed IPC protocol.** New
  `sentinel-broker-proto` crate: the `#![forbid(unsafe_code)]` wire
  contract for a future thin PAM shim → sandboxed root broker
  (`pam_sss`/OpenSSH-monitor model). Compact `postcard` messages with a
  length-prefixed, `MAX_FRAME_LEN`-bounded codec (no OOM on a hostile
  length), fail-closed semantics, and a `broker_proto` fuzz target.
- **Daemon (`sentinel-broker`).** The
  remember decision + grant store now have a home outside the privileged
  binary: a long-lived, **unprivileged** daemon (systemd `DynamicUser=`)
  serving root-only peers over a Unix socket (`SO_PEERCRED` uid-0 gate),
  `#![forbid(unsafe_code)]`, hardened unit (seccomp `@system-service`, no
  caps, `ProtectSystem=strict`, `AF_UNIX`-only). The store is **in
  memory**, which subsumes the on-disk HMAC-integrity work (T3b): no file
  to forge or roll back, monotonic-clock freshness, grants evaporate on
  stop. Keyed by the full command (the argv-binding guarantee holds here
  too).
- **PAM shim rewire.** `pam_sentinel` no
  longer keeps a root timestamp store of its own: it now **relays** the
  remember decision to `sentinel-broker` over the Unix socket
  (`broker_client`), and the on-disk `/run/sentinel/ts` store
  (`timestamp.rs`) is **removed**. Fail-closed: an unreachable broker
  means "show the dialog", never "let in". `install.sh`/`uninstall.sh`
  now deploy + enable (and tear down) the broker unit. This completes the
  privilege-separation split — the root PAM module holds no grant state.
### Installer

- **KDE installer ships the broker; terminal remember enabled.** The KDE
  installer (`packaging-kde/install.sh`) now builds, installs, and enables
  `sentinel-broker` (the missing piece that backs terminal remember), and
  uninstall tears it down. The shipped `config/sentinel.conf` opts
  `[services.sudo]` / `[services.sudo-i]` / `[services.su]` into
  `remember_seconds = 300`, so sudo/su now show the per-command "Remember"
  checkbox. (Compiled default for terminal stays `0`; the shipped config
  opts in. A remembered grant makes a repeat of the *same* command
  passwordless for the window — per-command, shell-excluded.)
- **Installer disables sudo's own credential cache.** `sudo`'s
  `timestamp_timeout` (~5 min) let a back-to-back `sudo` skip the PAM stack
  entirely, so Sentinel never saw it and its per-command remember was
  bypassed by sudo's *blanket* session cache. The KDE installer now drops a
  `sentinel-timestamp` snippet (`Defaults timestamp_timeout=0`) so every
  `sudo` runs PAM and Sentinel's per-command window is the only cache —
  honored by classic sudo **and** sudo-rs. `find_sudoers_dropin` detects the
  active sudoers across distro layouts — `/etc/sudoers`
  (Debian/Ubuntu/Fedora/Arch), openSUSE's `/usr/etc/sudoers`, and sudo-rs's
  `/etc/sudoers-rs` — and writes only into a drop-in dir that config
  actually `@includedir`s (preferring `/etc/sudoers.d`, never a `/usr/etc`
  vendor dir). `visudo`-validated before install, recorded for uninstall.
  Skipped with a warning (never a hard fail) when there's no safe drop-in
  (e.g. NixOS's generated sudoers); `--no-sudo` opts out of terminal wiring
  and this override.

## [0.11.1] — 2026-06-20

Packaging hotfix for 0.11.0 — no runtime, config, or auth-path change.

- **`sentinel-kde` now installs.** `package()` pulled its systemd user
  service and polkit admin rule from `packaging/` (repo root), but
  post-monorepo the KDE-specific assets live under `packaging-kde/packaging/`,
  so `makepkg` failed in `package()`. All KDE assets are now sourced from
  `packaging-kde/packaging/`. (CI builds tarballs but never runs `package()`,
  so it slipped through every release.)
- **Quieted the cxx-qt build** — GCC 16's `-Wsfinae-incomplete` (fired inside
  Qt6's `qchar.h`, not our code) is suppressed via `CXXFLAGS` in the KDE
  helper's `build.rs`.
- **AUR repo hygiene** — stopped tracking release source tarballs (an
  `updpkgsums` side-effect committed them every release) and added a
  `.gitignore`.

## [0.11.0] — 2026-06-20

Packaging-only release — no changes to runtime behaviour, config, or the
auth path.

- **AUR build fixed** — the KDE `package()` installed `config/su`, a PAM
  reference doc that was never committed, so `sentinel-kde 0.10.0` failed
  in `package()` for everyone. It's now shipped (mirrors `config/sudo`).
- **Per-frontend cargo target isolation** — `build()` now uses explicit
  `-p` target lists instead of `--workspace --exclude`, so the KDE package
  no longer compiles the COSMIC/libcosmic stack (and vice versa). The leak
  came via `check()`'s `--workspace -p …`, where `--workspace` overrode the
  `-p` filter and pulled the whole workspace into the test build.
- **Dropped `check()` from both PKGBUILDs** — fmt/clippy/test run in CI on
  every push and the AUR publish is gated on a green release, so re-running
  `cargo test` on each install was redundant compile time.

## [0.10.0] — 2026-06-20

New opt-in features (all default off, so existing configs are unchanged):

- **`[policy]` allow/deny lists** — auto-allow or auto-deny before the
  dialog, matched on the requesting binary's resolved exe path
  (`/proc/<pid>/exe`, never `argv[0]`), its basename, or the polkit
  action id. `deny` wins over `allow`.
- **`[general].remember_seconds` + a "Remember" checkbox** —
  `sudo`-timestamp-style window. When non-zero, the dialog shows a
  **"Remember for N min" checkbox**; tick it and Allow to let repeat
  requests from the same login session for the same service + binary
  skip the dialog (opt-in **per request**, not a silent global). Bound
  to `loginuid` + audit `sessionid`; a root-owned `/run/sentinel/ts`
  store (boottime clock) for sudo/su and an in-memory agent cache for
  polkit; capped at 900 s. Both the KDE and COSMIC helpers render it.
- **`[notifications]`** — `on_deny` / `on_timeout` desktop notifications
  on the polkit/GUI path (including silent policy denials).
- **KDE helper localization** — the Plasma helper's UI chrome now
  localizes from the system locale across all **12 locales** (en, de,
  es, fr, it, ja, nl, pl, pt, ru, tr, zh), matching the COSMIC helper.

Fixes:

- **`packaging-kde/install.sh`** now works from a source checkout in the
  monorepo (it had resolved `target/` and `config/` relative to the
  wrong directory).

## [0.9.0] — 2026-06-20

**Monorepo release.** The former `sentinel-kde` and `sentinel-cosmic`
projects are unified into a single repository
([atayoez/sentinel](https://github.com/atayoez/sentinel)) with one
shared backend and two frontends (`sentinel-helper-kde`,
`sentinel-helper`), released in lockstep. The old repos are archived
and redirect here.

- **Shared backend.** `pam-sentinel`, `sentinel-shared`, and
  `sentinel-polkit-agent` are now a single source of truth — fixes land
  once for both desktops.
- **COSMIC adopts the D-Bus bypass.** The agent → `pam_sentinel`
  pre-approval channel is the system D-Bus (`org.sentinel.Agent` /
  `TakeApproval`), replacing COSMIC's old unix socket. The socket was
  blocked by SELinux (`policykit_t` may `dbus send_msg` but not write a
  socket), so **the bypass now works under SELinux** out of the box.
  The COSMIC package ships the `org.sentinel.Agent.conf` bus policy.
- No config changes for end users; existing
  `/etc/security/sentinel.conf` and PAM wiring keep working.

## [0.8.1] — 2026-06-20

Maintenance release — `pam-bindings` 0.3 compatibility (`get_user`
became `&mut self`) plus a dependency refresh. No behaviour changes.

## [0.8.0] — 2026-05-04

Build-pipeline maintenance release. No behaviour or config changes for
end users; existing `/etc/security/sentinel.conf` and
`/etc/pam.d/polkit-1` keep working unchanged.

- **Fat LTO** across the workspace shrinks the shipped binaries by
  **−8.6%** combined (helper −9.3%, agent −6.1%, PAM module −4.8%);
  ~5 minutes added to release-build wall time, absorbed by CI.
- **AUR baseline raised to `x86-64-v3`** (Haswell / Zen 1+ — AVX2,
  BMI1/2, FMA, F16C). Aligns with how ALHP / CachyOS distribute
  microarch-tuned binaries. The portable `.deb` / `.rpm` and source
  builds are unchanged.
- **CI links with mold** (`-C link-arg=-fuse-ld=mold`) on both `ci.yml`
  and `release.yml`. Faster CI; doesn't affect the produced binary
  beyond build-id.
- **Honest tokio cleanup:** `sentinel-polkit-agent` no longer declares
  the `rt-multi-thread` feature it doesn't use. Workspace feature
  unification keeps it in the binary today (libcosmic via the helper);
  becomes a free win the day that changes.

[Full notes](https://github.com/atayoez/sentinel/releases/tag/v0.8.0)

## [0.7.0] — 2026-05-04

Bigger release: dialog UX final piece + supply-chain integrity +
docs site + repo polish.

- **Dialog process names:** `sudo -v` (cred-cache, used by topgrade
  / paru) now walks up to PPid and shows the user-facing originator
  (paru, topgrade, your shell) instead of `sudo-rs`. Closes the
  dialog-process-name fix series begun in v0.6.1.
- **Sigstore artifact attestations:** every release artifact (deb,
  rpm, tarball, both arches) is signed via
  `actions/attest-build-provenance@v3`. Verify with
  `gh attestation verify <file> --repo atayoez/sentinel`.
- **Threat model:** explicit section in SECURITY.md covering trust
  boundaries (PAM + agent), what each refuses, why no
  `systemd --user` unit, and the 2026 `polkit-agent-helper-1`
  SUID-stripping context.
- **Docs site:** wiki content migrated to `docs/` (mdBook),
  deployed to <https://atayoez.github.io/sentinel/> by
  `.github/workflows/docs.yml`. PR-reviewable, versioned,
  searchable.
- **REUSE / SPDX compliance:** per-file headers across the repo +
  `REUSE.toml` + `reuse-action` CI job. New badge.
- **OpenSSF Scorecard:** weekly + push-triggered
  `.github/workflows/scorecard.yml`. New badge.
- **Compositor compatibility issue template:** structured
  YAML form feeding the README compat table.
- **Agent integration test:** `tests/agent_flow.rs` drives the
  Allow / Deny / Timeout / cancel-drain paths end-to-end with mock
  helper + mock helper-1 via env-var test seams. Agent crate now
  exposes a `[lib]` target.

[Full notes](https://github.com/atayoez/sentinel/releases/tag/v0.7.0)

## [0.6.1] — 2026-05-04

Patch: dialog process names + AUR publish.

- **Dialog and audit logs now show the elevated program, not the
  wrapper**, for both sudo (PAM module path) and gparted-style
  apps that have their own polkit action but call pkexec
  internally. New shared `sentinel_shared::strip_elevation_prefix`
  helper recognises pkexec/sudo/sudo-rs/su/doas and strips both
  standalone flags and value-taking flags (`--user`/`-u`/etc).
- **AUR publish unblocked.** `KSXGitHub/github-actions-deploy-aur`
  bumped from v2.7.2 (broken against the 2026-04 archlinux:base
  with `==> ERROR: There is no secret key available to sign with.`)
  to v4.1.3.

[Full notes](https://github.com/atayoez/sentinel/releases/tag/v0.6.1)

## [0.6.0] — 2026-05-03

Comprehensive review follow-through: bug fixes in PAM module + agent,
distribution-pipeline corrections (aarch64 release, broader compositor
autostart), code-structure cleanups, and new repo-level docs.

- Bug fixes: `timeout = 0` honoured on the parent side, bypass-queue
  cancel-drain, `resolve_user` prefers `pamh.get_user()`, agent kill
  uses `pkill -fx <abs-path>` (was `pkill -f` matching shell siblings),
  cookie-prefix is multi-byte safe, Wayland socket detection requires
  a real socket.
- Distribution: aarch64 prebuilt deb/rpm/tarball, Niri/River/wlroots
  compositors get the autostart entry (`OnlyShowIn` removed),
  `X-systemd-skip=true` for forward-compat.
- UX: empty default `secondary` (was naming the buttons explicitly,
  conflicted with `randomize_buttons`), generic shield fallback icon
  (`system-lock-screen`), consistent details-panel height,
  `event=auth.headless` audit line.
- Internals: shared `audit::init_syslog` + `audit_emit` fallback,
  shared `POLKIT_PAM_SERVICE` const, structured zbus `MethodError`
  matching, `RenderMode` enum and `Args::effective_render_mode`
  method, placeholder-parity test across locales, dropped dead
  `POLKIT_AGENT_HELPER_CANDIDATES` build-script bake.
- CI / repo: `cargo deny` job + `deny.toml`, `cargo deb / rpm`
  smoke job on PRs, pre-tag release-notes guard, `CONTRIBUTING.md`,
  `CHANGELOG.md`, `CODEOWNERS`, `.github/FUNDING.yml`, README badges.

[Full notes](https://github.com/atayoez/sentinel/releases/tag/v0.6.0)

## [0.5.2] — 2026-05-03

Internal cleanup: shared crate rename + log dedup. No user-facing
behavior changes, no config changes, no wire-format changes.

- Renamed internal workspace crate `sentinel-config` → `sentinel-shared`.
- Collapsed four near-identical `event=auth.*` log statements in the
  PAM module's dialog path into a single match on `Outcome`.
- Switched `pam-sentinel`'s locale env reader to call shared
  `sentinel_shared::procfs::read_environ_var`.

[Full notes](https://github.com/atayoez/sentinel/releases/tag/v0.5.2)

## [0.5.1] — 2026-05-03

UAC-style polish + fixes for the install race.

- New `[audio].sound_name` config option — UAC-style audio cue when
  the dialog appears, played through `canberra-gtk-play`.
- Audit log lines (`event=auth.*`) now include logind session
  metadata (`session_type`, `session_class`, `session_remote`).
- Fixed a registration race in `install.sh`'s in-place agent restart
  flow.

[Full notes](https://github.com/atayoez/sentinel/releases/tag/v0.5.1)

## [0.5.0] — 2026-05-02

Localized dialog + tighter agent.

- 12 embedded fluent translation bundles for the helper's UI chrome
  (en-US, de-DE, es-ES, fr-FR, it-IT, ja-JP, nl-NL, pl-PL, pt-BR,
  ru-RU, tr-TR, zh-CN).
- `event=auth.*` audit lines emitted in logfmt for journald querying.
- libcosmic dependency pinned to a specific commit for reproducible
  builds.
- Layer-shell vs xdg-toplevel auto-fallback for Mutter-based desktops.
- Process icon resolved from the desktop's icon theme.

[Full notes](https://github.com/atayoez/sentinel/releases/tag/v0.5.0)

## [0.4.1] — 2026-05-02

Hotfix: agent registration silently failed on systems with
`systemd-xdg-autostart-generator`. The autostart entry now sets
`X-GNOME-Autostart-enabled=false` so the systemd wrapper is bypassed
and the agent inherits the compositor's session id.

[Full notes](https://github.com/atayoez/sentinel/releases/tag/v0.4.1)

## [0.4.0] — 2026-05-02

Sentinel is now your polkit authentication agent.

- `sentinel-polkit-agent` registers as the session's polkit
  authentication agent, replacing process-tree-trust with a Unix
  socket bypass to `polkit-agent-helper-1`.
- Expandable details panel in the dialog showing PID, cmdline, cwd,
  requesting user, polkit action.
- Hardened layout: long fields scroll, max widths/heights bound the
  dialog on tiny displays.

[Full notes](https://github.com/atayoez/sentinel/releases/tag/v0.4.0)

## [0.3.1] — 2026-05-02

Hotfix: agent registration never succeeded in v0.3.0 because the
agent used `logind.GetSessionByPID()` which requires polkit
authorization the unprivileged agent doesn't have. Replaced with
`/proc/self/sessionid`.

[Full notes](https://github.com/atayoez/sentinel/releases/tag/v0.3.1)

## [0.3.0] — 2026-05-02

First polkit agent release. (Yanked — see 0.3.1 for the fix.)

[Full notes](https://github.com/atayoez/sentinel/releases/tag/v0.3.0)

## [0.2.1] — 2026-05-01

Patch: pkexec dialog never appearing. Fixed `display::detect_for_user`
to walk `/run/user/<uid>` for the wayland socket when
`WAYLAND_DISPLAY` is unset (which is normal inside socket-activated
PAM stacks).

[Full notes](https://github.com/atayoez/sentinel/releases/tag/v0.2.1)

## [0.2.0] — 2026-05-01

**Full Rust rewrite.** The C++ helper and PAM module from v0.1.0 are
replaced. Same UAC-style confirmation dialog flow, smaller dependency
surface, structured logging.

[Full notes](https://github.com/atayoez/sentinel/releases/tag/v0.2.0)
