# Configuration

Sentinel reads `/etc/security/sentinel.conf` (TOML) on every PAM
auth attempt — no daemon to reload. The file is **root-owned and
not user-writable on purpose**: a per-user override layer would
defeat the UAC contract by letting an unprivileged user lower their
own `timeout` to zero.

## Sections

### `[general]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Master switch. When `false`, the module returns `PAM_IGNORE` and the rest of the stack runs unchanged. |
| `timeout` | uint | `30` | Auto-deny timeout in seconds. `0` disables the timeout (the dialog stays open until the user clicks). |
| `randomize_buttons` | bool | `true` | Swap Allow/Deny positions randomly to deter scripted clickers. |
| `headless_action` | enum | `"password"` | What to do when no Wayland display is available. `"allow"` silently grants (DANGEROUS), `"deny"` silently rejects, `"password"` falls through to the next PAM module (typically `pam_unix`). |
| `show_process_info` | bool | `true` | Display the requesting process's exe/cmdline in the dialog. |
| `log_attempts` | bool | `true` | Log every allow/deny/timeout to syslog (`auth.info`). |
| `min_display_time_ms` | uint | `500` | Disable the Allow button for this many ms after the dialog appears, blocking instant scripted clicks. |
| `remember_seconds` | uint | `300` | "Remember" window for the **polkit/GUI path**. The dialog shows a **"Remember for N min" checkbox** by default; tick it and Allow to let repeat requests from the **same login session** skip the dialog for this many seconds. **Both paths key the grant on the `action`/service + the full command**, so it never covers a different command. `0` hides the checkbox; hard-capped at `900`. Terminal `sudo`/`su` have a *compiled* default of `0`, but the **shipped config opts them into `300`**. See [below](#remember-window). |
| `remember_scope` | enum | `"command"` | Granularity of a remember grant. `"command"` binds it to the **full command line** (args included). `"program"` binds it to the **program only**, so one tick covers different invocations of the same tool — e.g. topgrade's `sudo zypper refresh` + `sudo zypper dist-upgrade` become one prompt. Program scope gives up the argument binding (a remembered `pacman` also covers `pacman -U /tmp/evil` for the window) — opt in knowingly. Shells/interpreters stay excluded either way. Per-service overridable. |

<a id="remember-window"></a>
**The remember window** is a `sudo`-timestamp analogue. The opt-in
checkbox is **shown by default on the polkit/GUI path** (set
`remember_seconds = 0` to hide it); ticking it is still opt-in **per
request** (the box defaults unchecked, so nothing is auto-allowed unless
you tick it on that prompt). A grant is bound to your `loginuid` **and**
kernel audit `sessionid`, so it can't be replayed in another session or
by another user, and is scoped to exactly what it was granted for —
**both paths key the grant on `(action, whole command)`** (`sudo pacman
-Syu` can never auto-allow `sudo pacman -U /tmp/evil`, and `pkexec id`
never covers `pkexec rm`) — never a blanket allow. It is enforced by
two trust-appropriate backends:

- **sudo / su** (PAM path): the `pam_sentinel` module relays the decision
  to the **`sentinel-broker`** daemon — a sandboxed, *unprivileged*
  service that holds grants **in memory** (no on-disk artifact to forge or
  roll back) and serves only root peers over a Unix socket. Grants
  evaporate when the broker stops, and the module is **fail-closed**: if
  the broker is unreachable, you simply get the dialog. (Installed and
  enabled by `install.sh`.)
- **polkit / GUI** (agent, per-user): an in-memory cache that evaporates
  on logout (the agent restarts with the session).

**Defaults.** The two paths have different blast radii, so the *compiled*
defaults differ — but the shipped config enables both:

- The **polkit/GUI** path inherits `[general].remember_seconds` (default
  `300`), so the checkbox is shown there by default.
- The **terminal** `sudo`/`su`/`sudo-i` paths have a *compiled* default of
  **`0` (off)**, but the shipped `config/sentinel.conf` opts them into
  `300`. Set a service back to `0` to require confirmation every time;
  disable the GUI path with `[general].remember_seconds = 0` or
  `[services."polkit-1"].remember_seconds = 0`.

Because grants are keyed by the **full command**, the generic pkexec
action (`org.freedesktop.policykit.exec`, "run any command as root") is
remembered **per command** — `pkexec id` only ever auto-allows
`pkexec id`, never `pkexec rm …`. (Earlier versions excluded pkexec
entirely because the key was command-blind; that is fixed.)

**Multi-command tools (topgrade, update scripts).** Full-command binding
means a runner that issues *several different* elevated commands prompts
once per distinct command — remembering `sudo zypper refresh` cannot
cover the `sudo zypper dist-upgrade` that follows. If you'd rather one
tick cover the whole tool, set `remember_scope = "program"` (globally in
`[general]` or just for one service, e.g. `[services.sudo]`): the grant
then binds to the program token instead of the full command line. The
trade-off is spelled out in the table above.

> **polkit's own caching is separate.** Actions whose policy uses
> `auth_admin_keep`/`auth_self_keep` are cached by **polkit itself** for
> the session after the first auth — independent of Sentinel's window, and
> not overridden by Sentinel. The first auth is still gated by the dialog;
> `pkexec` does **not** use `keep`, so the "run anything" path is
> re-confirmed every time.

**Never remembered** (always re-prompts), on **both** paths: arbitrary-code
gateways used as the elevated command — shells, language interpreters, and
common shell-escapers (editors, pagers, `find`, …), via a shared denylist
(`sentinel_shared::remember_eligible_command`); plus, on the terminal path,
interactive root shells and cred-cache invocations (`sudo -s`/`-i`/`-v`,
`su`). Conservative, non-exhaustive; the primary bound is full-command
binding, so keep windows short.

> ⚠️ **Terminal caveat.** A `sudo`/`su` grant is keyed by the **full
> command** (so a grant for `sudo pacman -Syu` does *not* cover
> `sudo pacman -U <file>`), but it is honored by every process sharing
> your audit session for the window. Under the shipped `auth sufficient`
> wiring a remembered grant is **passwordless** for its duration (it
> short-circuits the stack before `pam_unix`). Enable the terminal window
> only if you accept that trade-off.

A request with no audit session is never remembered.

> **sudo's own timestamp.** By default `sudo` caches credentials for ~5 min
> (`timestamp_timeout`), which lets a back-to-back `sudo` skip the PAM stack
> entirely — so Sentinel never sees it and this per-command window is
> bypassed by sudo's blanket session cache. The installer therefore drops
> `/etc/sudoers.d/sentinel-timestamp` (`Defaults timestamp_timeout=0`,
> validated with `visudo`) so **every** `sudo` runs the PAM stack and
> Sentinel's per-command remember is the only cache. Remove that file (or
> uninstall) to restore sudo's default timestamp; pass `--no-sudo` at
> install time to skip terminal wiring (and this override) altogether.

### `[appearance]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `title` | string | `"Authentication Required"` | Dialog title. No substitutions. |
| `message` | string | `'The application "%p" is requesting elevated privileges.'` | Primary message. Tokens: see below. |
| `secondary` | string | `""` | Optional hint line below the message. Empty by default — naming the buttons in the secondary text broke under `randomize_buttons` in 0.5.x. |

### `[audio]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `sound_name` | string | `"dialog-warning"` | Freedesktop sound name (NOT a file path). Empty string disables. Resolved via `canberra-gtk-play` if installed. |

### `[services.<name>]`

Per-PAM-service overrides. The overridable keys are `enabled`,
`timeout`, `randomize`, `remember_seconds`, and `remember_scope`.
Unknown keys are a **parse error** (a typo fails loudly rather than
being silently dropped). Omitted keys inherit from `[general]` —
**except `remember_seconds`**, which inherits
`[general].remember_seconds` only for `polkit-1` and defaults to `0`
(off) for terminal services; see the
[remember window](#remember-window).

```toml
[services.polkit-1]
timeout = 60          # more lenient for GUI auth

[services.su]
enabled = false       # never confirm `su`, fall through to password

[services.sudo]
remember_seconds = 300  # per-command 5-min window; set 0 to confirm every time
```

### `[policy]`

Static allow/deny lists evaluated **before** the dialog. Disabled by
default (empty lists never match), so behaviour is unchanged until you
opt in.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `allow` | list of string | `[]` | Auto-allow (no dialog) when an entry matches. |
| `deny` | list of string | `[]` | Auto-deny (no dialog). **Takes precedence over `allow`.** |

Each entry matches the requesting program's **resolved executable path**
(`/proc/<pid>/exe`, e.g. `/usr/bin/pacman` — never the spoofable
`argv[0]`), that path's **basename** when the entry contains no `/`, or
the **polkit action id** (agent path).

> ⚠️ An `allow` entry is **passwordless elevation** for that target — as
> load-bearing as a `sudoers` `NOPASSWD` line. Prefer absolute paths,
> keep the list short.

```toml
[policy]
allow = [
    "/usr/bin/topgrade",                         # full path (recommended)
    "pacman",                                    # basename: any path named 'pacman'
]
deny = [
    "org.freedesktop.systemd1.manage-units",     # polkit action id
]
```

### `[notifications]`

Desktop notifications (via `notify-send` / libnotify) on the polkit/GUI
auth path. Terminal `sudo`/`su` denials are already visible in the
terminal, so they're not covered. Both default off.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `on_deny` | bool | `false` | Notify when a request is denied (including silent `[policy]` denials, where no dialog appeared). |
| `on_timeout` | bool | `false` | Notify when a request auto-denies on timeout. |

```toml
[notifications]
on_deny = true
on_timeout = true
```

## Tokens

Inside `message` and `secondary` the following expand at runtime:

| Token | Expands to |
|-------|------------|
| `%u` | Username being authenticated |
| `%s` | PAM service name (`sudo`, `polkit-1`, …) |
| `%p` | Requesting process's executable path basename |
| `%%` | Literal `%` |

Unknown `%x` sequences are preserved verbatim so a typo is visible to
the admin in the rendered dialog.

## Example

```toml
# /etc/security/sentinel.conf

[general]
enabled = true
timeout = 30
randomize_buttons = true
headless_action = "password"
min_display_time_ms = 500
remember_seconds = 300        # GUI checkbox window (default); 0 = hide/off

[appearance]
title = "Authentication Required"
message = 'The application "%p" is requesting elevated privileges.'
secondary = ""

[audio]
sound_name = "dialog-warning"

# Auto-allow/deny before the dialog (off by default — empty lists).
[policy]
allow = []
deny = []

# Desktop notification on deny/timeout (polkit/GUI path).
[notifications]
on_deny = false
on_timeout = false

[services.sudo]
timeout = 30
remember_seconds = 300        # per-command window (shipped default); 0 = confirm every time

[services."polkit-1"]
timeout = 60

[services.su]
enabled = false

[services.gdm-password]
enabled = false

[services.lightdm]
enabled = false

[services.sddm]
enabled = false
```

## Localization

The helper's UI chrome (button labels, "Show details" toggle, "Auto-deny
in Ns") is localized from the system locale (`LC_ALL`/`LC_MESSAGES`/`LANG`).

The KDE helper (`sentinel-helper-kde`) localizes this chrome via
`sentinel_shared::ui_i18n`, which ships 12 languages: en, de, es, fr, it,
ja, nl, pl, pt, ru, tr, zh.

The dialog message/title/secondary are admin-supplied via this config
file — they're rendered verbatim as you write them. If you leave the
defaults (`title`, `message`), the helper substitutes the locale's
own translation; once you customise them, your text wins.

Locale resolution: `LC_ALL` → `LC_MESSAGES` → `LANG`, reduced to its
2-letter language code (`tr_TR.UTF-8` → `tr`), falling back to `en` for
unknown or unset values.
