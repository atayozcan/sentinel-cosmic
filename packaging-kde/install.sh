#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025 Atay Özcan <atay@oezcan.me>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Sentinel-KDE installer (source build).
#
# Wires the Sentinel PAM module + polkit agent + Kirigami helper into KDE
# Plasma's authentication path so privilege escalation shows a UAC-style
# confirmation dialog instead of a password prompt.
#
# Transactional: every change is recorded in /var/lib/sentinel/install.state
# and any error rolls back to the pre-install state.
#
# What it does that's Plasma-specific:
#   * Runs Sentinel's agent as a systemd *user* service (the only way it
#     registers cleanly with polkitd on Plasma 6 — see
#     packaging/systemd/user/sentinel-polkit-agent.service).
#   * Masks plasma-polkit-agent.service so Sentinel is the session's sole
#     polkit agent (reversed on uninstall).
#   * Installs a polkit admin rule making the install user a polkit
#     administrator — Sentinel's no-password model needs the logged-in
#     user to confirm their own escalation (UAC-style). root stays admin.
#
# Flags:
#   --no-sudo   Don't guard sudo / sudo -i / su (they keep requiring a
#               password). Default: Sentinel guards them too (prepend-in-place;
#               the password still works as a fallback).
#   --rebuild   Force `cargo build`. Default: reuse target/release artifacts
#               if all are present, otherwise build.

# -E (errtrace): so the ERR trap is inherited into functions and a failure
# inside install_file() rolls back instead of exiting silently.
set -Eeuo pipefail
umask 022

RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
VERBOSE=0
say()   { printf '%s\n' "$*"; }                                    # concise, always
info()  { if [[ $VERBOSE -eq 1 ]]; then printf '  %s\n' "$*"; fi; } # detail, -v only
step()  { info "$@"; }
warn()  { printf "${YELLOW}warning:${NC} %s\n" "$*" >&2; }
error() { printf "${RED}error:${NC} %s\n" "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || error "Run as root (use pkexec or sudo)."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Run from the workspace root: cargo's target/ and the shared config/ live
# there; KDE-specific packaging is under packaging-kde/ (= $SCRIPT_DIR).
cd "$SCRIPT_DIR/.."

PREFIX=${PREFIX:-/usr}
SYSCONFDIR=${SYSCONFDIR:-/etc}
LIBEXECDIR=${LIBEXECDIR:-lib}
HELPER_PATH="$PREFIX/$LIBEXECDIR/sentinel-helper-kde"

# PAM module directory is distro/multilib dependent (/usr/lib64/security on
# SUSE/Fedora, /usr/lib/<triplet>/security on Debian). Detect it from the
# canonical pam_unix.so — getting this wrong means libpam silently never
# loads pam_sentinel.so and every auth falls through to a password.
detect_pam_dir() {
    local d
    for d in /usr/lib64/security /usr/lib/security /lib64/security /lib/security \
             "/usr/lib/$(uname -m)-linux-gnu/security"; do
        [[ -e "$d/pam_unix.so" ]] && { echo "$d"; return 0; }
    done
    echo "$PREFIX/lib/security"
}
PAM_MODULE_DIR="${PAM_MODULE_DIR:-$(detect_pam_dir)}"

STATE_DIR="/var/lib/sentinel"
STATE_FILE="$STATE_DIR/install.state"
STATE_TMP="$(mktemp "${STATE_DIR%/}.install.XXXXXX" 2>/dev/null || mktemp)"
ROLLBACK_LOG="$(mktemp)"
INSTALL_OK=0

# -------------- argv -------------------------------------------------------

INSTALL_SUDO=1      # guard sudo / sudo -i / su by default; --no-sudo opts out
FORCE_BUILD=0       # default: reuse target/release if present; --rebuild forces a build
for arg in "$@"; do
    case "$arg" in
        --no-sudo)     INSTALL_SUDO=0 ;;
        --enable-sudo) INSTALL_SUDO=1 ;;   # back-compat: now the default
        --rebuild)     FORCE_BUILD=1 ;;
        -v|--verbose)  VERBOSE=1 ;;
        --help|-h) sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'; exit 0 ;;
        *) error "Unknown flag: $arg (try --help)" ;;
    esac
done

# -------------- invoking user (for build + systemd --user) -----------------

BUILD_USER=""; BUILD_UID=""
if [[ -n "${PKEXEC_UID:-}" ]]; then
    BUILD_UID="$PKEXEC_UID"
elif [[ -n "${SUDO_UID:-}" && "$SUDO_UID" != "0" ]]; then
    BUILD_UID="$SUDO_UID"
fi
[[ -n "$BUILD_UID" ]] && BUILD_USER="$(getent passwd "$BUILD_UID" | cut -d: -f1 || true)"

# -------------- rollback ---------------------------------------------------

rollback() {
    local rc=$?
    [[ $INSTALL_OK -eq 1 ]] && return
    warn "Install failed (exit $rc). Rolling back…"
    if [[ -s "$ROLLBACK_LOG" ]]; then
        tac "$ROLLBACK_LOG" | while IFS=$'\t' read -r action path backup; do
            case "$action" in
                CREATED)  rm -f -- "$path" || true ;;
                REPLACED) [[ -n "$backup" && -f "$backup" ]] && mv -f -- "$backup" "$path" || true ;;
            esac
        done
    fi
    rm -f -- "$STATE_TMP" "$ROLLBACK_LOG"
    error "Rollback complete. System restored to pre-install state."
}
trap rollback ERR INT TERM

# install_file <mode> <src> <dst> — record pre-state, copy, log for rollback + uninstall.
install_file() {
    local mode="$1" src="$2" dst="$3" backup=""
    mkdir -p "$(dirname "$dst")"
    if [[ -e "$dst" ]]; then
        backup="${dst}.pre-sentinel.bak"
        [[ ! -e "$backup" ]] && cp -a -- "$dst" "$backup"   # don't clobber the real original
        printf 'REPLACED\t%s\t%s\n' "$dst" "$backup" | tee -a "$ROLLBACK_LOG" >> "$STATE_TMP"
    else
        printf 'CREATED\t%s\t\n' "$dst" | tee -a "$ROLLBACK_LOG" >> "$STATE_TMP"
    fi
    install -Dm"$mode" -- "$src" "$dst"
}

# Locate a service's base PAM stack. openSUSE ships the vendor files under
# /usr/lib/pam.d and lets /etc/pam.d shadow them; other distros keep
# everything in /etc/pam.d. We honor that precedence (/etc wins).
find_pam_base() {
    local svc="$1" d
    for d in "$SYSCONFDIR/pam.d" /usr/lib/pam.d /usr/etc/pam.d /lib/pam.d; do
        [[ -f "$d/$svc" ]] && { printf '%s\n' "$d/$svc"; return 0; }
    done
    return 1
}

# Find an admin-writable sudoers drop-in dir that the ACTIVE sudoers config
# actually @includedir's — so `Defaults timestamp_timeout=0` we drop there is
# really read. Handles every target layout (and sudo-rs):
#   Debian/Ubuntu/Fedora/Arch: /etc/sudoers     @includedir /etc/sudoers.d
#   openSUSE (adminconf build): /usr/etc/sudoers @includedir /etc/sudoers.d
#                                                (+ /usr/etc/sudoers.d)
#   sudo-rs:                    /etc/sudoers-rs or /etc/sudoers
# We only ever write under /etc (prefer /etc/sudoers.d) — never a /usr/etc
# vendor dir (clobbered on update) — and never edit a main file in place.
# Echoes the dir and returns 0, or returns 1 (e.g. NixOS's generated sudoers
# with no writable include) so the caller skips with a warning. Both the old
# `@includedir` and legacy `#includedir` directive spellings are accepted.
find_sudoers_dropin() {
    local m d
    local -a incdirs=()
    for m in /etc/sudoers-rs /etc/sudoers /usr/etc/sudoers; do
        [[ -r "$m" ]] || continue
        while IFS= read -r d; do incdirs+=("$d"); done < <(
            grep -hE '^[[:space:]]*[#@]includedir[[:space:]]' "$m" 2>/dev/null \
                | sed -E 's/^[[:space:]]*[#@]includedir[[:space:]]+//; s/[[:space:]]+$//; s/^"(.*)"$/\1/'
        )
    done
    (( ${#incdirs[@]} )) || return 1      # no includedir anywhere (e.g. NixOS)
    for d in "${incdirs[@]}"; do          # prefer the standard admin drop-in
        [[ "$d" == /etc/sudoers.d ]] && { printf '%s\n' "$d"; return 0; }
    done
    for d in "${incdirs[@]}"; do          # else any included dir under /etc
        [[ "$d" == /etc/* ]] && { printf '%s\n' "$d"; return 0; }
    done
    return 1
}

# Wire pam_sentinel into a PAM service by COPYING its existing stack and
# inserting `auth sufficient pam_sentinel.so` just before the first
# `auth … include/substack` line. This:
#   * keeps the bypass first (it's sufficient → PAM_SUCCESS short-circuits),
#   * preserves leading auth lines like su's `pam_rootok.so` (root still
#     skips) and the vendor's session extras (pam_keyinit, …),
#   * leaves the distro's own include (common-auth on SUSE/Debian,
#     system-auth on Fedora) as the password fallback — so a denied/again
#     prompt and a disabled module both fall through to a real password.
# On openSUSE the base is /usr/lib/pam.d/<svc> and we create an /etc/pam.d
# shadow, so uninstall just deletes our file and the vendor stack returns.
# Idempotent; skips (warning) if the service has no base config — its
# package isn't installed, so there's nothing to guard.
SENTINEL_PAM_LINE='auth       sufficient pam_sentinel.so   # Sentinel-KDE: confirm instead of password'
wire_pam_service() {
    local svc="$1" base target="$SYSCONFDIR/pam.d/$1" tmp inserted=0 line
    if ! base="$(find_pam_base "$svc")"; then
        warn "No PAM config for '$svc' (package not installed?) — leaving it unguarded."
        return 0
    fi
    if [[ -f "$target" ]] && grep -q 'pam_sentinel\.so' "$target"; then
        return 0   # already wired (defensive; revert runs first on reinstall)
    fi
    tmp="$(mktemp)"
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ $inserted -eq 0 && "$line" =~ ^[[:space:]]*auth[[:space:]].*(include|substack) ]]; then
            printf '%s\n' "$SENTINEL_PAM_LINE" >> "$tmp"
            inserted=1
        fi
        printf '%s\n' "$line" >> "$tmp"
    done < "$base"
    if [[ $inserted -eq 0 ]]; then
        # No `auth … include` to anchor on (unusual): put Sentinel right after
        # the #%PAM-1.0 header so it still runs first.
        { printf '#%%PAM-1.0\n'; printf '%s\n' "$SENTINEL_PAM_LINE"; \
          grep -v '^[[:space:]]*#%PAM-1\.0[[:space:]]*$' "$base"; } > "$tmp"
    fi
    install_file 644 "$tmp" "$target"
    rm -f -- "$tmp"
}

# Run a `systemctl --user` command as the invoking user.
user_systemctl() {
    runuser -u "$BUILD_USER" -- env \
        XDG_RUNTIME_DIR="/run/user/$BUILD_UID" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$BUILD_UID/bus" \
        systemctl --user "$@"
}

# Replace semantics: if a previous install is recorded, cleanly revert it
# first. This makes re-installs idempotent, repairs a broken/partial prior
# state, and means installing the new build over an old one leaves nothing
# orphaned. Best-effort throughout — a
# missing backup or stale entry must never abort the fresh install.
revert_previous_install() {
    [[ -f "$STATE_FILE" ]] || return 0
    step "Existing install detected — reverting it before reinstalling…"
    while IFS=$'\t' read -r action path backup; do
        [[ -z "${action:-}" ]] && continue
        case "$action" in
            AGENTUNIT)  [[ -n "$BUILD_USER" && -n "$BUILD_UID" ]] && { user_systemctl disable --now "$path" 2>/dev/null || true; } ;;
            PLASMAMASK) [[ -n "$BUILD_USER" && -n "$BUILD_UID" ]] && { user_systemctl unmask "$path" 2>/dev/null || true; user_systemctl start "$path" 2>/dev/null || true; } ;;
            CREATED)    rm -f -- "$path" 2>/dev/null || true ;;
            REPLACED)   [[ -n "${backup:-}" && -f "$backup" ]] && { mv -f -- "$backup" "$path" 2>/dev/null || true; } ;;
        esac
    done < <(tac "$STATE_FILE")
    rm -f -- "$STATE_FILE"
    systemctl daemon-reload 2>/dev/null || true
    # If the prior install had dropped a polkit.service override (older
    # Sentinel did), restarting polkitd now drops it from the running process
    # so it's back to vendor hardening — the new socket path needs no override.
    systemctl try-restart polkit.service 2>/dev/null || true
}
revert_previous_install

# -------------- build (as the invoking user, not root) ---------------------

BUILD_CRATES=(-p pam-sentinel -p sentinel-polkit-agent -p sentinel-helper-kde -p sentinel-broker)

# Reuse prebuilt artifacts when they're all present (the common case after a
# `cargo build`); build only when something's missing or --rebuild is given.
artifacts_present() {
    [[ -f target/release/libpam_sentinel.so \
       && -f target/release/sentinel-polkit-agent \
       && -f target/release/sentinel-helper-kde \
       && -f target/release/sentinel-broker ]]
}
if [[ $FORCE_BUILD -eq 0 ]] && artifacts_present; then
    step "Using existing target/release artifacts (pass --rebuild to force a build)."
else
    step "Building (cargo --release)${BUILD_USER:+ as $BUILD_USER}…"
    # cxx-qt-build 0.9 needs QMAKE pointed at the system qmake6 (it no longer
    # auto-discovers Qt). Detect it so the helper crate compiles; harmless for
    # the pure-Rust crates.
    QMAKE_BIN="${QMAKE:-$(command -v qmake6 || command -v qmake-qt6 || command -v qmake || true)}"
    build_cmd=(env
        SENTINEL_PREFIX="$PREFIX" SENTINEL_SYSCONFDIR="$SYSCONFDIR"
        SENTINEL_LIBEXECDIR="$LIBEXECDIR" SENTINEL_HELPER_PATH="$HELPER_PATH"
        QMAKE="$QMAKE_BIN"
        cargo build --release --locked "${BUILD_CRATES[@]}")
    if [[ -n "$BUILD_USER" ]] && command -v runuser >/dev/null 2>&1; then
        runuser -u "$BUILD_USER" -- "${build_cmd[@]}"
    else
        "${build_cmd[@]}"
    fi
fi

for a in libpam_sentinel.so sentinel-polkit-agent sentinel-helper-kde sentinel-broker; do
    [[ -f "target/release/$a" ]] || error "Build artifact missing: target/release/$a"
done

# -------------- install ----------------------------------------------------

mkdir -p "$STATE_DIR"
printf 'VERSION\t%s\t\n' "$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' Cargo.toml | head -1)" >> "$STATE_TMP"

step "Installing system files…"
install_file 755 target/release/sentinel-helper-kde   "$HELPER_PATH"
install_file 755 target/release/sentinel-polkit-agent "$PREFIX/$LIBEXECDIR/sentinel-polkit-agent"
install_file 755 target/release/sentinel-broker       "$PREFIX/$LIBEXECDIR/sentinel-broker"
# pam_sentinel.so needs 0755 — some polkit helper sandboxes (NoNewPrivileges)
# make libpam refuse to dlopen .so files without the executable bit.
install_file 755 target/release/libpam_sentinel.so    "$PAM_MODULE_DIR/pam_sentinel.so"

install_file 644 config/sentinel.conf                 "$SYSCONFDIR/security/sentinel.conf"

# Wire pam_sentinel into polkit's PAM stack (this is what makes pkexec /
# polkit prompts show the Sentinel dialog). Prepend-in-place onto the
# distro's own polkit-1 stack — see wire_pam_service.
wire_pam_service polkit-1

# systemd *user* unit for the agent (registers cleanly on Plasma 6).
install_file 644 packaging-kde/packaging/systemd/user/sentinel-polkit-agent.service \
    "$PREFIX/lib/systemd/user/sentinel-polkit-agent.service"

# Bypass channel = the system D-Bus. The agent claims org.sentinel.Agent and
# pam_sentinel.so (root, inside the polkitd-forked helper-1) calls it to
# consume a pre-approval. On SELinux this rides the existing
# `policykit_t -> userdomain dbus send_msg` allow (same path pam_fprintd
# uses), so NO custom SELinux/AppArmor policy and NO polkit.service override
# are needed. This D-Bus policy lets the user own the name + lets root call it.
install_file 644 packaging-kde/packaging/dbus/org.sentinel.Agent.conf \
    "$PREFIX/share/dbus-1/system.d/org.sentinel.Agent.conf"
# Reload the system bus so it picks up the new policy before the agent (below)
# tries to claim the name. reload (SIGHUP), not restart — no client disconnects.
systemctl reload dbus.service 2>/dev/null || systemctl reload dbus-broker.service 2>/dev/null || true

# Remember-decision broker (system service): backs the terminal sudo/su
# remember window. Unprivileged daemon (DynamicUser); pam_sentinel relays
# to it over a Unix socket and fails closed if it's down. ExecStart is
# templated to the chosen libexec dir.
BROKER_UNIT_TMP="$(mktemp)"
sed "s|@LIBEXEC@|$PREFIX/$LIBEXECDIR|" packaging/systemd/sentinel-broker.service > "$BROKER_UNIT_TMP"
install_file 644 "$BROKER_UNIT_TMP" "$SYSCONFDIR/systemd/system/sentinel-broker.service"
rm -f "$BROKER_UNIT_TMP"
# Enable+start now when systemd is the init (skipped cleanly in containers).
systemctl daemon-reload 2>/dev/null || true
systemctl enable --now sentinel-broker.service 2>/dev/null || true

# Polkit admin rule: Sentinel's no-password model needs the logged-in user
# to be a polkit administrator (you confirm your own escalation). Without
# it, auth_admin actions (pkexec) authenticate root — whose session has no
# Sentinel agent — and the bypass can't be honored. root stays an admin.
if [[ -n "$BUILD_USER" ]]; then
    rule_tmp="$(mktemp)"
    cat > "$rule_tmp" <<RULE
// SPDX-License-Identifier: GPL-3.0-or-later
// Installed by Sentinel-KDE. Makes the logged-in user a polkit
// administrator so the no-password confirmation works for auth_admin
// actions (e.g. pkexec). root remains an administrator.
polkit.addAdminRule(function(action, subject) {
    return ["unix-user:$BUILD_USER", "unix-user:0"];
});
RULE
    install_file 644 "$rule_tmp" "$SYSCONFDIR/polkit-1/rules.d/49-sentinel-admin.rules"
    rm -f -- "$rule_tmp"
else
    warn "No invoking user — skipping the polkit admin rule. auth_admin (pkexec)"
    warn "will fall back to a password unless you add the rule yourself."
fi

# Also guard terminal escalation (sudo / sudo -i / su). Same prepend-in-place
# treatment so each keeps its real password fallback (and su keeps pam_rootok,
# so root still su's without a prompt). On by default; --no-sudo opts out.
if [[ $INSTALL_SUDO -eq 1 ]]; then
    for svc in sudo sudo-i su; do
        wire_pam_service "$svc"
    done

    # Make Sentinel the SINGLE source of sudo "remember". sudo's own
    # credential cache (timestamp_timeout, ~5 min) lets a back-to-back
    # `sudo` skip the PAM stack entirely — so Sentinel never sees it and our
    # per-command window is bypassed by sudo's blanket session cache. Drop
    # `Defaults timestamp_timeout=0` so every sudo runs PAM; Sentinel's
    # broker-backed, per-command remember is then the only layer. Honored by
    # classic sudo AND sudo-rs. Placed in whatever drop-in dir the active
    # sudoers actually includes (find_sudoers_dropin handles /etc/sudoers,
    # openSUSE's /usr/etc/sudoers, and sudo-rs). Best-effort: warns — never a
    # hard fail — if visudo is missing, no safe drop-in exists (e.g. NixOS),
    # or the snippet won't validate. A broken sudoers can lock out root, so we
    # validate before writing and never touch a main file in place.
    if ! command -v visudo >/dev/null 2>&1; then
        warn "visudo not found — skipped sudo timestamp override (set 'Defaults timestamp_timeout=0' yourself)."
    elif sudoers_dropin="$(find_sudoers_dropin)"; then
        ts_tmp="$(mktemp)"
        printf '# Installed by Sentinel — do not edit.\n# Disable sudo credential caching so every sudo runs the PAM stack and\n# Sentinel'\''s per-command remember is the only cache. Remove to restore\n# sudo'\''s default ~5-minute timestamp.\nDefaults timestamp_timeout=0\n' > "$ts_tmp"
        if visudo -cf "$ts_tmp" >/dev/null 2>&1; then
            install_file 440 "$ts_tmp" "$sudoers_dropin/sentinel-timestamp"
            step "Disabled sudo credential caching via $sudoers_dropin/sentinel-timestamp (Sentinel is now the only sudo remember)."
        else
            warn "sudoers snippet failed visudo validation — left sudo caching as-is."
        fi
        rm -f "$ts_tmp"
    else
        warn "No sudoers.d includedir found under /etc — skipped sudo timestamp override."
        warn "  Add 'Defaults timestamp_timeout=0' to your sudoers so Sentinel is the only sudo cache."
    fi
fi

# Agent shell completions + man pages.
step "Generating completions + man pages…"
GEN_DIR="$(mktemp -d)"
target/release/sentinel-polkit-agent completions bash > "$GEN_DIR/c.bash"
target/release/sentinel-polkit-agent completions fish > "$GEN_DIR/c.fish"
target/release/sentinel-polkit-agent completions zsh  > "$GEN_DIR/_c"
target/release/sentinel-polkit-agent man              > "$GEN_DIR/c.1"
install_file 644 "$GEN_DIR/c.bash" "$PREFIX/share/bash-completion/completions/sentinel-polkit-agent"
install_file 644 "$GEN_DIR/c.fish" "$PREFIX/share/fish/vendor_completions.d/sentinel-polkit-agent.fish"
install_file 644 "$GEN_DIR/_c"     "$PREFIX/share/zsh/site-functions/_sentinel-polkit-agent"
install_file 644 "$GEN_DIR/c.1"    "$PREFIX/share/man/man1/sentinel-polkit-agent.1"
install_file 644 packaging-kde/packaging/man/sentinel.conf.5 "$PREFIX/share/man/man5/sentinel.conf.5"
install_file 644 packaging-kde/packaging/man/pam_sentinel.8  "$PREFIX/share/man/man8/pam_sentinel.8"
rm -rf "$GEN_DIR"

# -------------- verify -----------------------------------------------------

step "Verifying installed files…"
verify() {
    local path="$1" mode="$2" kind="$3" actual owner
    [[ -e "$path" ]] || error "Missing after install: $path"
    [[ "$kind" == exe && ! -x "$path" ]] && error "Not executable: $path"
    actual="$(stat -c '%a' "$path" 2>/dev/null || echo '?')"
    [[ "$actual" == "$mode" ]] || error "Wrong mode on $path: got $actual, want $mode"
    owner="$(stat -c '%u:%g' "$path" 2>/dev/null || echo '?:?')"
    [[ "$owner" == "0:0" ]] || error "Wrong ownership on $path: got $owner, want 0:0"
}
verify "$HELPER_PATH"                                   755 exe
verify "$PREFIX/$LIBEXECDIR/sentinel-polkit-agent"     755 exe
verify "$PAM_MODULE_DIR/pam_sentinel.so"               755 regular
verify "$SYSCONFDIR/security/sentinel.conf"            644 regular
verify "$SYSCONFDIR/pam.d/polkit-1"                    644 regular
grep -q 'pam_sentinel\.so' "$SYSCONFDIR/pam.d/polkit-1" \
    || error "polkit-1 wiring failed: pam_sentinel line is missing from $SYSCONFDIR/pam.d/polkit-1"
verify "$PREFIX/lib/systemd/user/sentinel-polkit-agent.service" 644 regular
verify "$PREFIX/share/dbus-1/system.d/org.sentinel.Agent.conf" 644 regular
[[ -n "$BUILD_USER" ]] && verify "$SYSCONFDIR/polkit-1/rules.d/49-sentinel-admin.rules" 644 regular
# sudo/su are best-effort (skipped when the package isn't installed); verify
# only what actually got wired.
if [[ $INSTALL_SUDO -eq 1 ]]; then
    for svc in sudo sudo-i su; do
        [[ -f "$SYSCONFDIR/pam.d/$svc" ]] && verify "$SYSCONFDIR/pam.d/$svc" 644 regular
    done
    # The sudo timestamp override is best-effort (skipped if no safe drop-in);
    # verify it only at the dir we actually chose, and only if installed.
    if [[ -n "${sudoers_dropin:-}" && -f "$sudoers_dropin/sentinel-timestamp" ]]; then
        verify "$sudoers_dropin/sentinel-timestamp" 440 regular
    fi
fi

systemctl daemon-reload 2>/dev/null || true
# Note: we deliberately do NOT touch polkit.service anymore. The bypass socket
# lives in /run/sentinel (reachable from polkitd's sandbox as-is), so polkitd
# keeps its full vendor hardening — nothing to restart.

# -------------- commit -----------------------------------------------------

mv -f -- "$STATE_TMP" "$STATE_FILE"
chmod 644 "$STATE_FILE"
rm -f -- "$ROLLBACK_LOG"
INSTALL_OK=1

# -------------- activate (systemd --user; reversible, post-commit) ----------

AGENT_OK=0
activate_agent() {
    if [[ -z "$BUILD_USER" || -z "$BUILD_UID" ]] || ! command -v runuser >/dev/null 2>&1; then
        warn "No invoking user; activate after login with:"
        warn "  systemctl --user mask --now plasma-polkit-agent.service"
        warn "  systemctl --user enable --now sentinel-polkit-agent.service"
        return 0
    fi
    if [[ ! -S "/run/user/$BUILD_UID/bus" ]]; then
        warn "No user D-Bus for $BUILD_USER; the agent activates at next login."
        return 0
    fi
    step "Activating Sentinel as the polkit agent (systemd --user)…"
    user_systemctl daemon-reload 2>/dev/null || true
    if user_systemctl mask --now plasma-polkit-agent.service 2>/dev/null; then
        printf 'PLASMAMASK\tplasma-polkit-agent.service\t%s\n' "$BUILD_UID" >> "$STATE_FILE"
    else
        warn "Could not mask plasma-polkit-agent.service (continuing)."
    fi
    local mark; mark=$(date '+%Y-%m-%d %H:%M:%S')
    if user_systemctl enable --now sentinel-polkit-agent.service 2>/dev/null; then
        printf 'AGENTUNIT\tsentinel-polkit-agent.service\t%s\n' "$BUILD_UID" >> "$STATE_FILE"
        for _ in $(seq 1 15); do
            sleep 0.2
            if journalctl -t sentinel-polkit-agent --since "$mark" --no-pager 2>/dev/null \
                 | grep -q "registered as polkit auth agent"; then AGENT_OK=1; break; fi
        done
    else
        warn "Could not enable/start the agent now; it activates at next login."
    fi
}
activate_agent || true

# -------------- done -------------------------------------------------------

# Silent on success, like a normal package install. `-v` prints the summary;
# the only thing worth saying in quiet mode is when the user must act (the
# agent couldn't auto-activate, so they need to re-login).
if [[ $VERBOSE -eq 1 ]]; then
    if [[ $AGENT_OK -eq 1 ]]; then
        say "Sentinel-KDE installed and active. Test with: pkexec true   (remove: sudo ./uninstall.sh)"
    else
        say "Sentinel-KDE installed. Log out and back in to activate, then: pkexec true   (remove: sudo ./uninstall.sh)"
    fi
    cat <<EOF
  installed:
    $PAM_MODULE_DIR/pam_sentinel.so
    $PREFIX/$LIBEXECDIR/sentinel-polkit-agent  (systemd --user service)
    $HELPER_PATH
    $SYSCONFDIR/pam.d/polkit-1                  (original saved as .pre-sentinel.bak)
    $SYSCONFDIR/security/sentinel.conf
    ${BUILD_USER:+$SYSCONFDIR/polkit-1/rules.d/49-sentinel-admin.rules (admin: $BUILD_USER)}
  state: $STATE_FILE
EOF
elif [[ $AGENT_OK -ne 1 ]]; then
    warn "Sentinel-KDE installed but the agent isn't active yet — log out and back in."
fi
