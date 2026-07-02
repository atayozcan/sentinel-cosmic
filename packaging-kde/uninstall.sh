#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025 Atay Özcan <atay@oezcan.me>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Sentinel-KDE uninstaller.
#
# Reads /var/lib/sentinel/install.state and replays each entry in reverse
# to restore the system to its exact pre-install state: disables Sentinel's
# agent user service, unmasks + restarts plasma-polkit-agent, removes the
# installed files, and restores any backed-up originals. Idempotent. Falls
# back to best-effort path-based cleanup if the state file is missing.

set -Eeuo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
VERBOSE=0
say()   { printf '%s\n' "$*"; }
info()  { if [[ $VERBOSE -eq 1 ]]; then printf '  %s\n' "$*"; fi; }
step()  { info "$@"; }
warn()  { printf "${YELLOW}warning:${NC} %s\n" "$*" >&2; }
error() { printf "${RED}error:${NC} %s\n" "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || error "Run as root (use pkexec or sudo)."

PREFIX=${PREFIX:-/usr}
SYSCONFDIR=${SYSCONFDIR:-/etc}
LIBEXECDIR=${LIBEXECDIR:-lib}
STATE_DIR="/var/lib/sentinel"
STATE_FILE="$STATE_DIR/install.state"

ASSUME_YES=0
for arg in "$@"; do
    case "$arg" in -y|--yes) ASSUME_YES=1 ;; -v|--verbose) VERBOSE=1 ;; esac
done
if [[ -t 0 && -t 1 ]]; then
    read -r -p "Remove Sentinel? [y/N] " reply
    [[ "$reply" =~ ^[Yy]$ ]] || { info "Aborted."; exit 0; }
elif [[ $ASSUME_YES -eq 0 ]]; then
    error "Refusing to uninstall non-interactively. Pass -y/--yes to confirm."
fi

# Run a `systemctl --user` command as the user owning <uid>.
user_systemctl() {
    local uid="$1"; shift
    local user; user="$(getent passwd "$uid" | cut -d: -f1 || true)"
    [[ -n "$user" ]] || { warn "no user for uid $uid; skipping systemctl --user $*"; return 0; }
    command -v runuser >/dev/null 2>&1 || { warn "runuser missing; skipping systemctl --user $*"; return 0; }
    runuser -u "$user" -- env \
        XDG_RUNTIME_DIR="/run/user/$uid" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
        systemctl --user "$@" 2>/dev/null || warn "systemctl --user $* failed (continuing)"
}

# Stop + disable the system broker before its unit/binary are removed
# (by the state loop or fallback below). Guarded for non-systemd envs.
systemctl disable --now sentinel-broker.service 2>/dev/null || true

# -------------- state-file driven uninstall --------------------------------

if [[ -f "$STATE_FILE" ]]; then
    step "Restoring pre-install state from $STATE_FILE…"
    failures=0
    while IFS=$'\t' read -r action path backup; do
        [[ -z "${action:-}" ]] && continue
        case "$action" in
            AGENTUNIT)
                step "Disabling Sentinel agent service (uid $backup)…"
                user_systemctl "$backup" disable --now "$path"
                ;;
            PLASMAMASK)
                step "Re-enabling $path (uid $backup)…"
                user_systemctl "$backup" unmask "$path"
                user_systemctl "$backup" start "$path"   # restore polkit-kde now
                ;;
            CREATED)
                if [[ -e "$path" ]]; then
                    rm -f -- "$path" && info "Removed $path" || { warn "Could not remove $path"; failures=$((failures+1)); }
                else
                    warn "Already gone: $path"
                fi
                ;;
            REPLACED)
                if [[ -n "${backup:-}" && -f "$backup" ]]; then
                    mv -f -- "$backup" "$path" && info "Restored $path from backup" || { warn "Could not restore $path"; failures=$((failures+1)); }
                else
                    warn "Backup missing for $path; leaving current file in place"
                fi
                ;;
            VERSION) ;;
            *) warn "Unknown state entry: $action $path" ;;
        esac
    done < <(tac "$STATE_FILE")

    systemctl daemon-reload 2>/dev/null || true
    # Reload the bus so the removed org.sentinel.Agent policy stops applying.
    systemctl reload dbus.service 2>/dev/null || systemctl reload dbus-broker.service 2>/dev/null || true
    # Restart polkit only if a prior install had dropped a polkit.service
    # override (older Sentinel did; current installs don't touch it).
    systemctl try-restart polkit.service 2>/dev/null || true
    rm -rf -- /run/sentinel 2>/dev/null || true   # legacy runtime dir from older installs
    rm -f -- "$STATE_FILE"
    rmdir --ignore-fail-on-non-empty "$STATE_DIR" 2>/dev/null || true

    [[ $failures -gt 0 ]] && warn "finished with $failures non-fatal issue(s) (re-run with -v for detail)."
    say "Sentinel-KDE removed; polkit-kde restored. Log out and back in if GUI auth misbehaves."
    exit 0
fi

# -------------- fallback (no state file) -----------------------------------

warn "No install state file at $STATE_FILE; falling back to best-effort removal."

# Best-effort: disable Sentinel's unit + restore plasma for the live user.
for uid in /run/user/*; do
    uid="${uid##*/}"; [[ "$uid" =~ ^[0-9]+$ ]] || continue
    user_systemctl "$uid" disable --now sentinel-polkit-agent.service
    user_systemctl "$uid" unmask plasma-polkit-agent.service
    user_systemctl "$uid" start plasma-polkit-agent.service
done

# Files Sentinel wholly owns — safe to restore-or-remove outright.
FALLBACK_OWNED=(
    "/usr/lib64/security/pam_sentinel.so"
    "/usr/lib/security/pam_sentinel.so"
    "$PREFIX/$LIBEXECDIR/sentinel-helper-kde"
    "$PREFIX/$LIBEXECDIR/sentinel-polkit-agent"
    "$PREFIX/$LIBEXECDIR/sentinel-broker"
    "$PREFIX/lib/systemd/user/sentinel-polkit-agent.service"
    "$SYSCONFDIR/systemd/system/sentinel-broker.service"
    "$SYSCONFDIR/security/sentinel.conf"
    "$SYSCONFDIR/sudoers.d/sentinel-timestamp"
    "$SYSCONFDIR/polkit-1/rules.d/49-sentinel-admin.rules"
    "$PREFIX/share/dbus-1/system.d/org.sentinel.Agent.conf"
    "$PREFIX/lib/tmpfiles.d/sentinel.conf"
    "$SYSCONFDIR/systemd/system/polkit.service.d/sentinel.conf"
    "$SYSCONFDIR/systemd/system/polkit-agent-helper@.service.d/sentinel.conf"
    "$PREFIX/share/man/man1/sentinel-polkit-agent.1"
    "$PREFIX/share/man/man5/sentinel.conf.5"
    "$PREFIX/share/man/man8/pam_sentinel.8"
    "$PREFIX/share/bash-completion/completions/sentinel-polkit-agent"
    "$PREFIX/share/fish/vendor_completions.d/sentinel-polkit-agent.fish"
    "$PREFIX/share/zsh/site-functions/_sentinel-polkit-agent"
)
for p in "${FALLBACK_OWNED[@]}"; do
    if [[ -e "$p" ]]; then
        if [[ -f "${p}.pre-sentinel.bak" ]]; then
            mv -f -- "${p}.pre-sentinel.bak" "$p" && info "Restored $p from backup"
        else
            rm -f -- "$p" && info "Removed $p"
        fi
    fi
done

# Distro PAM stacks Sentinel only EDITED in place (prepended one line).
# These belong to the distro, not us — deleting one locks out that
# service. So: restore the backup if we have it; otherwise strip just our
# line if present; and NEVER remove the file. A file with no backup and no
# Sentinel line is left untouched (it was never ours to begin with).
FALLBACK_SHARED_PAM=(
    "$SYSCONFDIR/pam.d/polkit-1"
    "$SYSCONFDIR/pam.d/sudo"
    "$SYSCONFDIR/pam.d/sudo-i"
    "$SYSCONFDIR/pam.d/su"
)
for p in "${FALLBACK_SHARED_PAM[@]}"; do
    [[ -e "$p" ]] || continue
    if [[ -f "${p}.pre-sentinel.bak" ]]; then
        mv -f -- "${p}.pre-sentinel.bak" "$p" && info "Restored $p from backup"
    elif grep -q 'pam_sentinel\.so' "$p" 2>/dev/null; then
        # No backup, but our line is here — remove just that line, leaving
        # the distro's own stack intact.
        if sed -i '/pam_sentinel\.so/d' "$p"; then
            info "Stripped Sentinel line from $p (no backup found)"
        else
            warn "Could not strip Sentinel line from $p — leaving as-is"
        fi
    fi
    # else: not ours (no backup, no Sentinel line) — leave it completely alone.
done
rm -rf -- /run/sentinel 2>/dev/null || true   # legacy runtime dir from older installs
systemctl daemon-reload 2>/dev/null || true
systemctl reload dbus.service 2>/dev/null || systemctl reload dbus-broker.service 2>/dev/null || true
systemctl try-restart polkit.service 2>/dev/null || true   # only matters if an older install dropped a polkit override
say "Sentinel-KDE removed (fallback mode). Log out and back in to fully restore polkit-kde."
