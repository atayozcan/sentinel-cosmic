#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Atay Özcan <atay@oezcan.me>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# scripts/release-local.sh — fully-local, reproducible release matrix.
#
# Replaces the GitHub release workflow. Builds + packages on two machines
# you control (no CI):
#   * THIS host  — native build for its own arch (aarch64 on `orion`).
#   * $ASUS_HOST — native build for x86_64, and `makepkg` for BOTH arches
#                  (Arch `.pkg.tar.zst` is just packaging prebuilt binaries,
#                  so it cross-packages fine with CARCH set).
#
# Per arch it emits:  .pkg.tar.zst (Arch) · .deb · .rpm · prebuilt bundle
# tarball + .sha256.  The AUR `sentinel-kde` PKGBUILD is binary (sources the
# bundle tarball); `release-local.sh --stage aur` fills its per-arch sums.
#
# Reproducibility knobs (so two runs of the same commit match):
#   * pinned toolchain  ($REPRO_TOOLCHAIN, installed via rustup if missing)
#   * SOURCE_DATE_EPOCH = the commit's author date (deterministic mtimes)
#   * --remap-path-prefix  strips $HOME / repo paths out of the binaries
#   * Cargo.lock pinned (--locked); per-arch target-cpu baseline
#
# Usage:
#   scripts/release-local.sh                 # full matrix → dist/
#   scripts/release-local.sh --arch aarch64  # one arch only (local)
#   scripts/release-local.sh --worker        # internal: build+package local host
#   scripts/release-local.sh --stage aur     # fill AUR PKGBUILD sums from dist/
set -Eeuo pipefail

# ---- config (env-overridable) ---------------------------------------------
ASUS_HOST="${ASUS_HOST:-asus}"
REMOTE_REPO="${REMOTE_REPO:-/home/atay/Projects/sentinel}"
REPRO_TOOLCHAIN="${REPRO_TOOLCHAIN:-1.96.0}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
# cargo-installed subcommands (cargo-deb, cargo-generate-rpm) live here but
# aren't always on a non-login shell's PATH.
export PATH="$HOME/.cargo/bin:$PATH"

VERSION="$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' Cargo.toml | head -1)"
DIST="$REPO_ROOT/dist"
PKGCRATES=(-p pam-sentinel -p sentinel-polkit-agent -p sentinel-broker -p sentinel-helper-kde)

c() { printf '\033[1;36m==> %s\033[0m\n' "$*"; }
die() { printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

# ---- reproducible build env (applied on whichever host builds) -------------
setup_repro_env() {
    export SOURCE_DATE_EPOCH="$(git -C "$REPO_ROOT" log -1 --format=%ct)"
    export SENTINEL_PREFIX=/usr SENTINEL_SYSCONFDIR=/etc SENTINEL_LIBEXECDIR=lib
    export SENTINEL_HELPER_PATH=/usr/lib/sentinel-helper-kde
    # Strip machine-specific paths from the binaries for reproducibility.
    local remap="--remap-path-prefix=$HOME=/ --remap-path-prefix=$REPO_ROOT=/src"
    local linker target_cpu=""
    case "$(uname -m)" in
        x86_64)  linker="mold";              target_cpu="-C target-cpu=x86-64-v3" ;;
        aarch64) linker="bfd";               target_cpu="" ;;  # rust-lld bug on this aarch64 box
        *) die "unsupported build arch $(uname -m)" ;;
    esac
    export RUSTFLAGS="-C link-arg=-fuse-ld=$linker $target_cpu $remap"
    if command -v rustup >/dev/null 2>&1; then
        rustup toolchain list 2>/dev/null | grep -q "^$REPRO_TOOLCHAIN" \
            || { c "installing pinned toolchain $REPRO_TOOLCHAIN"; rustup toolchain install --no-self-update "$REPRO_TOOLCHAIN"; }
        CARGOPIN="+$REPRO_TOOLCHAIN"
    else
        c "rustup not found — using system cargo ($(cargo --version 2>/dev/null)); toolchain pin skipped"
        CARGOPIN=""
    fi
    export CARGOPIN
}

# ---- build + assemble the per-arch prebuilt bundle (runs on the build host) -
build_bundle() {
    setup_repro_env
    local arch; arch="$(uname -m)"
    c "build ($arch, toolchain $REPRO_TOOLCHAIN, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH)"
    cargo ${CARGOPIN} build --release --locked "${PKGCRATES[@]}"

    c "generate completions + man (arch-independent)"
    install -d target/release/share
    local a=target/release/sentinel-polkit-agent
    "$a" completions bash > target/release/share/sentinel-polkit-agent.bash
    "$a" completions fish > target/release/share/sentinel-polkit-agent.fish
    "$a" completions zsh  > target/release/share/_sentinel-polkit-agent
    "$a" man              > target/release/share/sentinel-polkit-agent.1

    c "assemble bundle (repo layout + prebuilt binaries)"
    local b="$DIST/sentinel-kde-$VERSION"
    rm -rf "$b"; mkdir -p "$b/target/release/share" "$b/config" "$b/packaging-kde" "$b/packaging"
    cp target/release/{libpam_sentinel.so,sentinel-polkit-agent,sentinel-broker,sentinel-helper-kde} "$b/target/release/"
    cp target/release/share/* "$b/target/release/share/"
    cp -a config/. "$b/config/"
    cp -a packaging-kde/install.sh packaging-kde/uninstall.sh packaging-kde/packaging packaging-kde/scripts "$b/packaging-kde/"
    cp -a packaging/systemd packaging/dbus packaging/man "$b/packaging/" 2>/dev/null || true
    cp -a Cargo.toml README.md LICENSE "$b/"
    # Deterministic tarball (sorted, fixed mtime/owner).
    local tar="$DIST/sentinel-kde-$VERSION-$arch-linux.tar.gz"
    tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
        -C "$DIST" -czf "$tar" "sentinel-kde-$VERSION"
    ( cd "$DIST" && sha256sum "$(basename "$tar")" > "$(basename "$tar").sha256" )
    c "bundle → $tar"
}

# ---- deb + rpm for the local (native) arch (cargo plugins) -----------------
pkg_deb_rpm() {
    local arch; arch="$(uname -m)"
    local bundle="$DIST/sentinel-kde-$VERSION-$arch-linux.tar.gz"
    [ -f "$bundle" ] || { c "no bundle for .deb/.rpm ($arch); skipping"; return 0; }
    # Stage the bundle at the fixed path the Cargo.toml deb/rpm metadata
    # references (so the package ships it + runs install.sh in post-install).
    cp "$bundle" target/release/sentinel-kde-bundle.tar.gz
    if command -v cargo-deb >/dev/null 2>&1; then
        c "package .deb ($arch)"
        cargo deb --no-build -p sentinel-helper-kde >/dev/null && cp -f target/debian/*.deb "$DIST/"
    else c ".deb skipped (cargo-deb not installed)"; fi
    if command -v cargo-generate-rpm >/dev/null 2>&1; then
        c "package .rpm ($arch)"
        cargo generate-rpm -p crates/sentinel-helper-kde >/dev/null && cp -f target/generate-rpm/*.rpm "$DIST/"
    else c ".rpm skipped (cargo-generate-rpm not installed)"; fi
}

# ---- Arch .pkg.tar.zst from a bundle (runs on asus; CARCH per arch) --------
pkg_arch() {
    local arch="$1" bundle="$2"   # bundle = path to extracted sentinel-kde-$VERSION
    command -v makepkg >/dev/null || die "makepkg not found (run on the Arch host)"
    c "makepkg .pkg.tar.zst ($arch)"
    local work; work="$(mktemp -d)"
    cp "$REPO_ROOT/packaging-kde/packaging/arch/PKGBUILD" "$REPO_ROOT/packaging-kde/packaging/arch/sentinel-kde.install" \
       "$REPO_ROOT/packaging-kde/packaging/arch/49-sentinel-admin.rules" "$work/"
    # Point the binary PKGBUILD at the LOCAL bundle instead of downloading.
    sed -i "s#^source_$arch=.*#source_$arch=(\"sentinel-kde-$VERSION-$arch.tar.gz\")#" "$work/PKGBUILD"
    cp "$DIST/sentinel-kde-$VERSION-$arch-linux.tar.gz" "$work/sentinel-kde-$VERSION-$arch.tar.gz"
    ( cd "$work" && CARCH="$arch" PKGEXT='.pkg.tar.zst' PKGDEST="$DIST" \
        SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" makepkg -df --skipinteg --noconfirm )
    rm -rf "$work"
}

# ---- modes -----------------------------------------------------------------
case "${1:-}" in
    --bundle)            # build + assemble the reproducible bundle only (testing)
        mkdir -p "$DIST"; build_bundle; exit 0 ;;
    --debrpm)            # build .deb + .rpm from an existing bundle (no recompile)
        mkdir -p "$DIST"; export SOURCE_DATE_EPOCH="$(git -C "$REPO_ROOT" log -1 --format=%ct)"
        pkg_deb_rpm; ls -1 "$DIST"/*.deb "$DIST"/*.rpm 2>/dev/null; exit 0 ;;
    --pkg-arch)          # makepkg one arch from an already-extracted bundle (asus)
        [ -n "${2:-}" ] || die "usage: --pkg-arch <arch>"
        setup_repro_env; pkg_arch "$2" "$DIST/sentinel-kde-$VERSION"; exit 0 ;;
    --worker)            # build+package this host's native arch (used over ssh)
        mkdir -p "$DIST"; build_bundle; pkg_deb_rpm
        [ "$(uname -m)" = x86_64 ] && command -v makepkg >/dev/null && {
            tar -C "$DIST" -xzf "$DIST/sentinel-kde-$VERSION-x86_64-linux.tar.gz"
            pkg_arch x86_64 "$DIST/sentinel-kde-$VERSION"; }
        exit 0 ;;
    --arch)              # local single-arch build (testing)
        mkdir -p "$DIST"; build_bundle; pkg_deb_rpm; exit 0 ;;
    --stage)             # fill AUR PKGBUILD sha256sums from dist/
        [ "${2:-}" = aur ] || die "usage: --stage aur"
        pk="packaging-kde/packaging/arch/PKGBUILD"
        for a in x86_64 aarch64; do
            s="$(sha256sum "$DIST/sentinel-kde-$VERSION-$a-linux.tar.gz" 2>/dev/null | cut -d' ' -f1)" || continue
            sed -i "s#^sha256sums_$a=.*#sha256sums_$a=('$s')#" "$pk"
        done
        c "AUR PKGBUILD sums filled for $VERSION"; exit 0 ;;
esac

# ---- full matrix orchestration --------------------------------------------
mkdir -p "$DIST"
c "Sentinel $VERSION — local release matrix"
# Fail before the (long) local build if the x86_64 worker is unreachable.
ssh -o ConnectTimeout=5 -o BatchMode=yes "$ASUS_HOST" true 2>/dev/null \
    || die "worker $ASUS_HOST unreachable over ssh — full matrix needs it (or run --arch for this host only)"

c "[1/4] aarch64 (this host)"; build_bundle; pkg_deb_rpm

c "[2/4] x86_64 (+ both .pkg) on $ASUS_HOST"
git push -q origin HEAD 2>/dev/null || true
ssh "$ASUS_HOST" "cd $REMOTE_REPO && git fetch -q origin && git checkout -q $(git rev-parse HEAD) && scripts/release-local.sh --worker"

c "[3/4] collect x86_64 artefacts + cross-package aarch64 .pkg"
scp -q "$ASUS_HOST:$REMOTE_REPO/dist/*x86_64*" "$ASUS_HOST:$REMOTE_REPO/dist/*.pkg.tar.zst" "$DIST/" 2>/dev/null || true
# aarch64 .pkg: send our bundle to asus, makepkg there, pull back.
scp -q "$DIST/sentinel-kde-$VERSION-aarch64-linux.tar.gz" "$ASUS_HOST:$REMOTE_REPO/dist/" 2>/dev/null
ssh "$ASUS_HOST" "cd $REMOTE_REPO && tar -C dist -xzf dist/sentinel-kde-$VERSION-aarch64-linux.tar.gz && \
    SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) scripts/release-local.sh --pkg-arch aarch64" 2>/dev/null || true
scp -q "$ASUS_HOST:$REMOTE_REPO/dist/*aarch64*.pkg.tar.zst" "$DIST/" 2>/dev/null || true

c "[4/4] checksums + manifest"
( cd "$DIST" && for f in *.pkg.tar.zst *.deb *.rpm; do [ -f "$f" ] && sha256sum "$f" > "$f.sha256"; done; ls -1 )

# The scp/ssh legs above are `|| true` (partial matrices are useful while
# iterating), so verify the FULL matrix explicitly rather than shipping a
# release with a silently-missing artefact.
missing=0
pkgrel="$(sed -n 's/^pkgrel=//p' packaging-kde/packaging/arch/PKGBUILD)"
for f in \
    "sentinel-kde-$VERSION-x86_64-linux.tar.gz" \
    "sentinel-kde-$VERSION-aarch64-linux.tar.gz" \
    "sentinel-kde-$VERSION-${pkgrel:-1}-x86_64.pkg.tar.zst" \
    "sentinel-kde-$VERSION-${pkgrel:-1}-aarch64.pkg.tar.zst" \
    "sentinel-kde_$VERSION-1_amd64.deb" \
    "sentinel-kde_$VERSION-1_arm64.deb" \
    "sentinel-kde-$VERSION-1.x86_64.rpm" \
    "sentinel-kde-$VERSION-1.aarch64.rpm"
do
    [ -f "$DIST/$f" ] || { printf '\033[1;31mmissing: %s\033[0m\n' "$f" >&2; missing=1; }
done
[ "$missing" = 0 ] || die "release matrix incomplete — see missing artefacts above"

"$0" --stage aur
c "Done. Artefacts in $DIST/. Next: commit the PKGBUILD sums, then: gh release create v$VERSION dist/*"
