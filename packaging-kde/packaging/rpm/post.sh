#!/bin/sh
# SPDX-FileCopyrightText: 2026 Atay Özcan <atay@oezcan.me>
# SPDX-License-Identifier: GPL-3.0-or-later
# Sentinel-KDE .rpm %post — extract the shipped bundle and run the tested,
# distro-adaptive install.sh (polkit-only; --no-sudo). Runs on install and
# upgrade ($1 = 1 or 2); install.sh reverts any prior state itself.
set -e
D=/usr/lib/sentinel-kde
rm -rf "$D/src"
mkdir -p "$D/src"
tar -C "$D/src" -xzf "$D/bundle.tar.gz"
cd "$D"/src/sentinel-kde-*
SENTINEL_SKIP_BUILD=1 ./packaging-kde/install.sh --no-sudo </dev/null
exit 0
