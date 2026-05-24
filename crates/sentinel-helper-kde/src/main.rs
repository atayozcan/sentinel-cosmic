// SPDX-FileCopyrightText: 2025 Atay Özcan <atay@oezcan.me>
// SPDX-License-Identifier: GPL-3.0-or-later
//! KDE Plasma-native confirmation helper for Sentinel.
//!
//! A drop-in alternative to the COSMIC `sentinel-helper`: same CLI flags
//! (parsed via `sentinel_shared::cli`), same `ALLOW`/`DENY`/`TIMEOUT`
//! stdout contract. Renders a Breeze/Kirigami dialog as a
//! `zwlr-layer-shell-v1` overlay (fullscreen, exclusive keyboard) on
//! Plasma/wlroots compositors, falling back to a normal window on
//! Mutter-based desktops.

mod bridge;

use cxx_qt_lib::{QQmlApplicationEngine, QQuickStyle, QString, QUrl};
use cxx_qt_lib_extras::QApplication;
use sentinel_shared::cli::{self, RenderMode};
use std::sync::OnceLock;

/// Parsed CLI args, cached process-wide. Read here for the render-mode
/// decision and by the QObject's `Default` impl when QML instantiates the
/// controller. `get_or_init` makes the ordering robust either way.
static ARGS: OnceLock<cli::Args> = OnceLock::new();

pub fn args() -> &'static cli::Args {
    ARGS.get_or_init(cli::parse)
}

fn main() {
    let a = args();
    let mode = a.effective_render_mode(std::env::var("XDG_CURRENT_DESKTOP").ok().as_deref());

    // Fail safe: this helper is Wayland-only. With no display we can't paint
    // the confirmation, so deny rather than proceed blindly or hang.
    if std::env::var_os("WAYLAND_DISPLAY").is_none() {
        eprintln!("sentinel-helper-kde: WAYLAND_DISPLAY not set; Wayland-only — denying");
        bridge::finish_deny();
    }

    // Fire the UAC-style audio cue before the GUI spins up.
    play_sound(&a.sound_name);

    if mode == RenderMode::LayerShell {
        // `LayerShellQt::Shell::useLayerShell()` is exactly this qputenv,
        // and the `liblayer-shell.so` Wayland integration ships with Plasma
        // — so no `layer-shell-qt6-devel` and no C++ shim are needed. Must
        // be set before QApplication initializes the Wayland platform.
        //
        // SAFETY: process start, single-threaded, before any Qt setup.
        unsafe { std::env::set_var("QT_WAYLAND_SHELL_INTEGRATION", "layer-shell") };
    }

    let mut app = QApplication::new();

    // Native Breeze styling for QtQuick.Controls. qqc2-desktop-style needs
    // the QApplication created above; the explicit style keeps the look
    // correct even when the helper is spawned under a minimal env.
    QQuickStyle::set_style(&QString::from("org.kde.desktop"));

    let mut engine = QQmlApplicationEngine::new();

    // Fail safe: if the QML scene fails to instantiate, deny instead of
    // running a windowless event loop until PAM SIGKILLs us. Connected
    // before load() so it fires during the synchronous instantiation.
    if let Some(engine) = engine.as_mut() {
        engine
            .on_object_creation_failed(|_engine, _url| {
                eprintln!("sentinel-helper-kde: QML failed to load — denying");
                bridge::finish_deny();
            })
            .release();
    }

    let entry = match mode {
        RenderMode::LayerShell => "Main.qml",
        RenderMode::Windowed => "Windowed.qml",
    };
    // QML is embedded in the binary (qrc) — tamper-proof and self-contained.
    let url = format!("qrc:/qt/qml/org/sentinel/kde/qml/{entry}");
    if let Some(engine) = engine.as_mut() {
        engine.load(&QUrl::from(url.as_str()));
    }

    if let Some(app) = app.as_mut() {
        app.exec();
    }

    // Reached only if the event loop quit without a verdict (e.g. the
    // surface was torn down). Fail safe: deny.
    bridge::finish_deny();
}

/// UAC-style audio cue. Optional and best-effort: libcanberra resolves the
/// freedesktop sound *name* through the user's theme. Silent if
/// `canberra-gtk-play` isn't installed — never blocks the dialog.
fn play_sound(name: &str) {
    if name.is_empty() {
        return;
    }
    if let Ok(mut child) = std::process::Command::new("canberra-gtk-play")
        .args(["-i", name])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        // Reap asynchronously so the player doesn't linger as a zombie.
        std::thread::spawn(move || {
            let _ = child.wait();
        });
    }
}
