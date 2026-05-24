// SPDX-FileCopyrightText: 2025 Atay Özcan <atay@oezcan.me>
// SPDX-License-Identifier: GPL-3.0-or-later
//! Build script: generate + compile the C++ side of the `#[cxx_qt::bridge]`,
//! register the `DialogController` QObject, and **embed the QML into the
//! binary** (qrc) so it can't be tampered with on disk to bypass the prompt.
//!
//! No C++ shim and no `layer-shell-qt6-devel` are needed: the layer-shell
//! overlay is configured from QML via the installed `org.kde.layershell`
//! plugin, and the Wayland integration is selected at runtime by the
//! `QT_WAYLAND_SHELL_INTEGRATION=layer-shell` env var (see `main.rs`).

use cxx_qt_build::{CxxQtBuilder, QmlModule};

fn main() {
    CxxQtBuilder::new_qml_module(
        // The QML files are baked into the module's qrc (loaded as
        // `qrc:/qt/qml/org/sentinel/kde/qml/<file>`), so the installed
        // binary is self-contained and the dialog logic is read-only.
        QmlModule::new("org.sentinel.kde").qml_files([
            "qml/Main.qml",
            "qml/Windowed.qml",
            "qml/DialogCard.qml",
            "qml/DetailRow.qml",
        ]),
    )
    // Qt Core is always linked; Gui/Qml come via cxx-qt-lib, but we name
    // them explicitly for a deterministic link. Quick drives the scene
    // graph; Widgets backs QApplication + qqc2-desktop-style (Breeze).
    .qt_module("Gui")
    .qt_module("Qml")
    .qt_module("Quick")
    .qt_module("Widgets")
    .files(["src/bridge.rs"])
    .build();
}
