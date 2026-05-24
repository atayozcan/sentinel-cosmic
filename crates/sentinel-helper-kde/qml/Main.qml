// SPDX-FileCopyrightText: 2025 Atay Özcan <atay@oezcan.me>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Layer-shell entry point: a fullscreen `zwlr-layer-shell-v1` overlay on
// the Overlay layer with exclusive keyboard focus. The Wayland layer-shell
// integration is activated by main.rs (QT_WAYLAND_SHELL_INTEGRATION).

import QtQuick
import QtQuick.Window
import org.kde.layershell 1.0 as LayerShell
import org.sentinel.kde 1.0

Window {
    id: win
    visible: true
    color: "transparent"
    // Lay the QML scene out fullscreen so the dim backdrop fills the whole
    // output. The layer surface is already stretched to the output by the
    // four-edge anchors below; this keeps the Qt content in lockstep.
    width: Screen.width
    height: Screen.height

    LayerShell.Window.anchors: LayerShell.Window.AnchorTop
        | LayerShell.Window.AnchorBottom
        | LayerShell.Window.AnchorLeft
        | LayerShell.Window.AnchorRight
    LayerShell.Window.layer: LayerShell.Window.LayerOverlay
    LayerShell.Window.keyboardInteractivity: LayerShell.Window.KeyboardInteractivityExclusive
    LayerShell.Window.exclusionZone: -1
    LayerShell.Window.scope: "sentinel"

    DialogCard {
        anchors.fill: parent
    }
}
