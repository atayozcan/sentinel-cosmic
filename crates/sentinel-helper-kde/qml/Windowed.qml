// SPDX-FileCopyrightText: 2025 Atay Özcan <atay@oezcan.me>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Windowed fallback for compositors without zwlr-layer-shell-v1 (e.g.
// GNOME/Mutter). A normal xdg-toplevel; the backdrop just fills it.

import QtQuick
import QtQuick.Window
import org.sentinel.kde 1.0

Window {
    visible: true
    width: 460
    height: 420
    minimumWidth: 380
    minimumHeight: 320
    title: qsTr("Authentication Required")
    color: "transparent"

    DialogCard {
        anchors.fill: parent
    }
}
