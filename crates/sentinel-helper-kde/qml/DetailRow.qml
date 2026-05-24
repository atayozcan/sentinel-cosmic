// SPDX-FileCopyrightText: 2025 Atay Özcan <atay@oezcan.me>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// One labelled row in the expandable process-details section. The value is
// attacker-influenceable (/proc data), so it's forced to Text.PlainText.

import QtQuick
import QtQuick.Layouts
import QtQuick.Controls as QQC2
import org.kde.kirigami as Kirigami

ColumnLayout {
    property string label: ""
    property string value: ""

    Layout.fillWidth: true
    spacing: 0

    QQC2.Label {
        text: label
        textFormat: Text.PlainText
        opacity: 0.7
        font: Kirigami.Theme.smallFont
    }
    QQC2.Label {
        text: value
        textFormat: Text.PlainText
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        font.family: "monospace"
    }
}
