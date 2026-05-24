// SPDX-FileCopyrightText: 2025 Atay Özcan <atay@oezcan.me>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The dialog itself: a translucent backdrop plus a centered Breeze card.
// Used by both Main.qml (layer-shell overlay) and Windowed.qml (fallback
// window). All state and the verdict live in the Rust DialogController.
//
// Every text element that shows controller-supplied strings forces
// `Text.PlainText`: the requesting process's exe/cmdline/cwd are
// attacker-influenceable and Qt's default `Text.AutoText` would render
// HTML-looking input as rich text (markup, links, <img> loads, prompt
// spoofing).

import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import org.sentinel.kde 1.0

Item {
    id: rootItem

    DialogController {
        id: ctrl
    }

    // 100 ms clock. The min-time gate, countdown and auto-deny timeout all
    // live in Rust; QML just ticks the controller.
    Timer {
        interval: 100
        running: true
        repeat: true
        onTriggered: ctrl.tick()
    }

    // Escape always denies, regardless of which control holds focus.
    Shortcut {
        sequences: [StandardKey.Cancel]
        context: Qt.ApplicationShortcut
        onActivated: ctrl.deny()
    }

    // Translucent backdrop covering the whole surface (the full output in
    // layer-shell mode; the window in windowed mode).
    Rectangle {
        anchors.fill: parent
        color: Qt.rgba(0, 0, 0, 0.55)
    }

    QQC2.Control {
        id: card
        anchors.centerIn: parent
        width: Math.min(parent.width - Kirigami.Units.gridUnit * 2,
                        Kirigami.Units.gridUnit * 26)
        padding: Kirigami.Units.largeSpacing * 2

        background: Kirigami.ShadowedRectangle {
            color: Kirigami.Theme.backgroundColor
            radius: 12
            border.width: 1
            border.color: Kirigami.Theme.separatorColor
            shadow.size: 24
            shadow.yOffset: 8
            shadow.color: Qt.rgba(0, 0, 0, 0.45)
        }

        contentItem: ColumnLayout {
            spacing: Kirigami.Units.largeSpacing

            Kirigami.Heading {
                level: 2
                text: ctrl.title
                textFormat: Text.PlainText
                Layout.fillWidth: true
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.WordWrap
            }

            QQC2.Label {
                text: ctrl.message
                textFormat: Text.PlainText
                visible: text.length > 0
                Layout.fillWidth: true
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.WordWrap
            }

            // Requesting process: icon + executable path, with expandable
            // details. UAC-style visual anchor for what's asking.
            Kirigami.AbstractCard {
                Layout.fillWidth: true
                visible: ctrl.processExe.length > 0

                contentItem: ColumnLayout {
                    spacing: Kirigami.Units.smallSpacing

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Kirigami.Units.largeSpacing

                        Kirigami.Icon {
                            source: ctrl.iconName
                            fallback: "system-lock-screen"
                            Layout.preferredWidth: Kirigami.Units.iconSizes.large
                            Layout.preferredHeight: Kirigami.Units.iconSizes.large
                        }
                        QQC2.Label {
                            text: ctrl.processExe
                            textFormat: Text.PlainText
                            Layout.fillWidth: true
                            elide: Text.ElideMiddle
                            font.family: "monospace"
                        }
                    }

                    QQC2.Button {
                        visible: ctrl.hasDetails
                        flat: true
                        text: ctrl.showDetails ? qsTr("Hide details") : qsTr("Show details")
                        onClicked: ctrl.toggleDetails()
                    }

                    QQC2.ScrollView {
                        visible: ctrl.showDetails
                        Layout.fillWidth: true
                        Layout.preferredHeight: Kirigami.Units.gridUnit * 11
                        clip: true
                        contentWidth: availableWidth

                        ColumnLayout {
                            width: parent.width
                            spacing: Kirigami.Units.smallSpacing

                            DetailRow {
                                label: qsTr("Command")
                                value: ctrl.processCmdline
                                visible: ctrl.processCmdline.length > 0
                            }
                            DetailRow {
                                label: qsTr("PID")
                                value: ctrl.processPid > 0 ? ("" + ctrl.processPid) : ""
                                visible: ctrl.processPid > 0
                            }
                            DetailRow {
                                label: qsTr("Working directory")
                                value: ctrl.processCwd
                                visible: ctrl.processCwd.length > 0
                            }
                            DetailRow {
                                label: qsTr("Requested by")
                                value: ctrl.requestingUser
                                visible: ctrl.requestingUser.length > 0
                            }
                            DetailRow {
                                label: qsTr("Action")
                                value: ctrl.action
                                visible: ctrl.action.length > 0
                            }
                        }
                    }
                }
            }

            QQC2.Label {
                text: ctrl.secondary
                textFormat: Text.PlainText
                visible: text.length > 0
                Layout.fillWidth: true
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.WordWrap
                opacity: 0.8
            }

            // Auto-deny progress + countdown (only when a timeout is set).
            QQC2.ProgressBar {
                visible: ctrl.timeoutSecs > 0
                Layout.fillWidth: true
                from: 0
                to: 1
                value: ctrl.progressFraction
            }
            QQC2.Label {
                visible: ctrl.timeoutSecs > 0
                text: qsTr("Auto-deny in %1 s").arg(ctrl.remainingSecs)
                Layout.fillWidth: true
                horizontalAlignment: Text.AlignHCenter
                opacity: 0.7
            }

            // Allow / Deny. Declared Allow-first; when allowFirst is false
            // (randomized) RightToLeft flips them so Deny is on the left.
            RowLayout {
                Layout.fillWidth: true
                Layout.topMargin: Kirigami.Units.smallSpacing
                spacing: Kirigami.Units.largeSpacing
                layoutDirection: ctrl.allowFirst ? Qt.LeftToRight : Qt.RightToLeft

                QQC2.Button {
                    text: qsTr("Allow")
                    icon.name: "dialog-ok"
                    enabled: ctrl.allowEnabled
                    highlighted: true
                    Layout.fillWidth: true
                    onClicked: ctrl.allow()
                }
                QQC2.Button {
                    text: qsTr("Deny")
                    icon.name: "dialog-cancel"
                    Layout.fillWidth: true
                    onClicked: ctrl.deny()
                    // Destructive tint.
                    Kirigami.Theme.inherit: false
                    Kirigami.Theme.textColor: Kirigami.Theme.negativeTextColor
                }
            }
        }
    }
}
