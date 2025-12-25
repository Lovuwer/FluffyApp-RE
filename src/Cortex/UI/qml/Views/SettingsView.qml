/**
 * SettingsView.qml
 * Sentinel Cortex - Settings View
 * 
 * Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import Sentinel.Cortex 1.0

Item {
    id: settingsView
    
    // Theme colors
    readonly property color bgPrimary: "#0D1117"
    readonly property color bgSecondary: "#161B22"
    readonly property color bgTertiary: "#21262D"
    readonly property color accentPrimary: "#58A6FF"
    readonly property color textPrimary: "#F0F6FC"
    readonly property color textSecondary: "#8B949E"
    readonly property color borderColor: "#30363D"
    readonly property color successColor: "#3FB950"
    
    ColumnLayout {
        anchors.fill: parent
        spacing: 24
        
        // Header
        RowLayout {
            Layout.fillWidth: true
            spacing: 12
            
            Text {
                text: qsTr("Settings")
                font.pixelSize: 28
                font.bold: true
                color: textPrimary
            }
            
            Item { Layout.fillWidth: true }
            
            Button {
                text: qsTr("Save Settings")
                
                background: Rectangle {
                    implicitHeight: 36
                    radius: 6
                    color: parent.pressed ? Qt.darker(successColor, 1.2) :
                           parent.hovered ? Qt.darker(successColor, 1.1) : successColor
                }
                
                contentItem: Text {
                    text: parent.text
                    color: textPrimary
                    font.pixelSize: 13
                    horizontalAlignment: Text.AlignHCenter
                }
                
                onClicked: SettingsController.saveSettings()
            }
            
            Button {
                text: qsTr("Reset to Defaults")
                
                background: Rectangle {
                    implicitHeight: 36
                    radius: 6
                    color: parent.pressed ? bgPrimary :
                           parent.hovered ? bgTertiary : bgSecondary
                    border.color: borderColor
                    border.width: 1
                }
                
                contentItem: Text {
                    text: parent.text
                    color: textPrimary
                    font.pixelSize: 13
                    horizontalAlignment: Text.AlignHCenter
                }
                
                onClicked: SettingsController.resetToDefaults()
            }
        }
        
        ScrollView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            
            ColumnLayout {
                width: parent.width
                spacing: 16
                
                // Appearance Section
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: appearanceCol.height + 32
                    radius: 12
                    color: bgSecondary
                    border.color: borderColor
                    border.width: 1
                    
                    ColumnLayout {
                        id: appearanceCol
                        anchors.fill: parent
                        anchors.margins: 16
                        spacing: 16
                        
                        Text {
                            text: qsTr("Appearance")
                            font.pixelSize: 18
                            font.bold: true
                            color: textPrimary
                        }
                        
                        RowLayout {
                            Layout.fillWidth: true
                            
                            Text {
                                text: qsTr("Dark Theme")
                                font.pixelSize: 14
                                color: textPrimary
                                Layout.fillWidth: true
                            }
                            
                            Switch {
                                checked: SettingsController.darkTheme
                                onToggled: SettingsController.setDarkTheme(checked)
                            }
                        }
                        
                        RowLayout {
                            Layout.fillWidth: true
                            
                            Text {
                                text: qsTr("Font Size")
                                font.pixelSize: 14
                                color: textPrimary
                                Layout.preferredWidth: 120
                            }
                            
                            SpinBox {
                                from: 8
                                to: 24
                                value: SettingsController.fontSize
                                onValueChanged: SettingsController.setFontSize(value)
                                
                                background: Rectangle {
                                    radius: 6
                                    color: bgTertiary
                                    border.color: borderColor
                                }
                                
                                contentItem: TextInput {
                                    text: parent.textFromValue(parent.value, parent.locale)
                                    font.pixelSize: 12
                                    color: textPrimary
                                    horizontalAlignment: Qt.AlignHCenter
                                    verticalAlignment: Qt.AlignVCenter
                                }
                            }
                        }
                    }
                }
                
                // Analysis Section
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: analysisCol.height + 32
                    radius: 12
                    color: bgSecondary
                    border.color: borderColor
                    border.width: 1
                    
                    ColumnLayout {
                        id: analysisCol
                        anchors.fill: parent
                        anchors.margins: 16
                        spacing: 16
                        
                        Text {
                            text: qsTr("Analysis")
                            font.pixelSize: 18
                            font.bold: true
                            color: textPrimary
                        }
                        
                        RowLayout {
                            Layout.fillWidth: true
                            
                            Text {
                                text: qsTr("Expert Mode")
                                font.pixelSize: 14
                                color: textPrimary
                                Layout.fillWidth: true
                            }
                            
                            Switch {
                                checked: SettingsController.expertMode
                                onToggled: SettingsController.setExpertMode(checked)
                            }
                        }
                        
                        Text {
                            text: qsTr("Expert mode enables advanced features and detailed analysis options")
                            font.pixelSize: 12
                            color: textSecondary
                            wrapMode: Text.Wrap
                            Layout.fillWidth: true
                        }
                    }
                }
                
                // About Section
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: aboutCol.height + 32
                    radius: 12
                    color: bgSecondary
                    border.color: borderColor
                    border.width: 1
                    
                    ColumnLayout {
                        id: aboutCol
                        anchors.fill: parent
                        anchors.margins: 16
                        spacing: 16
                        
                        Text {
                            text: qsTr("About")
                            font.pixelSize: 18
                            font.bold: true
                            color: textPrimary
                        }
                        
                        GridLayout {
                            columns: 2
                            rowSpacing: 8
                            columnSpacing: 16
                            Layout.fillWidth: true
                            
                            Text {
                                text: qsTr("Version:")
                                font.pixelSize: 13
                                color: textSecondary
                            }
                            
                            Text {
                                text: "1.0.0"
                                font.pixelSize: 13
                                color: textPrimary
                            }
                            
                            Text {
                                text: qsTr("Build:")
                                font.pixelSize: 13
                                color: textSecondary
                            }
                            
                            Text {
                                text: "2024-12-24"
                                font.pixelSize: 13
                                color: textPrimary
                            }
                            
                            Text {
                                text: qsTr("License:")
                                font.pixelSize: 13
                                color: textSecondary
                            }
                            
                            Text {
                                text: qsTr("Commercial")
                                font.pixelSize: 13
                                color: textPrimary
                            }
                        }
                    }
                }
                
                Item { Layout.fillHeight: true }
            }
        }
    }
}
