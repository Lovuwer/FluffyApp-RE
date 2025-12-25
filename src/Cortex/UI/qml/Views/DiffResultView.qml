/**
 * DiffResultView.qml
 * Sentinel Cortex - Binary Diff Results View
 * 
 * Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Dialogs

import Sentinel.Cortex 1.0

Item {
    id: diffResultView
    
    // Theme colors
    readonly property color bgPrimary: "#0D1117"
    readonly property color bgSecondary: "#161B22"
    readonly property color bgTertiary: "#21262D"
    readonly property color accentPrimary: "#58A6FF"
    readonly property color textPrimary: "#F0F6FC"
    readonly property color textSecondary: "#8B949E"
    readonly property color borderColor: "#30363D"
    readonly property color dangerColor: "#F85149"
    readonly property color successColor: "#3FB950"
    readonly property color warningColor: "#D29922"
    readonly property color addedColor: "#3FB950"
    readonly property color removedColor: "#F85149"
    readonly property color modifiedColor: "#D29922"
    
    ColumnLayout {
        anchors.fill: parent
        spacing: 16
        
        // Header with action buttons
        RowLayout {
            Layout.fillWidth: true
            spacing: 12
            
            Text {
                text: qsTr("Binary Diff Results")
                font.pixelSize: 24
                font.bold: true
                color: textPrimary
            }
            
            Item { Layout.fillWidth: true }
            
            Button {
                text: qsTr("Load Files...")
                
                background: Rectangle {
                    implicitHeight: 36
                    radius: 6
                    color: parent.pressed ? Qt.darker(accentPrimary, 1.2) :
                           parent.hovered ? Qt.darker(accentPrimary, 1.1) : accentPrimary
                }
                
                contentItem: Text {
                    text: parent.text
                    color: textPrimary
                    font.pixelSize: 13
                    horizontalAlignment: Text.AlignHCenter
                }
                
                onClicked: fileDialog.open()
            }
            
            Button {
                text: qsTr("Generate Patch")
                enabled: DiffController.hasDiff
                
                background: Rectangle {
                    implicitHeight: 36
                    radius: 6
                    color: parent.enabled ? 
                           (parent.pressed ? Qt.darker(successColor, 1.2) : 
                            parent.hovered ? Qt.darker(successColor, 1.1) : successColor) :
                           bgTertiary
                }
                
                contentItem: Text {
                    text: parent.text
                    color: parent.parent.enabled ? textPrimary : textSecondary
                    font.pixelSize: 13
                    horizontalAlignment: Text.AlignHCenter
                }
                
                onClicked: DiffController.generatePatch()
            }
        }
        
        // Statistics cards
        RowLayout {
            Layout.fillWidth: true
            spacing: 16
            visible: DiffController.hasDiff
            
            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 100
                radius: 12
                color: bgSecondary
                border.color: borderColor
                border.width: 1
                
                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 16
                    spacing: 8
                    
                    Text {
                        text: qsTr("Similarity Score")
                        font.pixelSize: 13
                        color: textSecondary
                    }
                    
                    Text {
                        text: DiffController.similarityScore.toFixed(1) + "%"
                        font.pixelSize: 28
                        font.bold: true
                        color: DiffController.similarityScore > 80 ? successColor :
                               DiffController.similarityScore > 50 ? warningColor : dangerColor
                    }
                }
            }
            
            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 100
                radius: 12
                color: bgSecondary
                border.color: borderColor
                border.width: 1
                
                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 16
                    spacing: 8
                    
                    Text {
                        text: qsTr("Matched Functions")
                        font.pixelSize: 13
                        color: textSecondary
                    }
                    
                    Text {
                        text: DiffController.matchedFunctions
                        font.pixelSize: 28
                        font.bold: true
                        color: successColor
                    }
                }
            }
            
            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 100
                radius: 12
                color: bgSecondary
                border.color: borderColor
                border.width: 1
                
                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 16
                    spacing: 8
                    
                    Text {
                        text: qsTr("Modified Functions")
                        font.pixelSize: 13
                        color: textSecondary
                    }
                    
                    Text {
                        text: DiffController.modifiedFunctions
                        font.pixelSize: 28
                        font.bold: true
                        color: warningColor
                    }
                }
            }
        }
        
        // Main diff content
        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            radius: 12
            color: bgSecondary
            border.color: borderColor
            border.width: 1
            
            ColumnLayout {
                anchors.fill: parent
                spacing: 0
                
                // Empty state
                Item {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    visible: !DiffController.hasDiff
                    
                    ColumnLayout {
                        anchors.centerIn: parent
                        spacing: 16
                        
                        Text {
                            text: "⚖"
                            font.pixelSize: 64
                            color: textSecondary
                            Layout.alignment: Qt.AlignHCenter
                            opacity: 0.5
                        }
                        
                        Text {
                            text: qsTr("No diff results")
                            font.pixelSize: 18
                            color: textSecondary
                            Layout.alignment: Qt.AlignHCenter
                        }
                        
                        Text {
                            text: qsTr("Load two binary files to compare")
                            font.pixelSize: 13
                            color: textSecondary
                            Layout.alignment: Qt.AlignHCenter
                            opacity: 0.7
                        }
                    }
                }
                
                // Diff results (placeholder for actual implementation)
                ScrollView {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    visible: DiffController.hasDiff
                    
                    ColumnLayout {
                        width: parent.width
                        spacing: 8
                        
                        Text {
                            text: qsTr("Detailed diff view will be implemented here")
                            color: textSecondary
                            font.pixelSize: 14
                            Layout.alignment: Qt.AlignCenter
                            Layout.topMargin: 20
                        }
                    }
                }
            }
        }
    }
    
    // File dialog for loading binaries
    FileDialog {
        id: fileDialog
        title: qsTr("Select Binaries to Compare")
        fileMode: FileDialog.OpenFile
        nameFilters: ["Executable files (*.exe *.dll *.so)", "All files (*)"]
        
        onAccepted: {
            // TODO: Handle multiple file selection for diff
            // For now, this is a placeholder
        }
    }
}
