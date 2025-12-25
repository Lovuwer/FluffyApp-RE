/**
 * PatchEditorView.qml
 * Sentinel Cortex - Patch Editor View
 * 
 * Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import Sentinel.Cortex 1.0

Item {
    id: patchEditorView
    
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
        spacing: 16
        
        Text {
            text: qsTr("Patch Editor")
            font.pixelSize: 24
            font.bold: true
            color: textPrimary
        }
        
        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            radius: 12
            color: bgSecondary
            border.color: borderColor
            border.width: 1
            
            ColumnLayout {
                anchors.centerIn: parent
                spacing: 16
                
                Text {
                    text: "✏"
                    font.pixelSize: 64
                    color: textSecondary
                    Layout.alignment: Qt.AlignHCenter
                    opacity: 0.5
                }
                
                Text {
                    text: qsTr("Patch Editor")
                    font.pixelSize: 18
                    color: textSecondary
                    Layout.alignment: Qt.AlignHCenter
                }
                
                Text {
                    text: qsTr("Create and edit binary patches")
                    font.pixelSize: 13
                    color: textSecondary
                    Layout.alignment: Qt.AlignHCenter
                    opacity: 0.7
                }
            }
        }
    }
}
