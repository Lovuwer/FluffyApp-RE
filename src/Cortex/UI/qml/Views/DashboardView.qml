/**
 * DashboardView.qml
 * Sentinel Cortex - Security Dashboard
 * 
 * Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtCharts

import Sentinel.Cortex 1.0

Item {
    id: dashboardView
    
    // Theme colors (inherited from main)
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
    
    ColumnLayout {
        anchors.fill: parent
        spacing: 24
        
        // Header
        RowLayout {
            Layout.fillWidth: true
            spacing: 16
            
            Text {
                text: qsTr("Security Dashboard")
                font.pixelSize: 28
                font.bold: true
                color: textPrimary
            }
            
            Item { Layout.fillWidth: true }
            
            // Sync button
            Button {
                text: qsTr("Sync with Cloud")
                icon.source: "qrc:/icons/sync.svg"
                enabled: !DashboardController.isSyncing
                
                background: Rectangle {
                    implicitWidth: 150
                    implicitHeight: 36
                    radius: 6
                    color: parent.pressed ? accentSecondary : 
                           parent.hovered ? Qt.darker(accentPrimary, 1.1) : accentPrimary
                }
                
                contentItem: RowLayout {
                    spacing: 8
                    Image {
                        source: "qrc:/icons/sync.svg"
                        Layout.preferredWidth: 16
                        Layout.preferredHeight: 16
                    }
                    Text {
                        text: parent.parent.text
                        color: textPrimary
                        font.pixelSize: 13
                    }
                }
                
                onClicked: DashboardController.syncSignatures()
            }
        }
        
        // Stats cards row
        RowLayout {
            Layout.fillWidth: true
            spacing: 16
            
            // Attacks Blocked Card
            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 140
                radius: 12
                color: bgSecondary
                border.color: borderColor
                border.width: 1
                
                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 20
                    spacing: 8
                    
                    RowLayout {
                        Layout.fillWidth: true
                        
                        Text {
                            text: qsTr("Attacks Blocked")
                            font.pixelSize: 14
                            color: textSecondary
                        }
                        
                        Item { Layout.fillWidth: true }
                        
                        Rectangle {
                            width: 8
                            height: 8
                            radius: 4
                            color: dangerColor
                        }
                    }
                    
                    Text {
                        text: DashboardController.attacksBlocked.toLocaleString()
                        font.pixelSize: 36
                        font.bold: true
                        color: textPrimary
                    }
                    
                    Text {
                        text: qsTr("Last 24 hours")
                        font.pixelSize: 12
                        color: textSecondary
                    }
                }
            }
            
            // Active Patches Card
            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 140
                radius: 12
                color: bgSecondary
                border.color: borderColor
                border.width: 1
                
                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 20
                    spacing: 8
                    
                    RowLayout {
                        Layout.fillWidth: true
                        
                        Text {
                            text: qsTr("Active Patches")
                            font.pixelSize: 14
                            color: textSecondary
                        }
                        
                        Item { Layout.fillWidth: true }
                        
                        Rectangle {
                            width: 8
                            height: 8
                            radius: 4
                            color: accentPrimary
                        }
                    }
                    
                    Text {
                        text: DashboardController.activePatches
                        font.pixelSize: 36
                        font.bold: true
                        color: textPrimary
                    }
                    
                    Text {
                        text: qsTr("Deployed globally")
                        font.pixelSize: 12
                        color: textSecondary
                    }
                }
            }
            
            // Signatures Card
            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 140
                radius: 12
                color: bgSecondary
                border.color: borderColor
                border.width: 1
                
                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 20
                    spacing: 8
                    
                    RowLayout {
                        Layout.fillWidth: true
                        
                        Text {
                            text: qsTr("Threat Signatures")
                            font.pixelSize: 14
                            color: textSecondary
                        }
                        
                        Item { Layout.fillWidth: true }
                        
                        Rectangle {
                            width: 8
                            height: 8
                            radius: 4
                            color: successColor
                        }
                    }
                    
                    Text {
                        text: DashboardController.signatureCount.toLocaleString()
                        font.pixelSize: 36
                        font.bold: true
                        color: textPrimary
                    }
                    
                    Text {
                        text: qsTr("In database")
                        font.pixelSize: 12
                        color: textSecondary
                    }
                }
            }
            
            // Threat Level Card
            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 140
                radius: 12
                color: bgSecondary
                border.color: borderColor
                border.width: 1
                
                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 20
                    spacing: 8
                    
                    Text {
                        text: qsTr("Current Threat Level")
                        font.pixelSize: 14
                        color: textSecondary
                    }
                    
                    Text {
                        text: DashboardController.threatLevelText
                        font.pixelSize: 28
                        font.bold: true
                        color: DashboardController.threatLevelColor
                    }
                    
                    // Threat level bar
                    Rectangle {
                        Layout.fillWidth: true
                        height: 8
                        radius: 4
                        color: bgTertiary
                        
                        Rectangle {
                            width: parent.width * (DashboardController.threatLevel / 100)
                            height: parent.height
                            radius: 4
                            color: DashboardController.threatLevelColor
                            
                            Behavior on width {
                                NumberAnimation { duration: 500; easing.type: Easing.OutQuad }
                            }
                        }
                    }
                }
            }
        }
        
        // Charts row
        RowLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 16
            
            // Attack timeline chart
            Rectangle {
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.preferredWidth: 2
                radius: 12
                color: bgSecondary
                border.color: borderColor
                border.width: 1
                
                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 20
                    spacing: 16
                    
                    Text {
                        text: qsTr("Attack Timeline (24h)")
                        font.pixelSize: 16
                        font.bold: true
                        color: textPrimary
                    }
                    
                    // Chart placeholder
                    ChartView {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        antialiasing: true
                        backgroundColor: "transparent"
                        legend.visible: false
                        margins { left: 0; right: 0; top: 0; bottom: 0 }
                        
                        LineSeries {
                            name: "Attacks"
                            color: dangerColor
                            width: 2
                            
                            XYPoint { x: 0; y: 12 }
                            XYPoint { x: 1; y: 8 }
                            XYPoint { x: 2; y: 15 }
                            XYPoint { x: 3; y: 23 }
                            XYPoint { x: 4; y: 19 }
                            XYPoint { x: 5; y: 31 }
                            XYPoint { x: 6; y: 28 }
                            XYPoint { x: 7; y: 35 }
                            XYPoint { x: 8; y: 42 }
                            XYPoint { x: 9; y: 38 }
                            XYPoint { x: 10; y: 45 }
                            XYPoint { x: 11; y: 52 }
                        }
                        
                        ValueAxis {
                            id: axisX
                            min: 0
                            max: 11
                            tickCount: 12
                            labelsColor: textSecondary
                            gridLineColor: borderColor
                            lineVisible: false
                        }
                        
                        ValueAxis {
                            id: axisY
                            min: 0
                            max: 60
                            tickCount: 5
                            labelsColor: textSecondary
                            gridLineColor: borderColor
                            lineVisible: false
                        }
                    }
                }
            }
            
            // Recent threats list
            Rectangle {
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.preferredWidth: 1
                radius: 12
                color: bgSecondary
                border.color: borderColor
                border.width: 1
                
                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 20
                    spacing: 16
                    
                    RowLayout {
                        Layout.fillWidth: true
                        
                        Text {
                            text: qsTr("Recent Threats")
                            font.pixelSize: 16
                            font.bold: true
                            color: textPrimary
                        }
                        
                        Item { Layout.fillWidth: true }
                        
                        Text {
                            text: qsTr("View All")
                            font.pixelSize: 12
                            color: accentPrimary
                            
                            MouseArea {
                                anchors.fill: parent
                                cursorShape: Qt.PointingHandCursor
                                onClicked: { /* Open threats view */ }
                            }
                        }
                    }
                    
                    ListView {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        clip: true
                        spacing: 8
                        
                        model: ListModel {
                            ListElement {
                                name: "SpeedHack.dll"
                                type: "Memory Injection"
                                severity: "High"
                                time: "2 min ago"
                            }
                            ListElement {
                                name: "AimBot_v3.exe"
                                type: "Function Hook"
                                severity: "Critical"
                                time: "15 min ago"
                            }
                            ListElement {
                                name: "WallHack.sys"
                                type: "Kernel Driver"
                                severity: "Critical"
                                time: "1 hour ago"
                            }
                            ListElement {
                                name: "ESP_Cheat.dll"
                                type: "Signature Match"
                                severity: "Medium"
                                time: "3 hours ago"
                            }
                            ListElement {
                                name: "GodMode.exe"
                                type: "Memory Patch"
                                severity: "High"
                                time: "5 hours ago"
                            }
                        }
                        
                        delegate: Rectangle {
                            width: ListView.view.width
                            height: 60
                            radius: 8
                            color: mouseArea.containsMouse ? bgTertiary : "transparent"
                            
                            MouseArea {
                                id: mouseArea
                                anchors.fill: parent
                                hoverEnabled: true
                                cursorShape: Qt.PointingHandCursor
                            }
                            
                            RowLayout {
                                anchors.fill: parent
                                anchors.margins: 12
                                spacing: 12
                                
                                // Severity indicator
                                Rectangle {
                                    width: 4
                                    Layout.fillHeight: true
                                    radius: 2
                                    color: severity === "Critical" ? dangerColor :
                                           severity === "High" ? warningColor :
                                           severity === "Medium" ? accentPrimary : textSecondary
                                }
                                
                                ColumnLayout {
                                    Layout.fillWidth: true
                                    spacing: 4
                                    
                                    Text {
                                        text: name
                                        font.pixelSize: 13
                                        font.bold: true
                                        color: textPrimary
                                    }
                                    
                                    Text {
                                        text: type
                                        font.pixelSize: 11
                                        color: textSecondary
                                    }
                                }
                                
                                ColumnLayout {
                                    spacing: 4
                                    
                                    Rectangle {
                                        Layout.alignment: Qt.AlignRight
                                        implicitWidth: severityText.width + 12
                                        implicitHeight: 20
                                        radius: 4
                                        color: severity === "Critical" ? Qt.rgba(dangerColor.r, dangerColor.g, dangerColor.b, 0.2) :
                                               severity === "High" ? Qt.rgba(warningColor.r, warningColor.g, warningColor.b, 0.2) :
                                               Qt.rgba(accentPrimary.r, accentPrimary.g, accentPrimary.b, 0.2)
                                        
                                        Text {
                                            id: severityText
                                            anchors.centerIn: parent
                                            text: severity
                                            font.pixelSize: 10
                                            font.bold: true
                                            color: severity === "Critical" ? dangerColor :
                                                   severity === "High" ? warningColor : accentPrimary
                                        }
                                    }
                                    
                                    Text {
                                        Layout.alignment: Qt.AlignRight
                                        text: time
                                        font.pixelSize: 10
                                        color: textSecondary
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Quick actions row
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 80
            radius: 12
            color: bgSecondary
            border.color: borderColor
            border.width: 1
            
            RowLayout {
                anchors.fill: parent
                anchors.margins: 16
                spacing: 16
                
                Text {
                    text: qsTr("Quick Actions")
                    font.pixelSize: 14
                    font.bold: true
                    color: textSecondary
                }
                
                Item { Layout.preferredWidth: 20 }
                
                Repeater {
                    model: [
                        { text: "Analyze Binary", icon: "analyze" },
                        { text: "Compare Files", icon: "diff" },
                        { text: "Generate Patch", icon: "patch" },
                        { text: "VM Deobfuscate", icon: "vm" }
                    ]
                    
                    delegate: Button {
                        text: modelData.text
                        
                        background: Rectangle {
                            implicitWidth: 140
                            implicitHeight: 40
                            radius: 8
                            color: parent.pressed ? bgPrimary :
                                   parent.hovered ? bgTertiary : "transparent"
                            border.color: borderColor
                            border.width: 1
                        }
                        
                        contentItem: Text {
                            text: parent.text
                            font.pixelSize: 12
                            color: textPrimary
                            horizontalAlignment: Text.AlignHCenter
                            verticalAlignment: Text.AlignVCenter
                        }
                        
                        onClicked: {
                            switch (index) {
                                case 0: mainWindow.currentView = 1; break
                                case 1: mainWindow.currentView = 2; break
                                case 2: mainWindow.currentView = 2; break
                                case 3: mainWindow.currentView = 3; break
                            }
                        }
                    }
                }
                
                Item { Layout.fillWidth: true }
            }
        }
    }
}
