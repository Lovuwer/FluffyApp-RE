/**
 * Main.qml
 * Sentinel Cortex - Main Application Window
 * 
 * Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window
import Qt.labs.platform as Platform

import Sentinel.Cortex 1.0

ApplicationWindow {
    id: mainWindow
    
    title: qsTr("Sentinel Cortex - Security Analyzer")
    width: 1400
    height: 900
    minimumWidth: 1200
    minimumHeight: 700
    visible: true
    
    // Dark theme colors
    readonly property color bgPrimary: "#0D1117"
    readonly property color bgSecondary: "#161B22"
    readonly property color bgTertiary: "#21262D"
    readonly property color accentPrimary: "#58A6FF"
    readonly property color accentSecondary: "#1F6FEB"
    readonly property color textPrimary: "#F0F6FC"
    readonly property color textSecondary: "#8B949E"
    readonly property color borderColor: "#30363D"
    readonly property color dangerColor: "#F85149"
    readonly property color successColor: "#3FB950"
    readonly property color warningColor: "#D29922"
    
    color: bgPrimary
    
    // Current view state
    property int currentView: 0  // 0=Dashboard, 1=Analyzer, 2=Diff, 3=VMTrace, 4=Settings
    
    // Menu bar
    menuBar: MenuBar {
        id: appMenuBar
        
        Menu {
            title: qsTr("&File")
            
            Action {
                text: qsTr("&Open Binary...")
                shortcut: StandardKey.Open
                onTriggered: fileDialog.open()
            }
            
            Action {
                text: qsTr("Open &Project...")
                shortcut: "Ctrl+Shift+O"
            }
            
            MenuSeparator {}
            
            Action {
                text: qsTr("&Save Patch...")
                shortcut: StandardKey.Save
                enabled: AnalyzerController.hasAnalysis
            }
            
            Action {
                text: qsTr("Export &Report...")
                shortcut: "Ctrl+E"
                enabled: AnalyzerController.hasAnalysis
            }
            
            MenuSeparator {}
            
            Action {
                text: qsTr("&Quit")
                shortcut: StandardKey.Quit
                onTriggered: Qt.quit()
            }
        }
        
        Menu {
            title: qsTr("&Analysis")
            
            Action {
                text: qsTr("&Disassemble")
                shortcut: "F5"
                enabled: AnalyzerController.hasFile
                onTriggered: AnalyzerController.disassemble()
            }
            
            Action {
                text: qsTr("&Diff with Clean...")
                shortcut: "F6"
                enabled: AnalyzerController.hasAnalysis
            }
            
            Action {
                text: qsTr("&Generate Patch")
                shortcut: "F7"
                enabled: DiffController.hasDiff
            }
            
            MenuSeparator {}
            
            Action {
                text: qsTr("&VM Deobfuscate")
                shortcut: "F8"
                enabled: AnalyzerController.hasFile
                onTriggered: VMTraceController.startAnalysis()
            }
            
            Action {
                text: qsTr("Compute &Fuzzy Hash")
                enabled: AnalyzerController.hasFile
                onTriggered: AnalyzerController.computeFuzzyHash()
            }
        }
        
        Menu {
            title: qsTr("&View")
            
            Action {
                text: qsTr("&Dashboard")
                shortcut: "Ctrl+1"
                checkable: true
                checked: currentView === 0
                onTriggered: currentView = 0
            }
            
            Action {
                text: qsTr("&Analyzer")
                shortcut: "Ctrl+2"
                checkable: true
                checked: currentView === 1
                onTriggered: currentView = 1
            }
            
            Action {
                text: qsTr("D&iff View")
                shortcut: "Ctrl+3"
                checkable: true
                checked: currentView === 2
                onTriggered: currentView = 2
            }
            
            Action {
                text: qsTr("&VM Trace")
                shortcut: "Ctrl+4"
                checkable: true
                checked: currentView === 3
                onTriggered: currentView = 3
            }
            
            MenuSeparator {}
            
            Action {
                text: qsTr("&Expert Mode")
                checkable: true
                checked: SettingsController.expertMode
                onTriggered: SettingsController.expertMode = !SettingsController.expertMode
            }
        }
        
        Menu {
            title: qsTr("&Cloud")
            
            Action {
                text: qsTr("&Upload Analysis...")
                enabled: AnalyzerController.hasAnalysis
            }
            
            Action {
                text: qsTr("&Sync Signatures")
                onTriggered: DashboardController.syncSignatures()
            }
            
            Action {
                text: qsTr("&Check for Patches")
            }
        }
        
        Menu {
            title: qsTr("&Help")
            
            Action {
                text: qsTr("&Documentation")
                shortcut: StandardKey.HelpContents
            }
            
            Action {
                text: qsTr("&About Sentinel Cortex")
                onTriggered: aboutDialog.open()
            }
        }
    }
    
    // Main layout
    RowLayout {
        anchors.fill: parent
        spacing: 0
        
        // Left sidebar navigation
        Rectangle {
            Layout.fillHeight: true
            Layout.preferredWidth: 60
            color: bgSecondary
            
            ColumnLayout {
                anchors.fill: parent
                anchors.margins: 8
                spacing: 4
                
                // Logo
                Image {
                    Layout.alignment: Qt.AlignHCenter
                    Layout.preferredWidth: 40
                    Layout.preferredHeight: 40
                    source: "qrc:/icons/sentinel-logo.svg"
                    fillMode: Image.PreserveAspectFit
                }
                
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 1
                    color: borderColor
                    Layout.topMargin: 8
                    Layout.bottomMargin: 8
                }
                
                // Navigation buttons
                Repeater {
                    model: [
                        { icon: "qrc:/icons/dashboard.svg", view: 0, tooltip: "Dashboard" },
                        { icon: "qrc:/icons/analyze.svg", view: 1, tooltip: "Analyzer" },
                        { icon: "qrc:/icons/diff.svg", view: 2, tooltip: "Diff View" },
                        { icon: "qrc:/icons/patch.svg", view: 3, tooltip: "VM Trace" }
                    ]
                    
                    delegate: Rectangle {
                        Layout.fillWidth: true
                        Layout.preferredHeight: 44
                        radius: 8
                        color: currentView === modelData.view ? bgTertiary : "transparent"
                        
                        Image {
                            anchors.centerIn: parent
                            width: 24
                            height: 24
                            source: modelData.icon
                            opacity: currentView === modelData.view ? 1.0 : 0.6
                        }
                        
                        MouseArea {
                            anchors.fill: parent
                            cursorShape: Qt.PointingHandCursor
                            onClicked: currentView = modelData.view
                            hoverEnabled: true
                            
                            ToolTip.visible: containsMouse
                            ToolTip.text: modelData.tooltip
                            ToolTip.delay: 500
                        }
                    }
                }
                
                Item { Layout.fillHeight: true }
                
                // Settings button
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 44
                    radius: 8
                    color: currentView === 4 ? bgTertiary : "transparent"
                    
                    Image {
                        anchors.centerIn: parent
                        width: 24
                        height: 24
                        source: "qrc:/icons/settings.svg"
                        opacity: currentView === 4 ? 1.0 : 0.6
                    }
                    
                    MouseArea {
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        onClicked: currentView = 4
                        
                        ToolTip.visible: containsMouse
                        ToolTip.text: qsTr("Settings")
                        ToolTip.delay: 500
                    }
                }
            }
        }
        
        // Main content area
        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            color: bgPrimary
            
            StackLayout {
                anchors.fill: parent
                anchors.margins: 16
                currentIndex: currentView
                
                // Dashboard View
                DashboardView {
                    id: dashboardView
                }
                
                // Analyzer View
                AnalyzerView {
                    id: analyzerView
                }
                
                // Diff View
                DiffResultView {
                    id: diffView
                }
                
                // VM Trace View
                VMTraceView {
                    id: vmTraceView
                }
                
                // Settings View
                SettingsView {
                    id: settingsView
                }
            }
        }
    }
    
    // Status bar
    footer: Rectangle {
        height: 28
        color: bgSecondary
        
        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: 12
            anchors.rightMargin: 12
            spacing: 16
            
            // Status indicator
            Rectangle {
                width: 8
                height: 8
                radius: 4
                color: DashboardController.isConnected ? successColor : dangerColor
            }
            
            Text {
                text: DashboardController.isConnected ? 
                    qsTr("Connected to Sentinel Cloud") : 
                    qsTr("Offline Mode")
                color: textSecondary
                font.pixelSize: 12
            }
            
            Item { Layout.fillWidth: true }
            
            // Threat level indicator
            Text {
                text: qsTr("Threat Level: ") + DashboardController.threatLevelText
                color: DashboardController.threatLevelColor
                font.pixelSize: 12
                font.bold: true
            }
            
            Rectangle {
                width: 1
                height: 16
                color: borderColor
            }
            
            Text {
                text: qsTr("v") + APP_VERSION
                color: textSecondary
                font.pixelSize: 11
            }
        }
    }
    
    // File dialog
    Platform.FileDialog {
        id: fileDialog
        title: qsTr("Open Binary File")
        nameFilters: [
            "Executable files (*.exe *.dll *.so *.dylib)",
            "All files (*)"
        ]
        onAccepted: {
            AnalyzerController.loadFile(file)
            currentView = 1  // Switch to analyzer view
        }
    }
    
    // About dialog
    Dialog {
        id: aboutDialog
        title: qsTr("About Sentinel Cortex")
        anchors.centerIn: parent
        modal: true
        width: 400
        
        background: Rectangle {
            color: bgSecondary
            radius: 8
            border.color: borderColor
            border.width: 1
        }
        
        contentItem: ColumnLayout {
            spacing: 16
            
            Image {
                Layout.alignment: Qt.AlignHCenter
                source: "qrc:/icons/sentinel-logo.svg"
                Layout.preferredWidth: 80
                Layout.preferredHeight: 80
            }
            
            Text {
                Layout.alignment: Qt.AlignHCenter
                text: "Sentinel Cortex"
                font.pixelSize: 24
                font.bold: true
                color: textPrimary
            }
            
            Text {
                Layout.alignment: Qt.AlignHCenter
                text: qsTr("Version ") + APP_VERSION
                font.pixelSize: 14
                color: textSecondary
            }
            
            Text {
                Layout.alignment: Qt.AlignHCenter
                text: qsTr("Military-Grade Game Security Analyzer")
                font.pixelSize: 12
                color: textSecondary
            }
            
            Rectangle {
                Layout.fillWidth: true
                height: 1
                color: borderColor
            }
            
            Text {
                Layout.alignment: Qt.AlignHCenter
                text: "© 2024 Sentinel Security"
                font.pixelSize: 11
                color: textSecondary
            }
            
            Text {
                Layout.alignment: Qt.AlignHCenter
                text: qsTr("Built on ") + BUILD_DATE
                font.pixelSize: 11
                color: textSecondary
            }
        }
        
        standardButtons: Dialog.Ok
    }
    
    // Drop area for drag-and-drop analysis
    DropArea {
        anchors.fill: parent
        keys: ["text/uri-list"]
        
        onDropped: function(drop) {
            if (drop.hasUrls) {
                var url = drop.urls[0]
                AnalyzerController.loadFile(url)
                currentView = 1
            }
        }
        
        onEntered: function(drag) {
            drag.accepted = drag.hasUrls
            dropOverlay.visible = drag.hasUrls
        }
        
        onExited: {
            dropOverlay.visible = false
        }
    }
    
    // Drop overlay
    Rectangle {
        id: dropOverlay
        anchors.fill: parent
        color: Qt.rgba(0, 0, 0, 0.8)
        visible: false
        z: 1000
        
        ColumnLayout {
            anchors.centerIn: parent
            spacing: 16
            
            Image {
                Layout.alignment: Qt.AlignHCenter
                source: "qrc:/icons/analyze.svg"
                Layout.preferredWidth: 64
                Layout.preferredHeight: 64
                opacity: 0.8
            }
            
            Text {
                Layout.alignment: Qt.AlignHCenter
                text: qsTr("Drop binary file to analyze")
                font.pixelSize: 18
                color: textPrimary
            }
            
            Text {
                Layout.alignment: Qt.AlignHCenter
                text: qsTr("Supported: EXE, DLL, SO, DYLIB")
                font.pixelSize: 12
                color: textSecondary
            }
        }
    }
    
    // Keyboard shortcuts
    Shortcut {
        sequence: "Escape"
        onActivated: {
            if (dropOverlay.visible) {
                dropOverlay.visible = false
            }
        }
    }
}
