/**
 * VMAnalysisView.qml
 * Sentinel Cortex - VM Deobfuscation Analysis View
 * 
 * Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Dialogs

import Sentinel.Cortex 1.0

Item {
    id: vmAnalysisView
    
    // Theme colors
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
    readonly property color purpleColor: "#A371F7"
    
    property bool isAnalyzing: false
    property int currentPhase: 0
    property real analysisProgress: 0
    
    RowLayout {
        anchors.fill: parent
        spacing: 0
        
        // Left panel - Handler list
        Rectangle {
            Layout.preferredWidth: 320
            Layout.fillHeight: true
            color: bgSecondary
            
            ColumnLayout {
                anchors.fill: parent
                spacing: 0
                
                // Header
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 60
                    color: bgTertiary
                    
                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: 12
                        spacing: 4
                        
                        Text {
                            text: qsTr("VM Handlers")
                            font.pixelSize: 16
                            font.bold: true
                            color: textPrimary
                        }
                        
                        Text {
                            text: VMController.handlerCount + qsTr(" handlers identified")
                            font.pixelSize: 12
                            color: textSecondary
                        }
                    }
                }
                
                // Filter tabs
                RowLayout {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 40
                    Layout.margins: 8
                    spacing: 4
                    
                    Repeater {
                        model: ["All", "Arithmetic", "Memory", "Control", "Stack"]
                        
                        delegate: Rectangle {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            radius: 6
                            color: VMController.handlerFilter === modelData ? accentSecondary : "transparent"
                            
                            Text {
                                anchors.centerIn: parent
                                text: modelData
                                font.pixelSize: 11
                                color: VMController.handlerFilter === modelData ? textPrimary : textSecondary
                            }
                            
                            MouseArea {
                                anchors.fill: parent
                                cursorShape: Qt.PointingHandCursor
                                onClicked: VMController.setHandlerFilter(modelData)
                            }
                        }
                    }
                }
                
                // Handler list
                ListView {
                    id: handlerList
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    clip: true
                    
                    model: VMController.handlersModel
                    
                    delegate: Rectangle {
                        width: handlerList.width
                        height: 72
                        color: ListView.isCurrentItem ? bgTertiary :
                               mouseArea.containsMouse ? Qt.darker(bgTertiary, 1.2) : "transparent"
                        
                        MouseArea {
                            id: mouseArea
                            anchors.fill: parent
                            hoverEnabled: true
                            
                            onClicked: {
                                handlerList.currentIndex = index
                                VMController.selectHandler(model.id)
                            }
                        }
                        
                        RowLayout {
                            anchors.fill: parent
                            anchors.margins: 12
                            spacing: 12
                            
                            // Handler type indicator
                            Rectangle {
                                Layout.preferredWidth: 44
                                Layout.preferredHeight: 44
                                radius: 8
                                color: getTypeColor(model.category)
                                opacity: 0.2
                                
                                Text {
                                    anchors.centerIn: parent
                                    text: getTypeIcon(model.category)
                                    font.pixelSize: 18
                                    color: getTypeColor(model.category)
                                }
                            }
                            
                            ColumnLayout {
                                Layout.fillWidth: true
                                spacing: 4
                                
                                Text {
                                    text: model.name
                                    font.pixelSize: 13
                                    font.bold: true
                                    color: textPrimary
                                }
                                
                                Text {
                                    text: model.description
                                    font.pixelSize: 11
                                    color: textSecondary
                                    elide: Text.ElideRight
                                    Layout.fillWidth: true
                                }
                                
                                RowLayout {
                                    spacing: 8
                                    
                                    Text {
                                        text: "0x" + model.address.toString(16).toUpperCase()
                                        font.pixelSize: 10
                                        font.family: "Consolas"
                                        color: successColor
                                    }
                                    
                                    Rectangle {
                                        width: confidenceBadge.width + 8
                                        height: 16
                                        radius: 4
                                        color: model.confidence > 80 ? Qt.rgba(successColor.r, successColor.g, successColor.b, 0.2) :
                                               model.confidence > 50 ? Qt.rgba(warningColor.r, warningColor.g, warningColor.b, 0.2) :
                                               Qt.rgba(dangerColor.r, dangerColor.g, dangerColor.b, 0.2)
                                        
                                        Text {
                                            id: confidenceBadge
                                            anchors.centerIn: parent
                                            text: model.confidence + "%"
                                            font.pixelSize: 9
                                            color: model.confidence > 80 ? successColor :
                                                   model.confidence > 50 ? warningColor : dangerColor
                                        }
                                    }
                                }
                            }
                        }
                        
                        Rectangle {
                            anchors.bottom: parent.bottom
                            width: parent.width
                            height: 1
                            color: borderColor
                        }
                    }
                    
                    ScrollBar.vertical: ScrollBar {
                        active: true
                        policy: ScrollBar.AsNeeded
                    }
                }
            }
        }
        
        // Separator
        Rectangle {
            Layout.preferredWidth: 1
            Layout.fillHeight: true
            color: borderColor
        }
        
        // Main content area
        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            color: bgPrimary
            
            ColumnLayout {
                anchors.fill: parent
                spacing: 0
                
                // Toolbar
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 60
                    color: bgSecondary
                    
                    RowLayout {
                        anchors.fill: parent
                        anchors.margins: 12
                        spacing: 12
                        
                        Button {
                            text: qsTr("Load Protected Binary")
                            
                            background: Rectangle {
                                implicitHeight: 36
                                radius: 6
                                color: parent.pressed ? Qt.darker(accentPrimary, 1.2) :
                                       parent.hovered ? Qt.darker(accentPrimary, 1.1) : accentPrimary
                            }
                            
                            contentItem: Text {
                                text: parent.text
                                color: textPrimary
                                font.pixelSize: 12
                            }
                            
                            onClicked: loadDialog.open()
                        }
                        
                        Rectangle {
                            width: 1
                            height: 24
                            color: borderColor
                        }
                        
                        Button {
                            text: isAnalyzing ? qsTr("Stop Analysis") : qsTr("Start Analysis")
                            enabled: VMController.binaryLoaded
                            
                            background: Rectangle {
                                implicitHeight: 36
                                radius: 6
                                color: isAnalyzing ? 
                                       (parent.pressed ? Qt.darker(dangerColor, 1.2) : dangerColor) :
                                       (parent.pressed ? Qt.darker(successColor, 1.2) : 
                                        parent.hovered ? Qt.darker(successColor, 1.1) : successColor)
                            }
                            
                            contentItem: Text {
                                text: parent.text
                                color: textPrimary
                                font.pixelSize: 12
                            }
                            
                            onClicked: {
                                if (isAnalyzing) {
                                    VMController.stopAnalysis()
                                } else {
                                    VMController.startAnalysis()
                                }
                                isAnalyzing = !isAnalyzing
                            }
                        }
                        
                        Item { Layout.fillWidth: true }
                        
                        // Analysis options
                        ComboBox {
                            id: analysisMode
                            model: ["Full Analysis", "Quick Scan", "Handler Only", "Trace Mode"]
                            
                            background: Rectangle {
                                implicitWidth: 140
                                implicitHeight: 36
                                radius: 6
                                color: bgTertiary
                                border.color: borderColor
                            }
                            
                            contentItem: Text {
                                text: analysisMode.displayText
                                color: textPrimary
                                font.pixelSize: 12
                                leftPadding: 12
                                verticalAlignment: Text.AlignVCenter
                            }
                        }
                        
                        CheckBox {
                            id: symbolicCheck
                            text: qsTr("Symbolic Execution")
                            checked: true
                            
                            contentItem: Text {
                                text: parent.text
                                color: textPrimary
                                font.pixelSize: 12
                                leftPadding: parent.indicator.width + 8
                            }
                        }
                    }
                }
                
                // Progress section (visible during analysis)
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: isAnalyzing ? 100 : 0
                    color: bgTertiary
                    visible: isAnalyzing
                    clip: true
                    
                    Behavior on Layout.preferredHeight {
                        NumberAnimation { duration: 200 }
                    }
                    
                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: 16
                        spacing: 12
                        
                        RowLayout {
                            Layout.fillWidth: true
                            
                            Text {
                                text: getPhaseText(currentPhase)
                                font.pixelSize: 14
                                font.bold: true
                                color: textPrimary
                            }
                            
                            Item { Layout.fillWidth: true }
                            
                            Text {
                                text: Math.round(analysisProgress * 100) + "%"
                                font.pixelSize: 14
                                color: accentPrimary
                            }
                        }
                        
                        // Progress bar
                        Rectangle {
                            Layout.fillWidth: true
                            height: 8
                            radius: 4
                            color: bgPrimary
                            
                            Rectangle {
                                width: parent.width * analysisProgress
                                height: parent.height
                                radius: 4
                                color: accentPrimary
                                
                                Behavior on width {
                                    NumberAnimation { duration: 300 }
                                }
                            }
                        }
                        
                        // Phase indicators
                        RowLayout {
                            Layout.fillWidth: true
                            spacing: 4
                            
                            Repeater {
                                model: ["Trace", "Pattern", "Symbolic", "Lift", "Optimize"]
                                
                                delegate: RowLayout {
                                    spacing: 4
                                    
                                    Rectangle {
                                        width: 8
                                        height: 8
                                        radius: 4
                                        color: currentPhase > index ? successColor :
                                               currentPhase === index ? accentPrimary : textSecondary
                                    }
                                    
                                    Text {
                                        text: modelData
                                        font.pixelSize: 10
                                        color: currentPhase >= index ? textPrimary : textSecondary
                                    }
                                    
                                    Item { Layout.preferredWidth: 8 }
                                }
                            }
                        }
                    }
                }
                
                // Tab view for results
                TabBar {
                    id: resultsTabBar
                    Layout.fillWidth: true
                    background: Rectangle { color: bgSecondary }
                    
                    TabButton {
                        text: qsTr("Lifted Code")
                        width: implicitWidth
                        
                        background: Rectangle {
                            color: resultsTabBar.currentIndex === 0 ? bgPrimary : "transparent"
                        }
                        
                        contentItem: Text {
                            text: parent.text
                            color: resultsTabBar.currentIndex === 0 ? textPrimary : textSecondary
                            font.pixelSize: 12
                            horizontalAlignment: Text.AlignHCenter
                        }
                    }
                    
                    TabButton {
                        text: qsTr("Handler Details")
                        width: implicitWidth
                        
                        background: Rectangle {
                            color: resultsTabBar.currentIndex === 1 ? bgPrimary : "transparent"
                        }
                        
                        contentItem: Text {
                            text: parent.text
                            color: resultsTabBar.currentIndex === 1 ? textPrimary : textSecondary
                            font.pixelSize: 12
                            horizontalAlignment: Text.AlignHCenter
                        }
                    }
                    
                    TabButton {
                        text: qsTr("Execution Trace")
                        width: implicitWidth
                        
                        background: Rectangle {
                            color: resultsTabBar.currentIndex === 2 ? bgPrimary : "transparent"
                        }
                        
                        contentItem: Text {
                            text: parent.text
                            color: resultsTabBar.currentIndex === 2 ? textPrimary : textSecondary
                            font.pixelSize: 12
                            horizontalAlignment: Text.AlignHCenter
                        }
                    }
                    
                    TabButton {
                        text: qsTr("Control Flow")
                        width: implicitWidth
                        
                        background: Rectangle {
                            color: resultsTabBar.currentIndex === 3 ? bgPrimary : "transparent"
                        }
                        
                        contentItem: Text {
                            text: parent.text
                            color: resultsTabBar.currentIndex === 3 ? textPrimary : textSecondary
                            font.pixelSize: 12
                            horizontalAlignment: Text.AlignHCenter
                        }
                    }
                }
                
                // Tab content
                StackLayout {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    currentIndex: resultsTabBar.currentIndex
                    
                    // Lifted code view
                    Rectangle {
                        color: bgPrimary
                        
                        ScrollView {
                            anchors.fill: parent
                            anchors.margins: 16
                            
                            TextArea {
                                id: liftedCodeArea
                                readOnly: true
                                font.family: "Consolas"
                                font.pixelSize: 12
                                color: textPrimary
                                wrapMode: TextArea.NoWrap
                                text: VMController.liftedCode
                                
                                background: Rectangle {
                                    color: bgSecondary
                                    radius: 8
                                }
                            }
                        }
                        
                        // Empty state
                        ColumnLayout {
                            anchors.centerIn: parent
                            spacing: 16
                            visible: VMController.liftedCode === ""
                            
                            Text {
                                text: "🔐"
                                font.pixelSize: 64
                                Layout.alignment: Qt.AlignHCenter
                            }
                            
                            Text {
                                text: qsTr("No lifted code available")
                                font.pixelSize: 18
                                color: textSecondary
                                Layout.alignment: Qt.AlignHCenter
                            }
                            
                            Text {
                                text: qsTr("Load a protected binary and run analysis to see deobfuscated code")
                                font.pixelSize: 13
                                color: textSecondary
                                opacity: 0.7
                                Layout.alignment: Qt.AlignHCenter
                            }
                        }
                    }
                    
                    // Handler details view
                    Rectangle {
                        color: bgPrimary
                        
                        RowLayout {
                            anchors.fill: parent
                            anchors.margins: 16
                            spacing: 16
                            
                            // Handler code
                            Rectangle {
                                Layout.fillWidth: true
                                Layout.fillHeight: true
                                radius: 8
                                color: bgSecondary
                                
                                ColumnLayout {
                                    anchors.fill: parent
                                    anchors.margins: 12
                                    spacing: 8
                                    
                                    Text {
                                        text: qsTr("Handler Implementation")
                                        font.pixelSize: 14
                                        font.bold: true
                                        color: textPrimary
                                    }
                                    
                                    ScrollView {
                                        Layout.fillWidth: true
                                        Layout.fillHeight: true
                                        
                                        TextArea {
                                            readOnly: true
                                            font.family: "Consolas"
                                            font.pixelSize: 11
                                            color: textPrimary
                                            text: VMController.selectedHandlerCode
                                            background: null
                                        }
                                    }
                                }
                            }
                            
                            // Handler properties
                            Rectangle {
                                Layout.preferredWidth: 280
                                Layout.fillHeight: true
                                radius: 8
                                color: bgSecondary
                                
                                ColumnLayout {
                                    anchors.fill: parent
                                    anchors.margins: 12
                                    spacing: 12
                                    
                                    Text {
                                        text: qsTr("Handler Properties")
                                        font.pixelSize: 14
                                        font.bold: true
                                        color: textPrimary
                                    }
                                    
                                    GridLayout {
                                        columns: 2
                                        columnSpacing: 12
                                        rowSpacing: 8
                                        Layout.fillWidth: true
                                        
                                        Text { text: "Opcode:"; color: textSecondary; font.pixelSize: 11 }
                                        Text { text: VMController.selectedHandlerOpcode; color: purpleColor; font.family: "Consolas"; font.pixelSize: 11 }
                                        
                                        Text { text: "Category:"; color: textSecondary; font.pixelSize: 11 }
                                        Text { text: VMController.selectedHandlerCategory; color: accentPrimary; font.pixelSize: 11 }
                                        
                                        Text { text: "Size:"; color: textSecondary; font.pixelSize: 11 }
                                        Text { text: VMController.selectedHandlerSize + " bytes"; color: textPrimary; font.pixelSize: 11 }
                                        
                                        Text { text: "Calls:"; color: textSecondary; font.pixelSize: 11 }
                                        Text { text: VMController.selectedHandlerCalls; color: textPrimary; font.pixelSize: 11 }
                                        
                                        Text { text: "Frequency:"; color: textSecondary; font.pixelSize: 11 }
                                        Text { text: VMController.selectedHandlerFrequency; color: warningColor; font.pixelSize: 11 }
                                    }
                                    
                                    Rectangle {
                                        Layout.fillWidth: true
                                        height: 1
                                        color: borderColor
                                    }
                                    
                                    Text {
                                        text: qsTr("Semantic Analysis")
                                        font.pixelSize: 12
                                        font.bold: true
                                        color: textPrimary
                                    }
                                    
                                    Text {
                                        text: VMController.selectedHandlerSemantics
                                        font.pixelSize: 11
                                        color: textSecondary
                                        wrapMode: Text.Wrap
                                        Layout.fillWidth: true
                                    }
                                    
                                    Item { Layout.fillHeight: true }
                                }
                            }
                        }
                    }
                    
                    // Execution trace view
                    Rectangle {
                        color: bgPrimary
                        
                        ListView {
                            id: traceList
                            anchors.fill: parent
                            anchors.margins: 16
                            clip: true
                            
                            model: VMController.traceModel
                            
                            header: Rectangle {
                                width: traceList.width
                                height: 40
                                color: bgTertiary
                                radius: 8
                                
                                RowLayout {
                                    anchors.fill: parent
                                    anchors.margins: 12
                                    
                                    Text { text: "#"; color: textSecondary; font.pixelSize: 11; font.bold: true; Layout.preferredWidth: 50 }
                                    Text { text: "Address"; color: textSecondary; font.pixelSize: 11; font.bold: true; Layout.preferredWidth: 120 }
                                    Text { text: "Handler"; color: textSecondary; font.pixelSize: 11; font.bold: true; Layout.preferredWidth: 100 }
                                    Text { text: "Stack"; color: textSecondary; font.pixelSize: 11; font.bold: true; Layout.fillWidth: true }
                                    Text { text: "Context"; color: textSecondary; font.pixelSize: 11; font.bold: true; Layout.preferredWidth: 200 }
                                }
                            }
                            
                            delegate: Rectangle {
                                width: traceList.width
                                height: 32
                                color: index % 2 === 0 ? "transparent" : Qt.rgba(bgTertiary.r, bgTertiary.g, bgTertiary.b, 0.3)
                                
                                RowLayout {
                                    anchors.fill: parent
                                    anchors.margins: 12
                                    
                                    Text {
                                        text: model.index
                                        font.pixelSize: 11
                                        font.family: "Consolas"
                                        color: textSecondary
                                        Layout.preferredWidth: 50
                                    }
                                    
                                    Text {
                                        text: model.address
                                        font.pixelSize: 11
                                        font.family: "Consolas"
                                        color: successColor
                                        Layout.preferredWidth: 120
                                    }
                                    
                                    Text {
                                        text: model.handler
                                        font.pixelSize: 11
                                        font.family: "Consolas"
                                        color: purpleColor
                                        Layout.preferredWidth: 100
                                    }
                                    
                                    Text {
                                        text: model.stack
                                        font.pixelSize: 11
                                        font.family: "Consolas"
                                        color: textPrimary
                                        elide: Text.ElideRight
                                        Layout.fillWidth: true
                                    }
                                    
                                    Text {
                                        text: model.context
                                        font.pixelSize: 11
                                        font.family: "Consolas"
                                        color: textSecondary
                                        elide: Text.ElideRight
                                        Layout.preferredWidth: 200
                                    }
                                }
                            }
                            
                            ScrollBar.vertical: ScrollBar {
                                active: true
                                policy: ScrollBar.AsNeeded
                            }
                        }
                    }
                    
                    // Control flow graph view
                    Rectangle {
                        color: bgPrimary
                        
                        // CFG Canvas - placeholder for actual graph rendering
                        Canvas {
                            id: cfgCanvas
                            anchors.fill: parent
                            anchors.margins: 16
                            
                            onPaint: {
                                var ctx = getContext("2d")
                                ctx.clearRect(0, 0, width, height)
                                
                                // Draw placeholder CFG
                                ctx.strokeStyle = borderColor
                                ctx.fillStyle = bgSecondary
                                ctx.lineWidth = 2
                                
                                // Entry block
                                drawBlock(ctx, width/2 - 60, 50, 120, 60, "Entry", successColor)
                                
                                // Middle blocks
                                drawBlock(ctx, width/2 - 180, 180, 120, 60, "Handler_1", purpleColor)
                                drawBlock(ctx, width/2 + 60, 180, 120, 60, "Handler_2", purpleColor)
                                
                                // Exit
                                drawBlock(ctx, width/2 - 60, 310, 120, 60, "Exit", dangerColor)
                                
                                // Edges
                                ctx.strokeStyle = accentPrimary
                                drawEdge(ctx, width/2, 110, width/2 - 120, 180)
                                drawEdge(ctx, width/2, 110, width/2 + 120, 180)
                                drawEdge(ctx, width/2 - 120, 240, width/2, 310)
                                drawEdge(ctx, width/2 + 120, 240, width/2, 310)
                            }
                            
                            function drawBlock(ctx, x, y, w, h, label, borderCol) {
                                ctx.fillStyle = bgSecondary
                                ctx.strokeStyle = borderCol
                                ctx.beginPath()
                                ctx.roundRect(x, y, w, h, 8)
                                ctx.fill()
                                ctx.stroke()
                                
                                ctx.fillStyle = textPrimary
                                ctx.font = "12px Consolas"
                                ctx.textAlign = "center"
                                ctx.fillText(label, x + w/2, y + h/2 + 4)
                            }
                            
                            function drawEdge(ctx, x1, y1, x2, y2) {
                                ctx.beginPath()
                                ctx.moveTo(x1, y1)
                                ctx.lineTo(x2, y2)
                                ctx.stroke()
                                
                                // Arrow head
                                var angle = Math.atan2(y2 - y1, x2 - x1)
                                ctx.beginPath()
                                ctx.moveTo(x2, y2)
                                ctx.lineTo(x2 - 10 * Math.cos(angle - 0.4), y2 - 10 * Math.sin(angle - 0.4))
                                ctx.lineTo(x2 - 10 * Math.cos(angle + 0.4), y2 - 10 * Math.sin(angle + 0.4))
                                ctx.closePath()
                                ctx.fillStyle = accentPrimary
                                ctx.fill()
                            }
                        }
                        
                        // Zoom controls
                        RowLayout {
                            anchors.bottom: parent.bottom
                            anchors.right: parent.right
                            anchors.margins: 16
                            spacing: 8
                            
                            Button {
                                text: "−"
                                background: Rectangle {
                                    implicitWidth: 32
                                    implicitHeight: 32
                                    radius: 6
                                    color: parent.hovered ? bgTertiary : bgSecondary
                                }
                                contentItem: Text {
                                    text: parent.text
                                    color: textPrimary
                                    font.pixelSize: 16
                                    horizontalAlignment: Text.AlignHCenter
                                }
                            }
                            
                            Text {
                                text: "100%"
                                color: textSecondary
                                font.pixelSize: 12
                            }
                            
                            Button {
                                text: "+"
                                background: Rectangle {
                                    implicitWidth: 32
                                    implicitHeight: 32
                                    radius: 6
                                    color: parent.hovered ? bgTertiary : bgSecondary
                                }
                                contentItem: Text {
                                    text: parent.text
                                    color: textPrimary
                                    font.pixelSize: 16
                                    horizontalAlignment: Text.AlignHCenter
                                }
                            }
                            
                            Button {
                                text: "Fit"
                                background: Rectangle {
                                    implicitWidth: 48
                                    implicitHeight: 32
                                    radius: 6
                                    color: parent.hovered ? bgTertiary : bgSecondary
                                }
                                contentItem: Text {
                                    text: parent.text
                                    color: textPrimary
                                    font.pixelSize: 12
                                    horizontalAlignment: Text.AlignHCenter
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    // File dialog
    FileDialog {
        id: loadDialog
        title: qsTr("Open Protected Binary")
        nameFilters: ["Executable files (*.exe *.dll)", "All files (*)"]
        
        onAccepted: {
            var path = selectedFile.toString().replace("file:///", "")
            VMController.loadBinary(path)
        }
    }
    
    // Analysis progress connection
    Connections {
        target: VMController
        
        function onAnalysisProgressChanged(phase, progress) {
            currentPhase = phase
            analysisProgress = progress
        }
        
        function onAnalysisCompleted() {
            isAnalyzing = false
        }
    }
    
    // Helper functions
    function getTypeColor(category) {
        switch (category) {
            case "arithmetic": return warningColor
            case "memory": return accentPrimary
            case "control": return dangerColor
            case "stack": return successColor
            default: return textSecondary
        }
    }
    
    function getTypeIcon(category) {
        switch (category) {
            case "arithmetic": return "∑"
            case "memory": return "📦"
            case "control": return "⤴"
            case "stack": return "📚"
            default: return "?"
        }
    }
    
    function getPhaseText(phase) {
        switch (phase) {
            case 0: return qsTr("Phase 1: Execution Tracing...")
            case 1: return qsTr("Phase 2: Pattern Recognition...")
            case 2: return qsTr("Phase 3: Symbolic Execution...")
            case 3: return qsTr("Phase 4: IR Lifting...")
            case 4: return qsTr("Phase 5: Optimization...")
            default: return qsTr("Analyzing...")
        }
    }
}
