/**
 * DisassemblyView.qml
 * Sentinel Cortex - Binary Disassembly View
 * 
 * Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Dialogs

import Sentinel.Cortex 1.0

Item {
    id: disassemblyView
    
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
    
    // Syntax highlighting colors
    readonly property color syntaxKeyword: "#FF7B72"
    readonly property color syntaxRegister: "#79C0FF"
    readonly property color syntaxNumber: "#A5D6FF"
    readonly property color syntaxString: "#A5D6FF"
    readonly property color syntaxComment: "#8B949E"
    readonly property color syntaxAddress: "#7EE787"
    readonly property color syntaxMnemonic: "#D2A8FF"
    
    property string currentFile: ""
    property bool isLoading: false
    
    RowLayout {
        anchors.fill: parent
        spacing: 0
        
        // Left panel - Function list
        Rectangle {
            Layout.preferredWidth: 280
            Layout.fillHeight: true
            color: bgSecondary
            
            ColumnLayout {
                anchors.fill: parent
                spacing: 0
                
                // Header
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 50
                    color: bgTertiary
                    
                    RowLayout {
                        anchors.fill: parent
                        anchors.margins: 12
                        
                        Text {
                            text: qsTr("Functions")
                            font.pixelSize: 14
                            font.bold: true
                            color: textPrimary
                        }
                        
                        Item { Layout.fillWidth: true }
                        
                        Text {
                            text: DisassemblerController.functionCount
                            font.pixelSize: 12
                            color: textSecondary
                        }
                    }
                }
                
                // Search
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 40
                    Layout.margins: 8
                    radius: 6
                    color: bgPrimary
                    border.color: searchField.focus ? accentPrimary : borderColor
                    
                    RowLayout {
                        anchors.fill: parent
                        anchors.margins: 8
                        spacing: 8
                        
                        Image {
                            source: "qrc:/icons/search.svg"
                            Layout.preferredWidth: 16
                            Layout.preferredHeight: 16
                            opacity: 0.5
                        }
                        
                        TextField {
                            id: searchField
                            Layout.fillWidth: true
                            placeholderText: qsTr("Search functions...")
                            color: textPrimary
                            placeholderTextColor: textSecondary
                            font.pixelSize: 12
                            background: null
                            
                            onTextChanged: DisassemblerController.filterFunctions(text)
                        }
                    }
                }
                
                // Function list
                ListView {
                    id: functionList
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    clip: true
                    
                    model: DisassemblerController.functionsModel
                    
                    delegate: Rectangle {
                        width: functionList.width
                        height: 56
                        color: ListView.isCurrentItem ? bgTertiary :
                               mouseArea.containsMouse ? Qt.darker(bgTertiary, 1.1) : "transparent"
                        
                        MouseArea {
                            id: mouseArea
                            anchors.fill: parent
                            hoverEnabled: true
                            
                            onClicked: {
                                functionList.currentIndex = index
                                DisassemblerController.disassembleFunction(model.address)
                            }
                        }
                        
                        ColumnLayout {
                            anchors.fill: parent
                            anchors.margins: 12
                            spacing: 4
                            
                            Text {
                                text: model.name
                                font.pixelSize: 12
                                font.family: "Consolas"
                                color: accentPrimary
                                elide: Text.ElideRight
                                Layout.fillWidth: true
                            }
                            
                            RowLayout {
                                Layout.fillWidth: true
                                spacing: 8
                                
                                Text {
                                    text: "0x" + model.address.toString(16).toUpperCase()
                                    font.pixelSize: 10
                                    font.family: "Consolas"
                                    color: syntaxAddress
                                }
                                
                                Text {
                                    text: model.size + " bytes"
                                    font.pixelSize: 10
                                    color: textSecondary
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
        
        // Main disassembly view
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
                    Layout.preferredHeight: 50
                    color: bgSecondary
                    
                    RowLayout {
                        anchors.fill: parent
                        anchors.margins: 8
                        spacing: 8
                        
                        // Open file button
                        Button {
                            text: qsTr("Open Binary")
                            
                            background: Rectangle {
                                implicitHeight: 34
                                radius: 6
                                color: parent.pressed ? Qt.darker(accentPrimary, 1.2) :
                                       parent.hovered ? Qt.darker(accentPrimary, 1.1) : accentPrimary
                            }
                            
                            contentItem: Text {
                                text: parent.text
                                color: textPrimary
                                font.pixelSize: 12
                                horizontalAlignment: Text.AlignHCenter
                            }
                            
                            onClicked: fileDialog.open()
                        }
                        
                        Rectangle {
                            width: 1
                            height: 24
                            color: borderColor
                        }
                        
                        // Navigation buttons
                        Button {
                            id: backBtn
                            enabled: DisassemblerController.canGoBack
                            
                            background: Rectangle {
                                implicitWidth: 34
                                implicitHeight: 34
                                radius: 6
                                color: parent.pressed ? bgTertiary :
                                       parent.hovered ? Qt.darker(bgTertiary, 1.1) : "transparent"
                            }
                            
                            contentItem: Text {
                                text: "◀"
                                color: backBtn.enabled ? textPrimary : textSecondary
                                font.pixelSize: 14
                                horizontalAlignment: Text.AlignHCenter
                            }
                            
                            onClicked: DisassemblerController.navigateBack()
                        }
                        
                        Button {
                            id: forwardBtn
                            enabled: DisassemblerController.canGoForward
                            
                            background: Rectangle {
                                implicitWidth: 34
                                implicitHeight: 34
                                radius: 6
                                color: parent.pressed ? bgTertiary :
                                       parent.hovered ? Qt.darker(bgTertiary, 1.1) : "transparent"
                            }
                            
                            contentItem: Text {
                                text: "▶"
                                color: forwardBtn.enabled ? textPrimary : textSecondary
                                font.pixelSize: 14
                                horizontalAlignment: Text.AlignHCenter
                            }
                            
                            onClicked: DisassemblerController.navigateForward()
                        }
                        
                        Rectangle {
                            width: 1
                            height: 24
                            color: borderColor
                        }
                        
                        // Address jump
                        TextField {
                            id: addressField
                            Layout.preferredWidth: 150
                            placeholderText: "0x00000000"
                            font.family: "Consolas"
                            font.pixelSize: 12
                            color: textPrimary
                            placeholderTextColor: textSecondary
                            
                            background: Rectangle {
                                radius: 6
                                color: bgPrimary
                                border.color: addressField.focus ? accentPrimary : borderColor
                            }
                            
                            onAccepted: {
                                DisassemblerController.jumpToAddress(text)
                            }
                        }
                        
                        Button {
                            text: qsTr("Go")
                            
                            background: Rectangle {
                                implicitWidth: 50
                                implicitHeight: 34
                                radius: 6
                                color: parent.pressed ? bgPrimary :
                                       parent.hovered ? bgTertiary : bgTertiary
                            }
                            
                            contentItem: Text {
                                text: parent.text
                                color: textPrimary
                                font.pixelSize: 12
                                horizontalAlignment: Text.AlignHCenter
                            }
                            
                            onClicked: DisassemblerController.jumpToAddress(addressField.text)
                        }
                        
                        Item { Layout.fillWidth: true }
                        
                        // View options
                        ComboBox {
                            id: viewMode
                            model: ["Assembly", "Hex Dump", "Strings"]
                            currentIndex: 0
                            
                            background: Rectangle {
                                implicitWidth: 120
                                implicitHeight: 34
                                radius: 6
                                color: bgTertiary
                                border.color: borderColor
                            }
                            
                            contentItem: Text {
                                text: viewMode.displayText
                                color: textPrimary
                                font.pixelSize: 12
                                leftPadding: 12
                                verticalAlignment: Text.AlignVCenter
                            }
                            
                            onCurrentIndexChanged: DisassemblerController.setViewMode(currentIndex)
                        }
                    }
                }
                
                // File info bar
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 32
                    color: bgTertiary
                    visible: currentFile !== ""
                    
                    RowLayout {
                        anchors.fill: parent
                        anchors.margins: 8
                        spacing: 16
                        
                        Text {
                            text: currentFile
                            font.pixelSize: 11
                            color: textSecondary
                            elide: Text.ElideMiddle
                            Layout.fillWidth: true
                        }
                        
                        Text {
                            text: DisassemblerController.fileType
                            font.pixelSize: 11
                            color: accentPrimary
                        }
                        
                        Text {
                            text: DisassemblerController.architecture
                            font.pixelSize: 11
                            color: syntaxKeyword
                        }
                    }
                }
                
                // Disassembly content
                Rectangle {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    color: bgPrimary
                    
                    // Empty state
                    Item {
                        anchors.fill: parent
                        visible: DisassemblerController.instructionCount === 0 && !isLoading
                        
                        ColumnLayout {
                            anchors.centerIn: parent
                            spacing: 16
                            
                            Text {
                                text: "⚙"
                                font.pixelSize: 64
                                color: textSecondary
                                Layout.alignment: Qt.AlignHCenter
                                opacity: 0.5
                            }
                            
                            Text {
                                text: qsTr("No binary loaded")
                                font.pixelSize: 18
                                color: textSecondary
                                Layout.alignment: Qt.AlignHCenter
                            }
                            
                            Text {
                                text: qsTr("Open a binary file or drag and drop to analyze")
                                font.pixelSize: 13
                                color: textSecondary
                                Layout.alignment: Qt.AlignHCenter
                                opacity: 0.7
                            }
                        }
                    }
                    
                    // Loading state
                    BusyIndicator {
                        anchors.centerIn: parent
                        running: isLoading
                        visible: isLoading
                    }
                    
                    // Disassembly list
                    ListView {
                        id: disassemblyList
                        anchors.fill: parent
                        anchors.margins: 8
                        visible: DisassemblerController.instructionCount > 0 && !isLoading
                        clip: true
                        
                        model: DisassemblerController.instructionsModel
                        
                        delegate: Rectangle {
                            width: disassemblyList.width
                            height: 24
                            color: model.isBreakpoint ? Qt.rgba(dangerColor.r, dangerColor.g, dangerColor.b, 0.15) :
                                   model.isCurrentIP ? Qt.rgba(warningColor.r, warningColor.g, warningColor.b, 0.15) :
                                   mouseArea.containsMouse ? bgTertiary : "transparent"
                            
                            MouseArea {
                                id: mouseArea
                                anchors.fill: parent
                                hoverEnabled: true
                                acceptedButtons: Qt.LeftButton | Qt.RightButton
                                
                                onClicked: (mouse) => {
                                    if (mouse.button === Qt.RightButton) {
                                        contextMenu.popup()
                                    } else {
                                        disassemblyList.currentIndex = index
                                    }
                                }
                                
                                onDoubleClicked: {
                                    if (model.isCall || model.isJump) {
                                        DisassemblerController.followReference(model.targetAddress)
                                    }
                                }
                            }
                            
                            RowLayout {
                                anchors.fill: parent
                                anchors.leftMargin: 8
                                spacing: 16
                                
                                // Breakpoint indicator
                                Rectangle {
                                    width: 8
                                    height: 8
                                    radius: 4
                                    color: model.isBreakpoint ? dangerColor : "transparent"
                                    border.color: mouseArea.containsMouse ? dangerColor : "transparent"
                                    border.width: 1
                                    
                                    MouseArea {
                                        anchors.fill: parent
                                        cursorShape: Qt.PointingHandCursor
                                        onClicked: DisassemblerController.toggleBreakpoint(model.address)
                                    }
                                }
                                
                                // Address
                                Text {
                                    text: model.addressStr
                                    font.family: "Consolas"
                                    font.pixelSize: 12
                                    color: syntaxAddress
                                    Layout.preferredWidth: 100
                                }
                                
                                // Bytes
                                Text {
                                    text: model.bytesStr
                                    font.family: "Consolas"
                                    font.pixelSize: 12
                                    color: textSecondary
                                    Layout.preferredWidth: 120
                                }
                                
                                // Mnemonic
                                Text {
                                    text: model.mnemonic
                                    font.family: "Consolas"
                                    font.pixelSize: 12
                                    font.bold: true
                                    color: model.isCall ? syntaxKeyword :
                                           model.isJump ? warningColor :
                                           model.isRet ? successColor : syntaxMnemonic
                                    Layout.preferredWidth: 80
                                }
                                
                                // Operands
                                Text {
                                    text: model.operands
                                    font.family: "Consolas"
                                    font.pixelSize: 12
                                    color: textPrimary
                                    Layout.fillWidth: true
                                    
                                    // Syntax highlighting for operands
                                    textFormat: Text.StyledText
                                }
                                
                                // Comment
                                Text {
                                    text: model.comment ? "; " + model.comment : ""
                                    font.family: "Consolas"
                                    font.pixelSize: 12
                                    color: syntaxComment
                                    visible: model.comment !== ""
                                }
                            }
                            
                            Menu {
                                id: contextMenu
                                
                                MenuItem { text: qsTr("Copy Address"); onTriggered: DisassemblerController.copyAddress(model.address) }
                                MenuItem { text: qsTr("Copy Bytes"); onTriggered: DisassemblerController.copyBytes(model.address) }
                                MenuItem { text: qsTr("Copy Instruction"); onTriggered: DisassemblerController.copyInstruction(index) }
                                MenuSeparator {}
                                MenuItem { text: qsTr("Toggle Breakpoint"); onTriggered: DisassemblerController.toggleBreakpoint(model.address) }
                                MenuItem { text: qsTr("Add Comment..."); onTriggered: commentDialog.open() }
                                MenuSeparator {}
                                MenuItem { text: qsTr("Follow Reference"); enabled: model.isCall || model.isJump; onTriggered: DisassemblerController.followReference(model.targetAddress) }
                                MenuItem { text: qsTr("Go to Xrefs..."); onTriggered: xrefsDialog.open() }
                            }
                        }
                        
                        ScrollBar.vertical: ScrollBar {
                            active: true
                            policy: ScrollBar.AsNeeded
                        }
                    }
                }
            }
            
            // Drag and drop overlay
            DropArea {
                anchors.fill: parent
                
                onEntered: (drag) => {
                    if (drag.hasUrls) {
                        dropOverlay.visible = true
                    }
                }
                
                onExited: dropOverlay.visible = false
                
                onDropped: (drop) => {
                    dropOverlay.visible = false
                    if (drop.hasUrls) {
                        var path = drop.urls[0].toString().replace("file:///", "")
                        DisassemblerController.loadBinary(path)
                        currentFile = path
                    }
                }
            }
            
            Rectangle {
                id: dropOverlay
                anchors.fill: parent
                color: Qt.rgba(accentPrimary.r, accentPrimary.g, accentPrimary.b, 0.1)
                visible: false
                
                Rectangle {
                    anchors.fill: parent
                    anchors.margins: 20
                    radius: 12
                    color: "transparent"
                    border.color: accentPrimary
                    border.width: 2
                    
                    Text {
                        anchors.centerIn: parent
                        text: qsTr("Drop binary file to analyze")
                        font.pixelSize: 18
                        color: accentPrimary
                    }
                }
            }
        }
        
        // Right panel - Details
        Rectangle {
            Layout.preferredWidth: 300
            Layout.fillHeight: true
            color: bgSecondary
            visible: DisassemblerController.instructionCount > 0
            
            ColumnLayout {
                anchors.fill: parent
                spacing: 0
                
                // Header
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 50
                    color: bgTertiary
                    
                    Text {
                        anchors.centerIn: parent
                        text: qsTr("Instruction Details")
                        font.pixelSize: 14
                        font.bold: true
                        color: textPrimary
                    }
                }
                
                // Details content
                ScrollView {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    
                    ColumnLayout {
                        width: parent.width
                        spacing: 16
                        
                        // Selected instruction info
                        Rectangle {
                            Layout.fillWidth: true
                            Layout.margins: 12
                            Layout.preferredHeight: detailsCol.height + 24
                            radius: 8
                            color: bgTertiary
                            
                            ColumnLayout {
                                id: detailsCol
                                anchors.fill: parent
                                anchors.margins: 12
                                spacing: 8
                                
                                DetailRow {
                                    label: "Address"
                                    value: DisassemblerController.selectedAddress
                                    valueColor: syntaxAddress
                                }
                                
                                DetailRow {
                                    label: "Mnemonic"
                                    value: DisassemblerController.selectedMnemonic
                                    valueColor: syntaxMnemonic
                                }
                                
                                DetailRow {
                                    label: "Size"
                                    value: DisassemblerController.selectedSize + " bytes"
                                }
                                
                                DetailRow {
                                    label: "Group"
                                    value: DisassemblerController.selectedGroup
                                }
                            }
                        }
                        
                        // Register effects
                        Rectangle {
                            Layout.fillWidth: true
                            Layout.margins: 12
                            Layout.preferredHeight: regCol.height + 24
                            radius: 8
                            color: bgTertiary
                            
                            ColumnLayout {
                                id: regCol
                                anchors.fill: parent
                                anchors.margins: 12
                                spacing: 8
                                
                                Text {
                                    text: qsTr("Register Effects")
                                    font.pixelSize: 12
                                    font.bold: true
                                    color: textPrimary
                                }
                                
                                Text {
                                    text: qsTr("Read: ") + DisassemblerController.registersRead
                                    font.pixelSize: 11
                                    font.family: "Consolas"
                                    color: syntaxRegister
                                    wrapMode: Text.Wrap
                                    Layout.fillWidth: true
                                }
                                
                                Text {
                                    text: qsTr("Write: ") + DisassemblerController.registersWritten
                                    font.pixelSize: 11
                                    font.family: "Consolas"
                                    color: warningColor
                                    wrapMode: Text.Wrap
                                    Layout.fillWidth: true
                                }
                            }
                        }
                        
                        // Cross-references
                        Rectangle {
                            Layout.fillWidth: true
                            Layout.margins: 12
                            Layout.preferredHeight: xrefCol.height + 24
                            radius: 8
                            color: bgTertiary
                            
                            ColumnLayout {
                                id: xrefCol
                                anchors.fill: parent
                                anchors.margins: 12
                                spacing: 8
                                
                                RowLayout {
                                    Layout.fillWidth: true
                                    
                                    Text {
                                        text: qsTr("Cross-References")
                                        font.pixelSize: 12
                                        font.bold: true
                                        color: textPrimary
                                    }
                                    
                                    Item { Layout.fillWidth: true }
                                    
                                    Text {
                                        text: DisassemblerController.xrefCount
                                        font.pixelSize: 11
                                        color: textSecondary
                                    }
                                }
                                
                                Repeater {
                                    model: DisassemblerController.xrefsModel
                                    
                                    delegate: Text {
                                        text: model.addressStr + " (" + model.type + ")"
                                        font.pixelSize: 11
                                        font.family: "Consolas"
                                        color: accentPrimary
                                        
                                        MouseArea {
                                            anchors.fill: parent
                                            cursorShape: Qt.PointingHandCursor
                                            onClicked: DisassemblerController.jumpToAddress(model.address)
                                        }
                                    }
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
        id: fileDialog
        title: qsTr("Open Binary File")
        nameFilters: ["Executable files (*.exe *.dll *.sys)", "All files (*)"]
        
        onAccepted: {
            var path = selectedFile.toString().replace("file:///", "")
            DisassemblerController.loadBinary(path)
            currentFile = path
        }
    }
    
    // Comment dialog
    Dialog {
        id: commentDialog
        title: qsTr("Add Comment")
        standardButtons: Dialog.Ok | Dialog.Cancel
        modal: true
        anchors.centerIn: parent
        
        TextField {
            id: commentField
            width: 300
            placeholderText: qsTr("Enter comment...")
        }
        
        onAccepted: {
            DisassemblerController.setComment(disassemblyList.currentIndex, commentField.text)
            commentField.clear()
        }
    }
    
    // Helper component
    component DetailRow: RowLayout {
        property string label: ""
        property string value: ""
        property color valueColor: textPrimary
        
        Layout.fillWidth: true
        
        Text {
            text: label + ":"
            font.pixelSize: 11
            color: textSecondary
            Layout.preferredWidth: 70
        }
        
        Text {
            text: value
            font.pixelSize: 11
            font.family: "Consolas"
            color: valueColor
            Layout.fillWidth: true
        }
    }
}
