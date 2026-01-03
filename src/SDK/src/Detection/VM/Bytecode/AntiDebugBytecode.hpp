/**
 * @file AntiDebugBytecode.hpp
 * @brief Bytecode generation for anti-debug detection
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2026
 * 
 * @copyright Copyright (c) 2026 Sentinel Security. All rights reserved.
 * 
 * PURPOSE:
 * ========
 * This file provides bytecode generation helpers that compile anti-debug
 * detection logic into VM bytecode. This virtualizes the detection logic,
 * making it resistant to static analysis and binary patching.
 * 
 * SECURITY RATIONALE:
 * ===================
 * Native x64 code for debugger detection compiles to easily-patchable instructions:
 *   call    qword ptr [__imp_IsDebuggerPresent]  ; Visible in import table
 *   test    eax, eax
 *   jnz     debugger_found                        ; Single byte patch defeats check
 * 
 * VM bytecode disperses the logic across multiple virtual instructions with
 * polymorphic encoding, making static patching impractical.
 */

#pragma once

#include "../Opcodes.hpp"
#include <vector>
#include <cstdint>

namespace Sentinel::VM::BytecodeGen {

/**
 * @brief Generate bytecode equivalent of CheckIsDebuggerPresent
 * 
 * This function generates VM bytecode that implements the same logic as
 * the native CheckIsDebuggerPresent function, but in virtualized form.
 * 
 * Detection Method: Direct PEB.BeingDebugged Check
 * =================================================
 * The bytecode reads the Process Environment Block (PEB) and checks the
 * BeingDebugged field at offset +0x02. This is more resilient than calling
 * the IsDebuggerPresent() API because:
 * 1. No IAT entry to identify and patch
 * 2. No single conditional jump to patch
 * 3. Logic is dispersed across multiple VM instructions
 * 
 * Bytecode Sequence:
 * ==================
 *   OP_READ_PEB           ; [] → [peb_addr]
 *   PUSH_IMM 0x02         ; [peb_addr] → [peb_addr, 0x02]
 *   ADD                   ; [peb_addr, 0x02] → [being_debugged_addr]
 *   READ_SAFE_1           ; [being_debugged_addr] → [being_debugged_value]
 *   PUSH_IMM 0x00         ; [being_debugged_value] → [being_debugged_value, 0]
 *   CMP_NE                ; [being_debugged_value, 0] → [is_debugging]
 *   JMP_Z +5              ; If not debugging, skip detection block
 *   PUSH_IMM 0x01         ; Flag bit 1 = debugger attached
 *   SET_FLAG              ; Set detection flag
 *   HALT_FAIL             ; Critical violation
 *   HALT                  ; Clean exit
 * 
 * @return Vector of bytecode instructions (without header, just raw instructions)
 */
inline std::vector<uint8_t> generateIsDebuggerPresentCheck() {
    std::vector<uint8_t> bytecode;
    
    // OP_READ_PEB - get PEB base address
    bytecode.push_back(static_cast<uint8_t>(Opcode::OP_READ_PEB));
    
    // PUSH_IMM 0x02 - offset to BeingDebugged field
    // (PEB.BeingDebugged is at offset +2 on both x86 and x64)
    bytecode.push_back(static_cast<uint8_t>(Opcode::PUSH_IMM));
    for (int i = 0; i < 8; ++i) {
        bytecode.push_back(i == 0 ? 0x02 : 0x00);  // Little-endian 2
    }
    
    // ADD - calculate PEB + 2
    bytecode.push_back(static_cast<uint8_t>(Opcode::ADD));
    
    // READ_SAFE_1 - read BeingDebugged byte
    bytecode.push_back(static_cast<uint8_t>(Opcode::READ_SAFE_1));
    
    // PUSH_IMM 0x00 - compare against 0
    bytecode.push_back(static_cast<uint8_t>(Opcode::PUSH_IMM));
    for (int i = 0; i < 8; ++i) bytecode.push_back(0x00);
    
    // CMP_NE - check if BeingDebugged != 0
    bytecode.push_back(static_cast<uint8_t>(Opcode::CMP_NE));
    
    // JMP_Z +11 - if result is 0 (not debugging), skip detection block
    // Jump offset is 11 bytes to skip: PUSH_IMM(1) + 8-byte operand(8) + SET_FLAG(1) + HALT_FAIL(1)
    bytecode.push_back(static_cast<uint8_t>(Opcode::JMP_Z));
    bytecode.push_back(0x0B);  // Skip 11 bytes (little-endian 16-bit)
    bytecode.push_back(0x00);
    
    // Detection block: Set flag and halt
    // PUSH_IMM 0x01 - flag bit for debugger
    bytecode.push_back(static_cast<uint8_t>(Opcode::PUSH_IMM));
    for (int i = 0; i < 8; ++i) bytecode.push_back(i == 0 ? 0x01 : 0x00);
    
    // SET_FLAG - mark detection
    bytecode.push_back(static_cast<uint8_t>(Opcode::SET_FLAG));
    
    // HALT_FAIL - violation detected
    bytecode.push_back(static_cast<uint8_t>(Opcode::HALT_FAIL));
    
    // Clean path: HALT
    bytecode.push_back(static_cast<uint8_t>(Opcode::HALT));
    
    return bytecode;
}

} // namespace Sentinel::VM::BytecodeGen
