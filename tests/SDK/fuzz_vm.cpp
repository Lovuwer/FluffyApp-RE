/**
 * VM FUZZ TEST
 * 
 * This harness tests VMInterpreter against malformed bytecode using LibFuzzer.
 * 
 * INVARIANTS TESTED:
 * - VM must never crash (SIGSEGV, SIGABRT, or any other fatal signal)
 * - VM must return within configured timeout (100ms for fuzzing)
 * - VM must return valid VMResult enum value (Clean=0, Violation=1, Error=2, Timeout=3, Halted=4)
 * - VM must not corrupt process state (verified by AddressSanitizer)
 * - VM must handle all malformed bytecode gracefully
 * 
 * KNOWN LIMITATIONS:
 * - Does not test external callbacks (no OP_CALL_EXT registration in fuzzer)
 * - Does not test polymorphic opcode maps (uses identity map only)
 * - Does not test concurrent execution (single-threaded fuzzer)
 * - Limited instruction count (1000 max) to prevent fuzzer timeouts
 * 
 * FUZZING STRATEGY:
 * - Input: Raw bytes from LibFuzzer (randomized or mutated)
 * - Minimum size: sizeof(BytecodeHeader) = 24 bytes
 * - Maximum size: 65536 bytes (configurable via -max_len flag)
 * - Seed corpus: Valid bytecode samples in corpus/ directory
 * - Fuzzer will mutate valid bytecodes and generate random inputs
 * 
 * BYTECODE FORMAT REFERENCE (from VMInterpreter.hpp):
 * - Header: 24 bytes
 *   - magic (4 bytes): 0x53454E54 ("SENT")
 *   - version (2 bytes): Bytecode format version
 *   - flags (2 bytes): Reserved
 *   - xxh3_hash (8 bytes): Hash of instructions
 *   - instruction_count (4 bytes): Number of instruction bytes
 *   - constant_count (4 bytes): Number of 8-byte constants
 * - Constant Pool: constant_count * 8 bytes
 * - Instructions: instruction_count bytes
 * 
 * EXPECTED BEHAVIOR:
 * - Valid bytecode: Should execute and return Clean/Violation/Halted
 * - Invalid header: load() returns false, fuzzer returns 0 (no crash)
 * - Invalid hash: VM may detect or treat as Error (no crash)
 * - Malformed instructions: VM returns Error or Timeout (no crash)
 * - Out-of-bounds access: VM handles safely via bounds checking (no crash)
 * 
 * HOW TO BUILD:
 * - Configure with: cmake -DSENTINEL_ENABLE_FUZZING=ON ..
 * - Build with: cmake --build . --target fuzz_vm
 * - This will create the fuzz_vm executable in bin/ directory
 * 
 * HOW TO RUN:
 * - Create corpus directory: mkdir -p corpus
 * - Run fuzzer: ./bin/fuzz_vm corpus/ -max_len=65536 -timeout=10
 * - Run for 1 hour: ./bin/fuzz_vm corpus/ -max_len=65536 -timeout=10 -max_total_time=3600
 * - With more jobs: ./bin/fuzz_vm corpus/ -jobs=4 -workers=4
 * 
 * INTERPRETING RESULTS:
 * - No crashes after 1 hour: PASS (meets acceptance criteria)
 * - Crashes found: Investigate crash files in fuzzer output
 * - Timeout issues: May need to reduce max_instructions limit
 * - OOM issues: May need to add memory limit checks
 * 
 * CRASH TRIAGE:
 * - Fuzzer will save crashing inputs to crash-* files
 * - Reproduce with: ./bin/fuzz_vm crash-<hash>
 * - Add to regression tests in test_vm.cpp
 * - Fix the bug and re-run fuzzer to verify fix
 * 
 * INTEGRATION WITH CI:
 * - Fuzzing is not run in CI (too time-consuming)
 * - Run manually before releases
 * - Can integrate with OSS-Fuzz for continuous fuzzing
 * 
 * @author Sentinel Security Team
 * @date 2026-01-03
 * @copyright Copyright (c) 2026 Sentinel Security. All rights reserved.
 */

// Include VM headers - these contain the code we're fuzzing
// VMInterpreter.hpp contains: VMInterpreter class, VMConfig struct, VMResult enum, Bytecode class
#include "../src/SDK/src/Detection/VM/VMInterpreter.hpp"

// Standard includes needed for fuzzing
#include <cstdint>    // For uint8_t, size_t
#include <cstddef>    // For size_t
#include <vector>     // For std::vector (Bytecode::load takes std::vector<uint8_t>)
#include <cassert>    // For assert() to verify invariants

// Namespace alias for convenience
using namespace Sentinel::VM;

/**
 * @brief LibFuzzer entry point - called for each fuzzing iteration
 * 
 * This function is called by LibFuzzer with randomized or mutated input.
 * LibFuzzer will:
 * 1. Generate or mutate input bytes
 * 2. Call this function with data pointer and size
 * 3. Monitor for crashes, hangs, or sanitizer errors
 * 4. If interesting behavior found, add to corpus and continue mutating
 * 
 * @param data Pointer to fuzzed input bytes (raw bytecode)
 * @param size Number of bytes in input (0 to max_len)
 * @return 0 to continue fuzzing, -1 to reject input (not used here)
 * 
 * PERFORMANCE NOTE:
 * - This function is called millions of times during fuzzing
 * - Must be fast to maximize fuzzing throughput
 * - Current implementation: ~10-100us per iteration for valid bytecode
 * 
 * SAFETY NOTE:
 * - This function must never throw exceptions (fuzzer will catch and report)
 * - All VM operations are noexcept or catch internally
 * - AddressSanitizer will catch any memory errors
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // STEP 1: Validate minimum input size
    // BytecodeHeader is 24 bytes (see VMInterpreter.hpp line 264-271)
    // If input is smaller, it cannot be valid bytecode
    // Return 0 to tell fuzzer "this input was boring, try something else"
    if (size < sizeof(BytecodeHeader)) {
        return 0;  // Too small to be valid bytecode
    }
    
    // STEP 2: Attempt to load bytecode from fuzzed input
    // Bytecode::load() validates:
    // - Magic number (0x53454E54 = "SENT")
    // - Header structure integrity
    // - Constant pool and instruction sizes
    // It does NOT verify the hash - that's done by verify()
    // load() returns false if bytecode is structurally invalid
    Bytecode bytecode;
    std::vector<uint8_t> input_data(data, data + size);  // Copy to vector (required by load())
    
    if (!bytecode.load(input_data)) {
        // Bytecode is structurally invalid (bad magic, size mismatch, etc.)
        // This is expected for random inputs - just return
        // The fuzzer will try mutations to find valid structures
        return 0;
    }
    
    // STEP 3: Configure VM with limits appropriate for fuzzing
    // These limits prevent the fuzzer from hanging on complex bytecode
    VMConfig config{};
    
    // max_instructions: Limit opcode execution to 1000 instructions
    // - Prevents infinite loops from blocking fuzzer
    // - Production default is 100000, but fuzzing needs fast iterations
    // - If exceeded, VM returns VMResult::Error
    config.max_instructions = 1000;
    
    // timeout_ms: Maximum execution time of 100ms
    // - Prevents timeouts from slowing down fuzzing
    // - Production default is 5000ms, but fuzzing needs speed
    // - If exceeded, VM returns VMResult::Timeout
    config.timeout_ms = 100;
    
    // max_stack_depth: Stack overflow protection (keep default)
    // - Default is 1024 which is appropriate for fuzzing
    // - Prevents stack-based OOM
    
    // max_memory_reads: Limit memory read operations (keep default)
    // - Default is 10000 which is appropriate for fuzzing
    // - Prevents excessive memory scanning
    
    // enable_safe_reads: Use VirtualQuery validation (keep default true)
    // - Ensures memory reads are safe
    // - Critical for security testing
    
    // STEP 4: Create VM interpreter instance
    // VMInterpreter constructor is noexcept and cannot fail
    VMInterpreter vm(config);
    
    // NOTE: We do NOT register external callbacks (OP_CALL_EXT)
    // This is intentional to keep fuzzing focused on core VM logic
    // External callbacks would require setting up mock functions
    // and would slow down fuzzing iterations significantly
    
    // NOTE: We do NOT set custom opcode map (polymorphism)
    // Identity map is used by default
    // Testing polymorphic opcodes would require generating valid maps
    // which is out of scope for basic fuzzing
    
    // STEP 5: Execute bytecode in VM
    // execute() is noexcept and handles all errors internally
    // It will:
    // - Verify bytecode hash (may fail for fuzzed inputs)
    // - Execute instructions up to max_instructions or timeout
    // - Return VMResult indicating outcome
    // - Never crash or corrupt memory (protected by bounds checks)
    VMOutput output = vm.execute(bytecode);
    
    // STEP 6: Validate VM output invariants
    // The VM MUST return one of the five valid VMResult values
    // If it returns anything else, the enum is corrupted (memory corruption)
    // This assertion will catch such bugs
    //
    // Valid values (see VMInterpreter.hpp line 72-78):
    // - VMResult::Clean = 0: No violations detected
    // - VMResult::Violation = 1: Integrity violation detected
    // - VMResult::Error = 2: VM error (malformed bytecode, etc.)
    // - VMResult::Timeout = 3: Execution timeout exceeded
    // - VMResult::Halted = 4: Explicit halt opcode executed
    //
    // If this assertion fails, it means:
    // - Memory corruption occurred
    // - VM returned garbage value
    // - This is a CRITICAL BUG that must be fixed
    assert(output.result == VMResult::Clean ||
           output.result == VMResult::Violation ||
           output.result == VMResult::Error ||
           output.result == VMResult::Timeout ||
           output.result == VMResult::Halted);
    
    // ADDITIONAL INVARIANTS (implicit, checked by sanitizers):
    // - No memory leaks (checked by AddressSanitizer)
    // - No use-after-free (checked by AddressSanitizer)
    // - No buffer overflows (checked by AddressSanitizer)
    // - No undefined behavior (would be checked by UBSan if enabled)
    // - No data races (would be checked by TSan if testing concurrency)
    
    // STEP 7: Return success to fuzzer
    // Returning 0 tells LibFuzzer "this input was processed successfully"
    // The fuzzer will continue with new mutations or inputs
    // If we crashed or hung, the fuzzer would detect it and save the input
    return 0;
}

/**
 * OPTIONAL: LibFuzzer custom mutator (not implemented)
 * 
 * LibFuzzer allows custom mutators for structure-aware fuzzing.
 * For bytecode, we could implement:
 * - LLVMFuzzerCustomMutator: Mutate bytecode in structure-aware way
 * - LLVMFuzzerCustomCrossOver: Cross-over two bytecodes intelligently
 * 
 * This would be more effective than random bit flips, but adds complexity.
 * For now, we rely on seed corpus + bit-level mutations.
 * 
 * If needed in the future, see LibFuzzer documentation:
 * https://llvm.org/docs/LibFuzzer.html#custom-mutators
 */

/**
 * OPTIONAL: LibFuzzer initialization (not implemented)
 * 
 * extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
 *     // One-time initialization if needed
 *     // For example: load configurations, setup logging
 *     return 0;
 * }
 */
