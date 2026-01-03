# VM Fuzzing Test - README

## Overview

This directory contains fuzzing infrastructure for testing the VMInterpreter against malformed bytecode. Fuzzing is a security testing technique that feeds random or mutated inputs to find crashes, hangs, and memory corruption bugs.

## Files

- **`fuzz_vm.cpp`**: LibFuzzer harness that tests VMInterpreter
- **`generate_seed_corpus.py`**: Python script to create valid bytecode samples
- **`README_FUZZING.md`**: This file (documentation)

## Requirements

- **Clang 6.0+** (for `-fsanitize=fuzzer` support)
- **CMake 3.21+**
- **Python 3** (for corpus generation)

Note: Fuzzing does **not** work with GCC or MSVC. You must use Clang.

## Building the Fuzzer

```bash
# Configure with fuzzing enabled
cmake -B build \
      -DCMAKE_CXX_COMPILER=clang++ \
      -DSENTINEL_ENABLE_FUZZING=ON \
      -DSENTINEL_BUILD_TESTS=ON

# Build the fuzzer target
cmake --build build --target fuzz_vm

# The fuzzer will be in: build/bin/fuzz_vm
```

## Generating Seed Corpus

The fuzzer works best with a seed corpus of valid bytecode samples. The corpus generator creates 12 diverse samples:

```bash
# Create corpus directory
mkdir -p build/corpus/fuzz_vm

# Generate seed corpus
python3 tests/SDK/generate_seed_corpus.py build/corpus/fuzz_vm/

# Verify corpus was created
ls -lh build/corpus/fuzz_vm/
```

The generator creates samples testing:
1. Minimal bytecode (just HALT)
2. Sequential execution (NOPs)
3. Stack operations (PUSH/POP)
4. Arithmetic (ADD, SUB, MUL, DIV)
5. Control flow (JMP, JZ)
6. Comparisons (CMP_EQ)
7. Edge cases (empty constants, long sequences)

## Running the Fuzzer

### Basic Usage

```bash
cd build
./bin/fuzz_vm corpus/fuzz_vm/ -max_len=65536 -timeout=10
```

This will:
- Read initial corpus from `corpus/fuzz_vm/`
- Generate inputs up to 65KB in size
- Timeout individual tests after 10 seconds
- Run indefinitely until you press Ctrl+C

### One-Hour Fuzzing Session (Recommended)

```bash
./bin/fuzz_vm corpus/fuzz_vm/ \
    -max_len=65536 \
    -timeout=10 \
    -max_total_time=3600
```

**Definition of Done**: Pass if no crashes in 1 hour.

### Parallel Fuzzing (Faster)

```bash
# Use 4 CPU cores for 4x speedup
./bin/fuzz_vm corpus/fuzz_vm/ \
    -jobs=4 \
    -workers=4 \
    -max_len=65536 \
    -timeout=10
```

### Common Options

- `-max_len=N`: Maximum input size in bytes (default: 4096)
- `-timeout=N`: Timeout per test in seconds (default: 1200)
- `-max_total_time=N`: Stop after N seconds (for CI)
- `-jobs=N`: Run N parallel fuzzing jobs
- `-workers=N`: Use N worker processes
- `-dict=file`: Use mutation dictionary (advanced)
- `-help=1`: Show all options

## Interpreting Results

### Success (No Crashes)

```
#1000000: NEW    cov: 234 ft: 1024 corp: 156 exec/s: 2500 ...
```

- `NEW`: Found interesting input (added to corpus)
- `cov: 234`: Code coverage (234 basic blocks covered)
- `ft: 1024`: Feature count (unique execution paths)
- `corp: 156`: Corpus size (156 interesting inputs)
- `exec/s: 2500`: Executions per second (throughput)

If fuzzer runs for 1 hour with no crashes: **PASS** ✅

### Crash Found

```
==12345==ERROR: AddressSanitizer: heap-buffer-overflow
```

The fuzzer will:
1. Stop execution
2. Save crashing input to `crash-<hash>` file
3. Print stack trace and error details

**Action Required**:
1. Reproduce: `./bin/fuzz_vm crash-<hash>`
2. Debug: Use GDB or analyze stack trace
3. Fix the bug in VMInterpreter or Bytecode code
4. Add regression test to `test_vm.cpp`
5. Re-run fuzzer to verify fix

### Common Crashes

#### Heap Buffer Overflow
```
ERROR: AddressSanitizer: heap-buffer-overflow
```
- **Cause**: Reading/writing beyond allocated memory
- **Fix**: Add bounds checks to bytecode parsing or VM execution

#### Stack Overflow
```
ERROR: AddressSanitizer: stack-overflow
```
- **Cause**: Infinite recursion or excessive stack usage
- **Fix**: Check max_stack_depth enforcement in VM

#### Use-After-Free
```
ERROR: AddressSanitizer: heap-use-after-free
```
- **Cause**: Accessing freed memory
- **Fix**: Review object lifetimes and move semantics

#### Timeout
```
TIMEOUT: input took > 10s to execute
```
- **Cause**: Infinite loop or very slow bytecode
- **Fix**: Verify instruction count limit is enforced

## Corpus Management

### Growing Corpus

The fuzzer automatically adds interesting inputs to the corpus:

```bash
# Before fuzzing
ls corpus/fuzz_vm/ | wc -l
# 12

# After 1 hour
ls corpus/fuzz_vm/ | wc -l
# 156 (corpus grew by 144 files)
```

This is normal - the fuzzer discovers new code paths.

### Minimizing Corpus

After long fuzzing sessions, minimize the corpus to remove redundant files:

```bash
# Backup original corpus
cp -r corpus/fuzz_vm corpus/fuzz_vm.backup

# Minimize (keep smallest files with unique coverage)
./bin/fuzz_vm -merge=1 corpus/fuzz_vm_min corpus/fuzz_vm

# Replace original
mv corpus/fuzz_vm_min corpus/fuzz_vm
```

### Sharing Corpus

The corpus can be committed to the repository:

```bash
# Add seed corpus to git (optional)
git add corpus/fuzz_vm/seed_*.bin
git commit -m "Add VM fuzzing seed corpus"
```

**Note**: Don't commit the entire grown corpus (too many files). Only commit seed files.

## Continuous Fuzzing

For production projects, integrate with OSS-Fuzz:

1. Submit project to OSS-Fuzz: https://github.com/google/oss-fuzz
2. They will run fuzzer 24/7 on Google infrastructure
3. Crashes are reported automatically via bug tracker

## Debugging Crashes

### Reproduce Locally

```bash
# Run crashing input through fuzzer
./bin/fuzz_vm crash-abc123

# Run with debugger
gdb --args ./bin/fuzz_vm crash-abc123
```

### Inspect Crashing Bytecode

```bash
# Hex dump of crash file
xxd crash-abc123 | head -20

# Check if it's valid bytecode structure
python3 -c "
import sys
data = open('crash-abc123', 'rb').read()
print(f'Size: {len(data)} bytes')
print(f'Magic: {data[0:4].hex()}')
print(f'Version: {int.from_bytes(data[4:6], \"little\")}')
"
```

### Add Regression Test

After fixing, add to `test_vm.cpp`:

```cpp
TEST(VMInterpreterTests, FuzzRegression_Issue123) {
    // Reproduce crash found by fuzzer
    std::vector<uint8_t> crash_input = {
        // ... bytes from crash file ...
    };
    
    Bytecode bytecode;
    bytecode.load(crash_input);
    
    VMInterpreter vm;
    VMOutput output = vm.execute(bytecode);
    
    // Should not crash - any result is acceptable
    EXPECT_TRUE(output.result == VMResult::Clean ||
                output.result == VMResult::Error);
}
```

## Advanced: Custom Mutators

For structure-aware fuzzing, implement custom mutators:

```cpp
extern "C" size_t LLVMFuzzerCustomMutator(
    uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed) {
    // Mutate bytecode in structure-aware way
    // - Change opcodes but keep header valid
    // - Adjust jumps to stay in bounds
    // - Modify constants without breaking format
    return new_size;
}
```

See LibFuzzer docs: https://llvm.org/docs/LibFuzzer.html#custom-mutators

## Troubleshooting

### "Fuzzing requires Clang compiler"

**Problem**: CMake used GCC or MSVC instead of Clang.

**Solution**: Explicitly set compiler:
```bash
cmake -DCMAKE_CXX_COMPILER=clang++ ...
```

### "undefined reference to __sanitizer_cov"

**Problem**: Sanitizer libraries not found.

**Solution**: Install LLVM/Clang development packages:
```bash
# Ubuntu/Debian
sudo apt-get install clang libclang-dev

# Fedora
sudo dnf install clang compiler-rt
```

### Slow Fuzzing (< 100 exec/s)

**Problem**: Instrumentation overhead or slow VM execution.

**Solutions**:
- Reduce `max_instructions` in fuzz_vm.cpp (currently 1000)
- Reduce `timeout_ms` (currently 100ms)
- Use `-O2` or `-O3` optimization flags
- Disable expensive sanitizers (keep only ASan)

### Out of Memory

**Problem**: Fuzzer allocates too much memory.

**Solution**: Add memory limit:
```bash
./bin/fuzz_vm corpus/ -rss_limit_mb=2048
```

## References

- LibFuzzer Tutorial: https://llvm.org/docs/LibFuzzer.html
- OSS-Fuzz: https://google.github.io/oss-fuzz/
- AddressSanitizer: https://clang.llvm.org/docs/AddressSanitizer.html
- Fuzzing Best Practices: https://github.com/google/fuzzing

## Maintenance

### When to Run Fuzzing

- Before major releases (1+ hour session)
- After refactoring VM or Bytecode code
- When adding new opcodes
- After security vulnerability reports

### Updating Seed Corpus

When adding new opcodes or features:

1. Update `generate_seed_corpus.py` with new samples
2. Regenerate corpus: `python3 generate_seed_corpus.py corpus/fuzz_vm/`
3. Run fuzzer to discover new coverage
4. Commit new seed files

## Support

For questions or issues:
- File bug report with crash file attached
- Include fuzzer output and stack trace
- Specify Clang version and OS

---

**Last Updated**: 2026-01-03  
**Task**: 5.1 - Add Adversarial Fuzz Tests for VM  
**Status**: Implemented and documented
