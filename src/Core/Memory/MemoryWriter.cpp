/**
 * @file MemoryWriter.cpp
 * @brief Implementation of safe memory writing
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 */

#include <Sentinel/Core/MemoryWriter.hpp>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <mutex>
#include <algorithm>

namespace Sentinel::Memory {

// ============================================================================
// WriteTransaction Implementation
// ============================================================================

class WriteTransaction::Impl {
public:
    Impl(MemoryWriter* writer, const WriteOptions& options)
        : m_writer(writer)
        , m_options(options)
        , m_committed(false)
        , m_rolledBack(false)
    {}
    
    ~Impl() {
        if (!m_committed && !m_rolledBack && !m_operations.empty()) {
            // Auto-rollback on destruction
            rollback();
        }
    }
    
    Result<void> addWrite(Address address, const ByteBuffer& bytes) {
        if (m_committed || m_rolledBack) {
            return ErrorCode::InvalidState;
        }
        
        WriteOperation op;
        op.address = address;
        op.newBytes = bytes;
        op.committed = false;
        
        m_operations.push_back(std::move(op));
        return ErrorCode::Success;
    }
    
    Result<void> commit() {
        if (m_committed) return ErrorCode::InvalidState;
        if (m_rolledBack) return ErrorCode::InvalidState;
        
        // First, read and store all original bytes
        for (auto& op : m_operations) {
            auto readResult = readMemory(op.address, op.newBytes.size());
            if (readResult.isFailure()) {
                // Rollback any already committed operations
                rollback();
                return readResult.error();
            }
            op.originalBytes = std::move(readResult.value());
        }
        
        // Now write all new bytes
        for (auto& op : m_operations) {
            auto writeResult = writeMemory(op.address, op.newBytes);
            if (writeResult.isFailure()) {
                // Rollback all operations
                rollback();
                return writeResult.error();
            }
            op.committed = true;
        }
        
        m_committed = true;
        return ErrorCode::Success;
    }
    
    Result<void> rollback() {
        if (m_rolledBack) return ErrorCode::Success;
        
        // Rollback in reverse order
        for (auto it = m_operations.rbegin(); it != m_operations.rend(); ++it) {
            if (it->committed && !it->originalBytes.empty()) {
                writeMemory(it->address, it->originalBytes);
                it->committed = false;
            }
        }
        
        m_rolledBack = true;
        return ErrorCode::Success;
    }
    
    bool hasPendingOperations() const noexcept {
        return !m_operations.empty() && !m_committed && !m_rolledBack;
    }
    
    size_t pendingCount() const noexcept {
        return m_operations.size();
    }
    
    const std::vector<WriteOperation>& operations() const noexcept {
        return m_operations;
    }

private:
    Result<ByteBuffer> readMemory(Address address, size_t size) {
        HANDLE process = GetCurrentProcess();
        ByteBuffer buffer(size);
        SIZE_T bytesRead;
        
        if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address),
                buffer.data(), size, &bytesRead)) {
            return ErrorCode::MemoryReadFailed;
        }
        
        buffer.resize(bytesRead);
        return buffer;
    }
    
    Result<void> writeMemory(Address address, const ByteBuffer& bytes) {
        HANDLE process = GetCurrentProcess();
        DWORD oldProtect;
        
        // Change protection if needed
        if (m_options.autoProtection) {
            if (!VirtualProtect(reinterpret_cast<LPVOID>(address), bytes.size(),
                    PAGE_EXECUTE_READWRITE, &oldProtect)) {
                return ErrorCode::ProtectionChangeFailed;
            }
        }
        
        // Write the bytes
        SIZE_T bytesWritten;
        BOOL success = WriteProcessMemory(process, reinterpret_cast<LPVOID>(address),
            bytes.data(), bytes.size(), &bytesWritten);
        
        // Restore protection
        if (m_options.autoProtection && m_options.restoreProtection) {
            DWORD temp;
            VirtualProtect(reinterpret_cast<LPVOID>(address), bytes.size(),
                oldProtect, &temp);
        }
        
        if (!success || bytesWritten != bytes.size()) {
            return ErrorCode::MemoryWriteFailed;
        }
        
        // Flush instruction cache
        if (m_options.flushInstructionCache) {
            FlushInstructionCache(process, reinterpret_cast<LPCVOID>(address), bytes.size());
        }
        
        return ErrorCode::Success;
    }
    
    MemoryWriter* m_writer;
    WriteOptions m_options;
    std::vector<WriteOperation> m_operations;
    bool m_committed;
    bool m_rolledBack;
};

WriteTransaction::WriteTransaction(MemoryWriter* writer, const WriteOptions& options)
    : m_impl(std::make_unique<Impl>(writer, options))
{}

WriteTransaction::~WriteTransaction() = default;
WriteTransaction::WriteTransaction(WriteTransaction&&) noexcept = default;
WriteTransaction& WriteTransaction::operator=(WriteTransaction&&) noexcept = default;

Result<void> WriteTransaction::write(Address address, const ByteBuffer& bytes) {
    return m_impl->addWrite(address, bytes);
}

Result<void> WriteTransaction::write(Address address, ByteSpan bytes) {
    return write(address, ByteBuffer(bytes.begin(), bytes.end()));
}

Result<void> WriteTransaction::nop(Address address, size_t size) {
    ByteBuffer nops(size, 0x90); // x86/x64 NOP
    return write(address, nops);
}

Result<void> WriteTransaction::commit() {
    return m_impl->commit();
}

Result<void> WriteTransaction::rollback() {
    return m_impl->rollback();
}

bool WriteTransaction::hasPendingOperations() const noexcept {
    return m_impl->hasPendingOperations();
}

size_t WriteTransaction::pendingCount() const noexcept {
    return m_impl->pendingCount();
}

const std::vector<WriteOperation>& WriteTransaction::operations() const noexcept {
    return m_impl->operations();
}

// ============================================================================
// MemoryWriter Implementation
// ============================================================================

class MemoryWriter::Impl {
public:
    Impl() : m_processId(GetCurrentProcessId()), m_processHandle(GetCurrentProcess()) {}
    
    explicit Impl(ProcessId processId) : m_processId(processId) {
        if (processId == GetCurrentProcessId()) {
            m_processHandle = GetCurrentProcess();
        } else {
            m_processHandle = OpenProcess(
                PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ,
                FALSE,
                processId
            );
        }
    }
    
    ~Impl() {
        if (m_processHandle && m_processHandle != GetCurrentProcess()) {
            CloseHandle(m_processHandle);
        }
    }
    
    bool isValid() const noexcept {
        return m_processHandle != nullptr;
    }
    
    ProcessId getProcessId() const noexcept {
        return m_processId;
    }
    
    Result<ByteBuffer> write(Address address, const ByteBuffer& bytes, const WriteOptions& options) {
        if (!isValid()) return ErrorCode::InvalidHandle;
        
        // Read original bytes first
        ByteBuffer originalBytes(bytes.size());
        SIZE_T bytesRead;
        if (!ReadProcessMemory(m_processHandle, reinterpret_cast<LPCVOID>(address),
                originalBytes.data(), bytes.size(), &bytesRead)) {
            return ErrorCode::MemoryReadFailed;
        }
        originalBytes.resize(bytesRead);
        
        // Suspend threads if requested
        std::vector<HANDLE> suspendedThreads;
        if (options.suspendThreads) {
            suspendedThreads = suspendOtherThreads();
        }
        
        DWORD oldProtect = 0;
        
        // Change protection if needed
        if (options.autoProtection) {
            if (!VirtualProtectEx(m_processHandle, reinterpret_cast<LPVOID>(address),
                    bytes.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
                resumeThreads(suspendedThreads);
                return ErrorCode::ProtectionChangeFailed;
            }
        }
        
        // Write with retries
        bool success = false;
        for (int attempt = 0; attempt <= options.maxRetries && !success; ++attempt) {
            SIZE_T bytesWritten;
            if (WriteProcessMemory(m_processHandle, reinterpret_cast<LPVOID>(address),
                    bytes.data(), bytes.size(), &bytesWritten)) {
                if (bytesWritten == bytes.size()) {
                    success = true;
                }
            }
            
            if (!success && attempt < options.maxRetries) {
                Sleep(options.retryDelayMs);
            }
        }
        
        // Restore protection
        if (options.autoProtection && options.restoreProtection) {
            DWORD temp;
            VirtualProtectEx(m_processHandle, reinterpret_cast<LPVOID>(address),
                bytes.size(), oldProtect, &temp);
        }
        
        // Flush instruction cache
        if (success && options.flushInstructionCache) {
            FlushInstructionCache(m_processHandle, reinterpret_cast<LPCVOID>(address), bytes.size());
        }
        
        // Resume threads
        resumeThreads(suspendedThreads);
        
        if (!success) {
            return ErrorCode::MemoryWriteFailed;
        }
        
        // Verify write if requested
        if (options.verifyWrite) {
            ByteBuffer verifyBuffer(bytes.size());
            if (!ReadProcessMemory(m_processHandle, reinterpret_cast<LPCVOID>(address),
                    verifyBuffer.data(), bytes.size(), &bytesRead)) {
                return ErrorCode::MemoryReadFailed;
            }
            
            if (memcmp(verifyBuffer.data(), bytes.data(), bytes.size()) != 0) {
                return ErrorCode::MemoryWriteFailed;
            }
        }
        
        return originalBytes;
    }
    
    Result<MemoryProtection> setProtection(Address address, size_t size, MemoryProtection newProtection) {
        if (!isValid()) return ErrorCode::InvalidHandle;
        
        DWORD oldProtect;
        if (!VirtualProtectEx(m_processHandle, reinterpret_cast<LPVOID>(address),
                size, static_cast<DWORD>(newProtection), &oldProtect)) {
            return ErrorCode::ProtectionChangeFailed;
        }
        
        return static_cast<MemoryProtection>(oldProtect);
    }
    
    Result<void> flushInstructionCache(Address address, size_t size) {
        if (!isValid()) return ErrorCode::InvalidHandle;
        
        if (!FlushInstructionCache(m_processHandle, reinterpret_cast<LPCVOID>(address), size)) {
            return ErrorCode::SystemError;
        }
        
        return ErrorCode::Success;
    }
    
    WriteOptions& defaultOptions() { return m_defaultOptions; }
    const WriteOptions& defaultOptions() const { return m_defaultOptions; }

private:
    std::vector<HANDLE> suspendOtherThreads() {
        std::vector<HANDLE> handles;
        DWORD currentThreadId = GetCurrentThreadId();
        
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return handles;
        
        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        
        if (Thread32First(snapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == m_processId && te.th32ThreadID != currentThreadId) {
                    HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                    if (thread) {
                        SuspendThread(thread);
                        handles.push_back(thread);
                    }
                }
            } while (Thread32Next(snapshot, &te));
        }
        
        CloseHandle(snapshot);
        return handles;
    }
    
    void resumeThreads(std::vector<HANDLE>& handles) {
        for (HANDLE thread : handles) {
            ResumeThread(thread);
            CloseHandle(thread);
        }
        handles.clear();
    }
    
    ProcessId m_processId;
    HANDLE m_processHandle;
    WriteOptions m_defaultOptions;
    std::mutex m_mutex;
};

MemoryWriter::MemoryWriter() : m_impl(std::make_unique<Impl>()) {}

MemoryWriter::MemoryWriter(ProcessId processId) 
    : m_impl(std::make_unique<Impl>(processId)) {}

MemoryWriter::~MemoryWriter() = default;
MemoryWriter::MemoryWriter(MemoryWriter&&) noexcept = default;
MemoryWriter& MemoryWriter::operator=(MemoryWriter&&) noexcept = default;

Result<ByteBuffer> MemoryWriter::write(Address address, const ByteBuffer& bytes, const WriteOptions& options) {
    return m_impl->write(address, bytes, options);
}

Result<ByteBuffer> MemoryWriter::write(Address address, ByteSpan bytes, const WriteOptions& options) {
    return write(address, ByteBuffer(bytes.begin(), bytes.end()), options);
}

Result<ByteBuffer> MemoryWriter::nop(Address address, size_t size, const WriteOptions& options) {
    ByteBuffer nops(size, 0x90);
    return write(address, nops, options);
}

Result<ByteBuffer> MemoryWriter::fill(Address address, Byte value, size_t size, const WriteOptions& options) {
    ByteBuffer buffer(size, value);
    return write(address, buffer, options);
}

Result<void> MemoryWriter::restore(Address address, const ByteBuffer& originalBytes, const WriteOptions& options) {
    auto result = write(address, originalBytes, options);
    if (result.isFailure()) return result.error();
    return ErrorCode::Success;
}

WriteTransaction MemoryWriter::beginTransaction(const WriteOptions& options) {
    return WriteTransaction(this, options);
}

Result<MemoryProtection> MemoryWriter::setProtection(Address address, size_t size, MemoryProtection newProtection) {
    return m_impl->setProtection(address, size, newProtection);
}

Result<void> MemoryWriter::flushInstructionCache(Address address, size_t size) {
    return m_impl->flushInstructionCache(address, size);
}

bool MemoryWriter::isValid() const noexcept {
    return m_impl->isValid();
}

ProcessId MemoryWriter::getProcessId() const noexcept {
    return m_impl->getProcessId();
}

void MemoryWriter::setDefaultOptions(const WriteOptions& options) {
    m_impl->defaultOptions() = options;
}

const WriteOptions& MemoryWriter::getDefaultOptions() const noexcept {
    return m_impl->defaultOptions();
}

// ============================================================================
// Patch Application Helpers
// ============================================================================

Result<void> applyPatch(MemoryWriter& writer, const PatchEntry& patch, Address moduleBase) {
    if (!patch.active) return ErrorCode::Success;
    
    Address targetAddress = moduleBase + patch.rva;
    
    auto result = writer.write(targetAddress, patch.patchBytes);
    if (result.isFailure()) return result.error();
    
    return ErrorCode::Success;
}

Result<void> applyPatches(MemoryWriter& writer, const PatchList& patches, Address moduleBase) {
    auto transaction = writer.beginTransaction();
    
    // Sort by priority (higher first)
    PatchList sortedPatches = patches;
    std::sort(sortedPatches.begin(), sortedPatches.end(),
        [](const PatchEntry& a, const PatchEntry& b) {
            return a.priority > b.priority;
        });
    
    for (const auto& patch : sortedPatches) {
        if (!patch.active) continue;
        
        Address targetAddress = moduleBase + patch.rva;
        auto result = transaction.write(targetAddress, patch.patchBytes);
        if (result.isFailure()) {
            // Transaction will auto-rollback on destruction
            return result.error();
        }
    }
    
    return transaction.commit();
}

Result<void> revertPatch(MemoryWriter& writer, const PatchEntry& patch, Address moduleBase) {
    Address targetAddress = moduleBase + patch.rva;
    
    auto result = writer.write(targetAddress, patch.originalBytes);
    if (result.isFailure()) return result.error();
    
    return ErrorCode::Success;
}

} // namespace Sentinel::Memory
