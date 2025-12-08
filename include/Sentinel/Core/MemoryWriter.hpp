/**
 * @file MemoryWriter.hpp
 * @brief Safe memory writing with atomic operations and rollback support
 * @author Sentinel Security Team
 * @version 1.0.0
 * @date 2024
 * 
 * @copyright Copyright (c) 2024 Sentinel Security. All rights reserved.
 * 
 * This module provides safe memory writing capabilities with support for:
 * - Atomic writes
 * - Automatic protection handling
 * - Transaction-based writes with rollback
 * - Thread suspension during writes
 */

#pragma once

#ifndef SENTINEL_CORE_MEMORY_WRITER_HPP
#define SENTINEL_CORE_MEMORY_WRITER_HPP

#include <Sentinel/Core/Types.hpp>
#include <Sentinel/Core/ErrorCodes.hpp>
#include <vector>
#include <memory>
#include <functional>

namespace Sentinel::Memory {

// ============================================================================
// Write Options
// ============================================================================

/**
 * @brief Options for memory write operations
 */
struct WriteOptions {
    /// Automatically adjust memory protection
    bool autoProtection = true;
    
    /// Restore original protection after write
    bool restoreProtection = true;
    
    /// Flush instruction cache after write
    bool flushInstructionCache = true;
    
    /// Suspend other threads during write
    bool suspendThreads = false;
    
    /// Verify write by reading back
    bool verifyWrite = true;
    
    /// Maximum retries on failure
    int maxRetries = 3;
    
    /// Delay between retries in milliseconds
    int retryDelayMs = 10;
};

// ============================================================================
// Write Transaction
// ============================================================================

/**
 * @brief Represents a single memory write operation
 */
struct WriteOperation {
    Address address;           ///< Target address
    ByteBuffer newBytes;       ///< Bytes to write
    ByteBuffer originalBytes;  ///< Original bytes (for rollback)
    bool committed = false;    ///< Whether operation was committed
};

/**
 * @brief Transaction for atomic memory writes
 * 
 * Provides ACID-like guarantees for memory modifications:
 * - Atomicity: All writes succeed or none do
 * - Consistency: Memory stays consistent even on failure
 * - Isolation: Thread-safe operations
 * - Durability: Changes persist until explicitly reverted
 * 
 * @example
 * ```cpp
 * MemoryWriter writer;
 * auto transaction = writer.beginTransaction();
 * 
 * transaction.write(0x12345678, {0x90, 0x90, 0x90});
 * transaction.write(0x12345700, {0xE9, 0x00, 0x01, 0x00, 0x00});
 * 
 * auto result = transaction.commit();
 * if (result.isFailure()) {
 *     // All writes rolled back automatically
 * }
 * ```
 */
class WriteTransaction {
public:
    /// Transaction cannot be copied
    WriteTransaction(const WriteTransaction&) = delete;
    WriteTransaction& operator=(const WriteTransaction&) = delete;
    
    /// Transaction can be moved
    WriteTransaction(WriteTransaction&&) noexcept;
    WriteTransaction& operator=(WriteTransaction&&) noexcept;
    
    /// Destructor (rolls back if not committed)
    ~WriteTransaction();
    
    /**
     * @brief Add a write operation to the transaction
     * @param address Target address
     * @param bytes Bytes to write
     * @return Result indicating success or failure
     */
    Result<void> write(Address address, const ByteBuffer& bytes);
    
    /**
     * @brief Add a write operation to the transaction
     * @param address Target address
     * @param bytes Span of bytes to write
     * @return Result indicating success or failure
     */
    Result<void> write(Address address, ByteSpan bytes);
    
    /**
     * @brief Write a value to memory
     * @tparam T Type of value to write
     * @param address Target address
     * @param value Value to write
     * @return Result indicating success or failure
     */
    template<typename T>
    Result<void> writeValue(Address address, const T& value) {
        ByteBuffer bytes(sizeof(T));
        std::memcpy(bytes.data(), &value, sizeof(T));
        return write(address, bytes);
    }
    
    /**
     * @brief NOP out a range of memory
     * @param address Start address
     * @param size Number of bytes to NOP
     * @return Result indicating success or failure
     */
    Result<void> nop(Address address, size_t size);
    
    /**
     * @brief Commit all write operations
     * 
     * Applies all pending writes atomically. If any write fails,
     * all previous writes are rolled back.
     * 
     * @return Result indicating success or failure
     */
    Result<void> commit();
    
    /**
     * @brief Roll back all write operations
     * 
     * Restores original bytes for all committed operations.
     * 
     * @return Result indicating success or failure
     */
    Result<void> rollback();
    
    /**
     * @brief Check if transaction has pending operations
     * @return true if there are uncommitted operations
     */
    [[nodiscard]] bool hasPendingOperations() const noexcept;
    
    /**
     * @brief Get number of pending operations
     * @return Count of pending operations
     */
    [[nodiscard]] size_t pendingCount() const noexcept;
    
    /**
     * @brief Get all operations in this transaction
     * @return Vector of write operations
     */
    [[nodiscard]] const std::vector<WriteOperation>& operations() const noexcept;

private:
    friend class MemoryWriter;
    explicit WriteTransaction(class MemoryWriter* writer, const WriteOptions& options);
    
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

// ============================================================================
// Memory Writer Class
// ============================================================================

/**
 * @brief Safe memory writer with protection handling
 * 
 * Provides safe memory writing with automatic protection changes,
 * transaction support, and rollback capabilities.
 * 
 * @example
 * ```cpp
 * MemoryWriter writer;
 * 
 * // Simple write
 * auto result = writer.write(0x12345678, {0x90, 0x90, 0x90});
 * 
 * // Transaction-based write
 * auto transaction = writer.beginTransaction();
 * transaction.write(0x12345678, {0x90, 0x90, 0x90});
 * transaction.write(0x12345700, {0xE9, 0x00, 0x01, 0x00, 0x00});
 * transaction.commit();
 * ```
 */
class MemoryWriter {
public:
    /**
     * @brief Construct writer for current process
     */
    MemoryWriter();
    
    /**
     * @brief Construct writer for specific process
     * @param processId Target process ID
     */
    explicit MemoryWriter(ProcessId processId);
    
    /// Destructor
    ~MemoryWriter();
    
    // Non-copyable
    MemoryWriter(const MemoryWriter&) = delete;
    MemoryWriter& operator=(const MemoryWriter&) = delete;
    
    // Movable
    MemoryWriter(MemoryWriter&&) noexcept;
    MemoryWriter& operator=(MemoryWriter&&) noexcept;
    
    /**
     * @brief Write bytes to memory
     * @param address Target address
     * @param bytes Bytes to write
     * @param options Write options
     * @return Original bytes or error
     */
    [[nodiscard]] Result<ByteBuffer> write(
        Address address,
        const ByteBuffer& bytes,
        const WriteOptions& options = {}
    );
    
    /**
     * @brief Write bytes to memory
     * @param address Target address
     * @param bytes Span of bytes to write
     * @param options Write options
     * @return Original bytes or error
     */
    [[nodiscard]] Result<ByteBuffer> write(
        Address address,
        ByteSpan bytes,
        const WriteOptions& options = {}
    );
    
    /**
     * @brief Write a value to memory
     * @tparam T Type of value to write
     * @param address Target address
     * @param value Value to write
     * @param options Write options
     * @return Original value or error
     */
    template<typename T>
    [[nodiscard]] Result<T> writeValue(
        Address address,
        const T& value,
        const WriteOptions& options = {}
    ) {
        ByteBuffer bytes(sizeof(T));
        std::memcpy(bytes.data(), &value, sizeof(T));
        
        auto result = write(address, bytes, options);
        if (result.isFailure()) return result.error();
        
        T originalValue;
        std::memcpy(&originalValue, result.value().data(), sizeof(T));
        return originalValue;
    }
    
    /**
     * @brief NOP out a range of memory
     * @param address Start address
     * @param size Number of bytes to NOP
     * @param options Write options
     * @return Original bytes or error
     */
    [[nodiscard]] Result<ByteBuffer> nop(
        Address address,
        size_t size,
        const WriteOptions& options = {}
    );
    
    /**
     * @brief Fill memory with a byte value
     * @param address Start address
     * @param value Byte value to fill with
     * @param size Number of bytes to fill
     * @param options Write options
     * @return Original bytes or error
     */
    [[nodiscard]] Result<ByteBuffer> fill(
        Address address,
        Byte value,
        size_t size,
        const WriteOptions& options = {}
    );
    
    /**
     * @brief Restore previously saved bytes
     * @param address Target address
     * @param originalBytes Bytes to restore
     * @param options Write options
     * @return Result indicating success or failure
     */
    [[nodiscard]] Result<void> restore(
        Address address,
        const ByteBuffer& originalBytes,
        const WriteOptions& options = {}
    );
    
    /**
     * @brief Begin a write transaction
     * @param options Write options for the transaction
     * @return New transaction object
     */
    [[nodiscard]] WriteTransaction beginTransaction(const WriteOptions& options = {});
    
    /**
     * @brief Change memory protection
     * @param address Target address
     * @param size Size of region
     * @param newProtection New protection flags
     * @return Original protection or error
     */
    [[nodiscard]] Result<MemoryProtection> setProtection(
        Address address,
        size_t size,
        MemoryProtection newProtection
    );
    
    /**
     * @brief Flush instruction cache for a region
     * @param address Start address
     * @param size Size of region
     * @return Result indicating success or failure
     */
    [[nodiscard]] Result<void> flushInstructionCache(Address address, size_t size);
    
    /**
     * @brief Check if process is still valid
     * @return true if process is accessible
     */
    [[nodiscard]] bool isValid() const noexcept;
    
    /**
     * @brief Get process ID
     * @return Process ID being written to
     */
    [[nodiscard]] ProcessId getProcessId() const noexcept;
    
    /**
     * @brief Set default write options
     * @param options Default options for all writes
     */
    void setDefaultOptions(const WriteOptions& options);
    
    /**
     * @brief Get default write options
     * @return Current default options
     */
    [[nodiscard]] const WriteOptions& getDefaultOptions() const noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

// ============================================================================
// Patch Application Helpers
// ============================================================================

/**
 * @brief Apply a patch entry using MemoryWriter
 * @param writer Memory writer instance
 * @param patch Patch entry to apply
 * @param moduleBase Base address of target module
 * @return Result indicating success or failure
 */
[[nodiscard]] Result<void> applyPatch(
    MemoryWriter& writer,
    const PatchEntry& patch,
    Address moduleBase
);

/**
 * @brief Apply multiple patches atomically
 * @param writer Memory writer instance
 * @param patches Patches to apply
 * @param moduleBase Base address of target module
 * @return Result indicating success or failure
 */
[[nodiscard]] Result<void> applyPatches(
    MemoryWriter& writer,
    const PatchList& patches,
    Address moduleBase
);

/**
 * @brief Revert a patch entry
 * @param writer Memory writer instance
 * @param patch Patch entry to revert
 * @param moduleBase Base address of target module
 * @return Result indicating success or failure
 */
[[nodiscard]] Result<void> revertPatch(
    MemoryWriter& writer,
    const PatchEntry& patch,
    Address moduleBase
);

} // namespace Sentinel::Memory

#endif // SENTINEL_CORE_MEMORY_WRITER_HPP
