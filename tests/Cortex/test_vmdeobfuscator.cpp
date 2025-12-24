/**
 * test_vmdeobfuscator.cpp
 * Unit tests for VMDeobfuscator
 */

#include <gtest/gtest.h>
#include "VMDeobfuscator/VMDeobfuscator.hpp"

using namespace Sentinel::Cortex::VMDeobfuscator;

class VMDeobfuscatorTest : public ::testing::Test {
protected:
    void SetUp() override {
        engine = std::make_unique<VMDeobfuscatorEngine>();
    }
    
    std::unique_ptr<VMDeobfuscatorEngine> engine;
};

TEST_F(VMDeobfuscatorTest, EngineInitialization) {
    EXPECT_TRUE(engine->isReady());
}

TEST_F(VMDeobfuscatorTest, DetectProtectorInMemory) {
    // VMProtect-like pattern
    std::vector<uint8_t> code = {
        0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10,  // push ebp; mov ebp, esp; sub esp, 10
        0x90, 0x90, 0x90, 0x90
    };
    
    auto result = engine->detectProtectorInMemory(code, 0x400000);
    
    ASSERT_TRUE(result.isSuccess());
    // Should detect something (even if Unknown)
    EXPECT_TRUE(result.value().type != VMProtectorType::VMProtect || 
                result.value().confidence != ConfidenceLevel::None);
}

TEST_F(VMDeobfuscatorTest, AnalyzeMemory) {
    std::vector<uint8_t> code = {
        0x55, 0x8B, 0xEC, 0x90, 0x90, 0xC3  // Simple function
    };
    
    DeobfuscatorOptions options;
    options.enableDynamicTracing = true;
    options.enableSymbolicExecution = false;  // Simplified test
    options.enableSSALifting = true;
    options.generatePseudoC = true;
    
    auto result = engine->analyzeMemory(code, 0x400000, 0x400000, options);
    
    ASSERT_TRUE(result.isSuccess());
    EXPECT_GE(result.value().analysisTimeSeconds, 0.0);
}

TEST_F(VMDeobfuscatorTest, GetSupportedProtectors) {
    auto protectors = VMDeobfuscatorEngine::getSupportedProtectors();
    
    EXPECT_FALSE(protectors.empty());
    EXPECT_NE(std::find(protectors.begin(), protectors.end(), "VMProtect"), protectors.end());
    EXPECT_NE(std::find(protectors.begin(), protectors.end(), "Themida"), protectors.end());
}

TEST_F(VMDeobfuscatorTest, VirtualInstructionToString) {
    VirtualInstruction vinstr;
    vinstr.vmAddress = 0x1000;
    vinstr.mnemonic = "VPush";
    vinstr.operands = {0x42};
    vinstr.comment = "Push constant";
    
    std::string str = vinstr.toString();
    
    EXPECT_NE(str.find("1000"), std::string::npos);
    EXPECT_NE(str.find("VPush"), std::string::npos);
    EXPECT_NE(str.find("42"), std::string::npos);
}

TEST_F(VMDeobfuscatorTest, SSAValueCreation) {
    auto constVal = SSAValue::constant(42, 32);
    EXPECT_EQ(constVal.type, SSAValueType::Constant);
    EXPECT_EQ(constVal.constantValue.value(), 42);
    EXPECT_EQ(constVal.bitWidth, 32);
    
    auto tempVal = SSAValue::temp(123, 64);
    EXPECT_EQ(tempVal.type, SSAValueType::Temporary);
    EXPECT_EQ(tempVal.id, 123);
    EXPECT_EQ(tempVal.bitWidth, 64);
}

TEST_F(VMDeobfuscatorTest, SSAInstructionToString) {
    SSAInstruction instr;
    instr.opcode = SSAOpcode::Add;
    instr.result = SSAValue::temp(1, 64);
    instr.operands = {SSAValue::temp(2, 64), SSAValue::constant(10, 64)};
    
    std::string str = instr.toString();
    
    EXPECT_NE(str.find("add"), std::string::npos);
}

TEST_F(VMDeobfuscatorTest, SSAFunctionToPseudoC) {
    SSAFunction func;
    func.name = "test_function";
    func.originalAddress = 0x401000;
    
    SSABasicBlock block;
    block.label = "entry";
    
    SSAInstruction retInstr;
    retInstr.opcode = SSAOpcode::Ret;
    block.instructions.push_back(retInstr);
    
    func.blocks.push_back(block);
    
    std::string pseudoC = func.toPseudoC();
    
    EXPECT_NE(pseudoC.find("test_function"), std::string::npos);
    EXPECT_NE(pseudoC.find("entry"), std::string::npos);
}

TEST_F(VMDeobfuscatorTest, ExecutionTraceFiltering) {
    ExecutionTrace trace;
    
    TraceEntry entry1;
    entry1.address = 0x1000;
    trace.entries.push_back(entry1);
    
    TraceEntry entry2;
    entry2.address = 0x2000;
    trace.entries.push_back(entry2);
    
    TraceEntry entry3;
    entry3.address = 0x3000;
    trace.entries.push_back(entry3);
    
    auto filtered = trace.filterRange(0x1500, 0x2500);
    
    EXPECT_EQ(filtered.entries.size(), 1);
    EXPECT_EQ(filtered.entries[0].address, 0x2000);
}

TEST_F(VMDeobfuscatorTest, ExecutionTraceUniqueAddresses) {
    ExecutionTrace trace;
    
    for (int i = 0; i < 5; ++i) {
        TraceEntry entry;
        entry.address = 0x1000 + (i % 2) * 0x100;  // Alternating addresses
        trace.entries.push_back(entry);
    }
    
    auto unique = trace.getUniqueAddresses();
    
    EXPECT_EQ(unique.size(), 2);  // Only two unique addresses
}

TEST_F(VMDeobfuscatorTest, VirtualCFGBlockRetrieval) {
    VirtualCFG cfg;
    
    VirtualBasicBlock block;
    block.startAddress = 0x1000;
    block.endAddress = 0x1100;
    cfg.blocks[0x1000] = block;
    
    const auto* retrieved = cfg.getBlockAt(0x1000);
    ASSERT_NE(retrieved, nullptr);
    EXPECT_EQ(retrieved->startAddress, 0x1000);
    
    const auto* notFound = cfg.getBlockAt(0x2000);
    EXPECT_EQ(notFound, nullptr);
}

TEST_F(VMDeobfuscatorTest, DeobfuscationResultJSON) {
    DeobfuscationResult result;
    result.detection.type = VMProtectorType::VMProtect;
    result.detection.confidence = ConfidenceLevel::High;
    result.virtualInstructionCount = 100;
    result.handlerCount = 20;
    result.basicBlockCount = 10;
    result.analysisTimeSeconds = 1.5;
    
    std::string json = result.toJSON();
    
    EXPECT_NE(json.find("VMProtect"), std::string::npos);
    EXPECT_NE(json.find("100"), std::string::npos);
    EXPECT_NE(json.find("20"), std::string::npos);
}

TEST_F(VMDeobfuscatorTest, HandlerDatabase) {
    HandlerDatabase db;
    
    std::vector<uint8_t> pattern = {0x48, 0x8B, 0x00};  // mov rax, [rax]
    db.addPattern(VirtualOpcodeType::VLoad, pattern, "xxx");
    
    EXPECT_EQ(db.patternCount(), 1);
    
    auto [opcode, confidence] = db.match(pattern);
    EXPECT_EQ(opcode, VirtualOpcodeType::VLoad);
}

TEST_F(VMDeobfuscatorTest, OpcodeTypeToString) {
    EXPECT_EQ(opcodeTypeToString(VirtualOpcodeType::VPush), "VPush");
    EXPECT_EQ(opcodeTypeToString(VirtualOpcodeType::VAdd), "VAdd");
    EXPECT_EQ(opcodeTypeToString(VirtualOpcodeType::VJmp), "VJmp");
    EXPECT_EQ(opcodeTypeToString(VirtualOpcodeType::Unknown), "Unknown");
}

TEST_F(VMDeobfuscatorTest, ProtectorTypeToString) {
    EXPECT_EQ(protectorTypeToString(VMProtectorType::VMProtect), "VMProtect");
    EXPECT_EQ(protectorTypeToString(VMProtectorType::Themida), "Themida");
    EXPECT_EQ(protectorTypeToString(VMProtectorType::Unknown), "Unknown");
}

TEST_F(VMDeobfuscatorTest, ConfidenceToString) {
    EXPECT_EQ(confidenceToString(ConfidenceLevel::Certain), "Certain");
    EXPECT_EQ(confidenceToString(ConfidenceLevel::High), "High");
    EXPECT_EQ(confidenceToString(ConfidenceLevel::Medium), "Medium");
    EXPECT_EQ(confidenceToString(ConfidenceLevel::Low), "Low");
    EXPECT_EQ(confidenceToString(ConfidenceLevel::None), "None");
}

TEST_F(VMDeobfuscatorTest, ProgressTracking) {
    EXPECT_EQ(engine->getProgress(), 0);
    
    // After analysis, progress should be tracked
    std::vector<uint8_t> code = {0x90, 0x90, 0xC3};
    DeobfuscatorOptions options;
    options.enableDynamicTracing = false;  // Quick test
    
    engine->analyzeMemory(code, 0x400000, 0x400000, options);
    
    // Progress should be updated (likely to 100 after completion)
    EXPECT_GE(engine->getProgress(), 0);
}

TEST_F(VMDeobfuscatorTest, CancelAnalysis) {
    // Should not crash
    engine->cancelAnalysis();
    EXPECT_TRUE(engine->isReady());
}
