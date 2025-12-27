# scripts/verify-hardening.ps1
param([string]$BinaryPath)

Write-Host "Verifying security hardening for: $BinaryPath"

# Use dumpbin to check characteristics
$dumpbin = & dumpbin /headers $BinaryPath 2>&1

# Check for DYNAMICBASE (ASLR)
if ($dumpbin -match "Dynamic base") {
    Write-Host "[PASS] ASLR enabled (DYNAMICBASE)" -ForegroundColor Green
} else {
    Write-Host "[FAIL] ASLR not enabled" -ForegroundColor Red
    exit 1
}

# Check for NXCOMPAT (DEP)
if ($dumpbin -match "NX compatible") {
    Write-Host "[PASS] DEP enabled (NXCOMPAT)" -ForegroundColor Green
} else {
    Write-Host "[FAIL] DEP not enabled" -ForegroundColor Red
    exit 1
}

# Check for HIGH_ENTROPY_VA
if ($dumpbin -match "High Entropy Virtual Addresses") {
    Write-Host "[PASS] High-entropy ASLR enabled" -ForegroundColor Green
} else {
    Write-Host "[WARN] High-entropy ASLR not enabled" -ForegroundColor Yellow
}

# Check for GUARD_CF
if ($dumpbin -match "Guard") {
    Write-Host "[PASS] Control Flow Guard enabled" -ForegroundColor Green
} else {
    Write-Host "[WARN] Control Flow Guard not detected" -ForegroundColor Yellow
}

Write-Host "Hardening verification complete."
