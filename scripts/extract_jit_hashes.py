#!/usr/bin/env python3
"""
JIT Signature Hash Extractor Utility

This script extracts the first 4KB of the .text section from JIT engine DLLs
and computes their SHA-256 hashes for the JIT signature database.

Usage:
    python3 extract_jit_hashes.py <path_to_dll> [--output <output_file>]

Example:
    python3 extract_jit_hashes.py "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\clrjit.dll"

The script will:
1. Parse the PE headers to locate the .text section
2. Read the first 4KB of the .text section
3. Compute the SHA-256 hash
4. Output the hash in C++ array format for easy integration

Requirements:
    - Python 3.6+
    - pefile library (pip install pefile)
"""

import sys
import hashlib
import argparse
from pathlib import Path

try:
    import pefile
except ImportError:
    print("Error: pefile library not found. Install it with: pip install pefile")
    sys.exit(1)


def extract_text_section_hash(dll_path: str) -> tuple:
    """
    Extract the .text section from a DLL and compute its SHA-256 hash.
    
    Args:
        dll_path: Path to the DLL file
        
    Returns:
        Tuple of (hash_bytes, module_name, text_offset, text_size)
    """
    try:
        pe = pefile.PE(dll_path)
        
        # Find the .text section
        text_section = None
        for section in pe.sections:
            section_name = section.Name.decode('utf-8').rstrip('\x00')
            if section_name == '.text':
                text_section = section
                break
        
        if not text_section:
            raise ValueError("No .text section found in the DLL")
        
        # Read the first 4KB (or entire section if smaller)
        text_offset = text_section.PointerToRawData
        text_size = min(text_section.SizeOfRawData, 4096)
        
        # Read the raw data
        with open(dll_path, 'rb') as f:
            f.seek(text_offset)
            text_data = f.read(text_size)
        
        # Compute SHA-256 hash
        hash_obj = hashlib.sha256(text_data)
        hash_bytes = hash_obj.digest()
        
        # Get module name from path
        module_name = Path(dll_path).name
        
        return hash_bytes, module_name, text_offset, text_size
        
    except Exception as e:
        raise RuntimeError(f"Failed to process {dll_path}: {e}")


def format_cpp_array(hash_bytes: bytes) -> str:
    """Format hash bytes as a C++ array initializer."""
    hex_values = [f"0x{b:02x}" for b in hash_bytes]
    # Format as multiple lines for readability
    lines = []
    for i in range(0, len(hex_values), 8):
        line = ", ".join(hex_values[i:i+8])
        lines.append(f"        {line}")
    return ",\n".join(lines)


def generate_signature_code(dll_path: str, version: str = "Unknown", engine_type: str = "Unknown") -> str:
    """
    Generate C++ code for adding this signature to the database.
    
    Args:
        dll_path: Path to the DLL
        version: Version string (e.g., ".NET 8.0", "V8 10.x")
        engine_type: Engine type (e.g., "DotNetCLR", "V8JavaScript")
        
    Returns:
        C++ code snippet
    """
    hash_bytes, module_name, text_offset, text_size = extract_text_section_hash(dll_path)
    
    cpp_array = format_cpp_array(hash_bytes)
    
    code = f"""
// {module_name} - {version}
// .text section: offset=0x{text_offset:x}, size=0x{text_size:x}
{{
    JITSignature sig;
    sig.module_name = L"{module_name}";
    sig.engine_type = JITEngineType::{engine_type};
    sig.version = L"{version}";
    sig.text_hash = {{
{cpp_array}
    }};
    AddSignature(sig);
}}
"""
    return code


def main():
    parser = argparse.ArgumentParser(
        description="Extract JIT signature hashes from DLL files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("dll_path", help="Path to the JIT engine DLL")
    parser.add_argument("--version", default="Unknown", help="Version string (e.g., '.NET 8.0')")
    parser.add_argument("--engine-type", default="Unknown", 
                       choices=["DotNetCLR", "V8JavaScript", "LuaJIT", "UnityIL2CPP", "Unknown"],
                       help="JIT engine type")
    parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    
    args = parser.parse_args()
    
    try:
        code = generate_signature_code(args.dll_path, args.version, args.engine_type)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(code)
            print(f"Signature written to {args.output}")
        else:
            print(code)
            
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
