# ObfuscatedString Examples

This directory contains practical examples of using the ObfuscatedString framework in anti-cheat detection code.

## Building the Example

```bash
cd Sentinel-RE
mkdir -p build && cd build
cmake ..
g++ -std=c++20 -O2 -I../include ../docs/examples/obfuscated_string_example.cpp -o obfuscation_example
./obfuscation_example
```

## What's Demonstrated

The example shows 7 different use cases for string obfuscation:

1. **Simple Detection**: Obfuscating cheat engine process/window names
2. **Multiple Signatures**: Creating blacklists of obfuscated DLL names
3. **Logging**: Protecting violation messages and log output
4. **API Names**: Hiding Windows API function names used for detection
5. **Memory Patterns**: Obfuscating binary signatures used for pattern matching
6. **Configuration**: Protecting API keys and server URLs
7. **Report Templates**: Securing message templates

## Verifying Obfuscation

After building, you can verify that strings are obfuscated:

```bash
# This should NOT find the obfuscated strings
strings ./obfuscation_example | grep -i "speedhack"
strings ./obfuscation_example | grep -i "cheatengine"
strings ./obfuscation_example | grep -i "aimbot"
```

If the grep commands return nothing (or only partial matches from debug info), the obfuscation is working correctly.

## Performance Impact

The example demonstrates that obfuscation has minimal runtime impact:
- Decryption: < 1 microsecond per string
- Memory overhead: Only during active use
- Code size: Negligible increase

## Best Practices Demonstrated

✓ Use `OBFUSCATE_STR` for automatic memory cleanup  
✓ Obfuscate detection-critical strings  
✓ Create obfuscated strings close to point of use  
✓ Let RAII handle cleanup automatically  
✓ Store patterns/signatures in functions that return obfuscated strings  

## Integration with Existing Code

To integrate into your detection code:

1. Include the header:
   ```cpp
   #include <Sentinel/Core/ObfuscatedString.hpp>
   ```

2. Replace sensitive string literals:
   ```cpp
   // Before
   const char* cheat_name = "speedhack";
   
   // After
   auto cheat_name = OBFUSCATE_STR("speedhack");
   ```

3. Use the obfuscated string:
   ```cpp
   if (detectCheat(cheat_name.c_str())) {
       // Handle detection
   }
   ```

## See Also

- [ObfuscatedString Documentation](../ObfuscatedString.md)
- [ObfuscatedString.hpp](../../include/Sentinel/Core/ObfuscatedString.hpp)
- [Unit Tests](../../tests/Core/test_obfuscated_string.cpp)
