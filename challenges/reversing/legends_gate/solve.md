# Legends Gate - Complete Solution Guide

## 📝 Challenge Description
The VIP entrance to the ENSA Agadir stadium is controlled by a custom binary. We know it's dedicated to Las Leyendas, but the code is hardened against standard debugging. Can you bypass the security and prove you are a true Legend?

## 🕵️ Step 1: Initial Reconnaissance
First, we check the properties of the provided file to understand its architecture.

**Command:**
```bash
file legend_gate_pro
```

**Finding:** The output confirms it is a stripped ELF 64-bit binary.

**Significance:** Stripping removes the symbol table (function names). We cannot simply search for a function named main or check_password.

## 🛡️ Step 2: The Anti-Debug Trap
Attempting to run the program in a debugger like GDB or GEF triggers an immediate exit, preventing dynamic analysis.

**Command:**
```bash
gdb ./legend_gate_pro
(gdb) run
```

**Observation:** The program exits instantly with "Debugger detected! Access Denied."

**Technical Reason:** The binary uses a ptrace(PTRACE_TRACEME, ...) check. Since GDB is already "tracing" the process, this call fails, revealing that the program is being analyzed.

---

# METHOD 1: STATIC DECRYPTION (FIND PASSWORD FIRST)

## 🏗️ Step 3: Static Analysis with Ghidra
Since dynamic analysis is blocked, we use Ghidra to decompile the machine code.

**Navigate to Entry:** In the Symbol Tree, we go to the entry function.

**Find Main:** Inside entry, we locate the call to __libc_start_main. The first argument is the address of our real main function (renamed by Ghidra to FUN_001010c0).

**Analyze Logic:** Inside this function, we find an array of 13 hex bytes and a comparison loop.

## 🔢 Step 4: Cracking the XOR
The decompiled code reveals that each character of our input is XORed with 0x22 and compared against a hardcoded array.

**The Encrypted Bytes:**
```
0x6e, 0x16, 0x17, 0x7d, 0x6e, 0x11, 0x5b, 0x11, 0x4c, 0x46, 0x16, 0x17, 0x03
```

**The Recovery Script (Python):**
```python
secret = [0x6e, 0x16, 0x17, 0x7d, 0x6e, 0x11, 0x5b, 0x11, 0x4c, 0x46, 0x16, 0x17, 0x03]
print("".join([chr(b ^ 0x22) for b in secret]))
```

**Result:** L45_L3y3nd45!

## 🔍 Step 5: Getting the Flag (Method 1A - Run Binary)
Running the program normally with the recovered password:

**Command:**
```bash
echo "L45_L3y3nd45!" | ./legend_gate_pro
```

**Output:**
```
--- ENSA Agadir: Legendary Access ---
Code: [+] Legend Verified! Flag: INFODAYS{RE_15_NOT_GU3551NG_2026}
```

---

# METHOD 2: DIRECT FLAG EXTRACTION (DECRYPT FROM GHIDRA)

## 🔍 Step 3: Extract Encrypted Flag from Ghidra
Instead of finding the password first, we can extract the encrypted flag directly from Ghidra's decompiled code.

Looking at the success function in Ghidra, we find the encrypted flag data:

**Encrypted Flag Blocks (from Ghidra):**
```
local_a8 = 0x717b63666d646c6b
uStack_a0 = 0x6c7d17137d677059
local_98 = 0x17171177657d766d
uStack_90 = 0x141012107d656c13
```

## 🔢 Step 4: Decrypt the Flag Directly
Because x86_64 is Little-Endian, these 8-byte hex blocks must be read in reverse order (right-to-left) to get the correct byte sequence.

**Decryption Script:**
```python
# XOR key found in the binary
KEY = 0x22

# Extracted bytes after accounting for Little-Endian reversal
encrypted_flag = [
    # From local_a8 = 0x717b63666d646c6b
    0x6b, 0x6c, 0x64, 0x6d, 0x66, 0x63, 0x7b, 0x71,
    # From uStack_a0 = 0x6c7d17137d677059
    0x59, 0x70, 0x67, 0x7d, 0x13, 0x17, 0x7d, 0x6c,
    # From local_98 = 0x17171177657d766d
    0x6d, 0x76, 0x7d, 0x65, 0x77, 0x11, 0x17, 0x17,
    # From uStack_90 = 0x141012107d656c13
    0x13, 0x6c, 0x65, 0x7d, 0x10, 0x12, 0x10, 0x14,
]

# Decrypt with XOR 0x22
flag = "".join([chr(b ^ KEY) for b in encrypted_flag])
print(f"Flag: {flag}")
```

**Result:** INFODAYS{RE_15_NOT_GU3551NG_2026}

## 📊 Manual XOR Verification
We can also verify byte by byte:

| Encrypted | XOR 0x22 | ASCII | Character |
|-----------|----------|-------|-----------|
| 0x6b | 0x49 | 73 | I |
| 0x6c | 0x4e | 78 | N |
| 0x64 | 0x46 | 70 | F |
| 0x6d | 0x4f | 79 | O |
| 0x66 | 0x44 | 68 | D |
| 0x63 | 0x41 | 65 | A |
| 0x7b | 0x59 | 89 | Y |
| 0x71 | 0x53 | 83 | S |
| 0x59 | 0x7b | 123 | { |
| 0x70 | 0x52 | 82 | R |
| 0x67 | 0x45 | 69 | E |
| 0x7d | 0x5f | 95 | _ |
| 0x13 | 0x31 | 49 | 1 |
| 0x17 | 0x35 | 53 | 5 |
| 0x7d | 0x5f | 95 | _ |
| 0x6c | 0x4e | 78 | N |
| 0x6d | 0x4f | 79 | O |
| 0x76 | 0x54 | 84 | T |
| 0x7d | 0x5f | 95 | _ |
| 0x65 | 0x47 | 71 | G |
| 0x77 | 0x55 | 85 | U |
| 0x11 | 0x33 | 51 | 3 |
| 0x17 | 0x35 | 53 | 5 |
| 0x17 | 0x35 | 53 | 5 |
| 0x13 | 0x31 | 49 | 1 |
| 0x6c | 0x4e | 78 | N |
| 0x65 | 0x47 | 71 | G |
| 0x7d | 0x5f | 95 | _ |
| 0x10 | 0x32 | 50 | 2 |
| 0x12 | 0x30 | 48 | 0 |
| 0x10 | 0x32 | 50 | 2 |
| 0x14 | 0x36 | 54 | 6 |
| 0x5f | 0x7d | 125 | } |

**Result:** INFODAYS{RE_15_NOT_GU3551NG_2026}

---

## 📊 Solution Summary

| Item | Value |
|------|-------|
| **Password** | `L45_L3y3nd45!` |
| **Flag** | `INFODAYS{RE_15_NOT_GU3551NG_2026}` |
| **XOR Key** | `0x22` |
| **Anti-Debug** | `ptrace(PTRACE_TRACEME)` |

## 🎯 Key Takeaways
- **XOR Encryption:** The binary uses XOR with key 0x22 to encrypt both the password and flag
- **Two Solution Methods:** 
  - **Method 1:** Decrypt password (L45_L3y3nd45!) then run binary to get flag
  - **Method 2:** Extract encrypted flag directly from Ghidra and decrypt with XOR 0x22
- **Anti-Debugging:** ptrace check prevents simple debugger attachment, but Ghidra static analysis bypasses this
- **Endianness:** When reading large hex values from Ghidra's stack, remember to reverse the bytes for Little-Endian systems

**Final Flag:** `INFODAYS{RE_15_NOT_GU3551NG_2026}`
