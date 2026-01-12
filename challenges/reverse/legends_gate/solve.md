📝 Challenge Description
The VIP entrance to the ENSA Agadir stadium is controlled by a custom binary. We know it’s dedicated to Las Leyendas, but the code is hardened against standard debugging. Can you bypass the security and prove you are a true Legend?

🕵️ Step 1: Initial Reconnaissance
First, we check the properties of the provided file to understand its architecture.

Command: file legend_gate_pro

Finding: The output confirms it is a stripped ELF 64-bit binary.

Significance: Stripping removes the symbol table (function names). We cannot simply search for a function named main or check_password.

🛡️ Step 2: The Anti-Debug Trap
Attempting to run the program in a debugger like GDB or GEF triggers an immediate exit, preventing dynamic analysis.

Command: gdb ./legend_gate_pro -> run

Observation: The program exits instantly with code 01.

Technical Reason: The binary uses a ptrace(PTRACE_TRACEME, ...) check. Since GDB is already "tracing" the process, this call fails, revealing that the program is being analyzed.

🏗️ Step 3: Static Analysis (Ghidra)
Since dynamic analysis is blocked, we use Ghidra to decompile the machine code.

Navigate to Entry: In the Symbol Tree, we go to the entry function.

Find Main: Inside entry, we locate the call to __libc_start_main. The first argument is the address of our real main function (renamed by Ghidra to FUN_001011cd).

Analyze Logic: Inside this function, we find an array of 13 hex bytes and a comparison loop.

🔢 Step 4: Cracking the XOR
The decompiled code reveals that each character of our input is XORed with 0x22 and compared against a hardcoded array.

The Encrypted Bytes: 0x6e, 0x16, 0x17, 0x7d, 0x6e, 0x11, 0x5b, 0x11, 0x4c, 0x46, 0x16, 0x17, 0x03

The Recovery Script (Python):

Python

secret = [0x6e, 0x16, 0x17, 0x7d, 0x6e, 0x11, 0x5b, 0x11, 0x4c, 0x46, 0x16, 0x17, 0x03]
print("".join([chr(b ^ 0x22) for b in secret]))
Result: L45_L3y3nd45!

🏆 Final Execution
Running the program normally with the recovered code:

Input: L45_L3y3nd45!

Flag: INFODAYS{RE_15_NOT_GU3551NG_2026}
