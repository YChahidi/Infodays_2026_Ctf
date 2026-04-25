#!/usr/bin/python3
import socket
import re

def xor(a, b):
    return bytearray(x ^ y for x, y in zip(a, b))

class PaddingOracle:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.connect()
    
    def connect(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.host, self.port))
        self.data = b""
        while b"ENTER YOUR CHALLENGE" not in self.data and b">" not in self.data:
            self.data += self.s.recv(4096)
        self.data = self.data.decode()
        
        match = re.search(r'🔒 ([a-f0-9]+)', self.data)
        if match:
            self.full_ciphertext_hex = match.group(1)
        else:
            raise Exception("Could not find ciphertext")
        
        print(f"[+] Connected to VAR system")
        print(f"[+] Full data (IV + ciphertext): {self.full_ciphertext_hex[:64]}...")
    
    def decrypt(self, ciphertext):
        self.s.send(ciphertext.hex().encode() + b'\n')
        response = self.s.recv(1024).decode()
        
        if "GOAL" in response and "OFFSIDE" not in response:
            return "Valid"
        else:
            return "Invalid"
    
    def close(self):
        self.s.close()

def attack_block(oracle, previous_block, target_block, block_name):
    print(f"\n[*] Attacking {block_name}")
    D = bytearray(16)
    CC = bytearray(16)
    
    for K in range(1, 17):
        padding_val = K
        byte_pos = 16 - K
        
        for pos in range(byte_pos + 1, 16):
            CC[pos] = D[pos] ^ padding_val
        
        for guess in range(256):
            CC[byte_pos] = guess
            test_ct = previous_block + CC + target_block
            status = oracle.decrypt(test_ct)
            
            if status == "Valid":
                D[byte_pos] = CC[byte_pos] ^ padding_val
                print(f"  Byte {byte_pos:2d}: D = 0x{D[byte_pos]:02x}")
                break
        else:
            print(f"  ERROR at byte {byte_pos}")
            return None
    
    return D

def main():
    print("\n" + "="*50)
    print("⚽ PENALTY SHOOTOUT SOLVER - VAR HACKER ⚽")
    print("="*50 + "\n")
    
    oracle = PaddingOracle('localhost', 4444)
    
    # The full data is IV + C1 + C2 + C3 + ...
    full_data = bytes.fromhex(oracle.full_ciphertext_hex)
    
    IV = full_data[0:16]
    print(f"\n[*] Recovered IV: {IV.hex()}")
    
    # The rest are ciphertext blocks
    ciphertext_blocks = []
    for i in range(16, len(full_data), 16):
        ciphertext_blocks.append(full_data[i:i+16])
    
    num_blocks = len(ciphertext_blocks)
    print(f"[*] Number of ciphertext blocks: {num_blocks}")
    
    for i, block in enumerate(ciphertext_blocks):
        print(f"C{i+1}: {block.hex()}")
    
    # Attack from last block to first
    D_blocks = []
    P_blocks = []
    
    for i in range(num_blocks - 1, -1, -1):
        if i == 0:
            previous = IV
            print(f"\n[*] Attacking Block {i+1} (C{i+1}) using IV as previous")
        else:
            previous = ciphertext_blocks[i-1]
            print(f"\n[*] Attacking Block {i+1} (C{i+1}) using C{i} as previous")
        
        D = attack_block(oracle, previous, ciphertext_blocks[i], f"Block {i+1}")
        if D:
            D_blocks.insert(0, D)
            P = xor(previous, D)
            P_blocks.insert(0, P)
            print(f"P{i+1}: {P.hex()}")
    
    if P_blocks:
        full = b''.join(P_blocks)
        padding_len = full[-1]
        
        print("\n" + "="*50)
        print(f"Full decrypted (with padding): {full.hex()}")
        print(f"Padding length: {padding_len} bytes")
        
        if 1 <= padding_len <= 16:
            flag = full[:-padding_len]
            print(f"\n🏆 FLAG FOUND! 🏆")
            print(f"Hex: {flag.hex()}")
            print(f"Flag: {flag.decode()}")
        else:
            print(f"\n[-] Invalid padding length: {padding_len}")
    
    oracle.close()

if __name__ == "__main__":
    main()
