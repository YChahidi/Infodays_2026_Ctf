#!/usr/bin/python3
import socket
import re

def test_connection():
    print("[*] Connecting to localhost:4444...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('localhost', 4444))
    
    # Receive banner
    data = s.recv(4096).decode()
    print("[*] Received banner")
    
    # Extract ciphertext
    match = re.search(r'🔒 ([a-f0-9]+)', data)
    if match:
        ciphertext = match.group(1)
        print(f"[+] Ciphertext: {ciphertext[:64]}...")
    else:
        print("[-] Could not find ciphertext")
        s.close()
        return
    
    # Test 1: Send original ciphertext
    print("\n[*] Test 1: Sending original ciphertext...")
    s.send(ciphertext.encode() + b'\n')
    response = s.recv(1024).decode()
    print(f"[+] Response: {response.strip()}")
    
    # Reconnect for next test
    s.close()
    
    # Test 2: Send invalid ciphertext
    print("\n[*] Test 2: Sending invalid ciphertext...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('localhost', 4444))
    s.recv(4096)  # consume banner
    
    invalid = "00" * 32
    s.send(invalid.encode() + b'\n')
    response = s.recv(1024).decode()
    print(f"[+] Response: {response.strip()}")
    
    s.close()
    print("\n[✓] Tests complete!")

if __name__ == "__main__":
    test_connection()
