# SHANKS — Solve Writeup (Insane)

## Overview
Heap exploitation challenge: a pirate crew roster manager with three bugs:
1. **Use-After-Free** in inspect (slot pointer not NULLed immediately)
2. **Heap overflow** in promote (reads 0x100 into 0x58-byte title buffer)
3. **Double-free** via lazy slot clearing (dismiss same slot twice before menu cycle)

## Vulnerabilities

### Bug 1: UAF in dismiss/inspect
`op_dismiss()` calls `free(roster[i])` but sets `dismissed[i] = 1` instead of
`roster[i] = NULL`. The pointer is only NULLed in `lazy_clear()` which runs at the
top of the next menu loop. If you call inspect before the menu reprints, you read freed memory.

### Bug 2: Heap overflow in promote
```c
ssize_t got = read(0, roster[i]->title, 0x100);  // title is only 0x58 bytes!
```
Writing 0x100 bytes overflows past title into `on_inspect` (function pointer at
offset 0x98), `bounty`, and `bio` pointer — and potentially into the next heap chunk.

### Bug 3: Double-free
Same lazy-clear issue. Dismiss slot X, then immediately dismiss slot X again (before
`lazy_clear` runs) → double-free → tcache dup.

## Exploitation Chain

### Path A: Function pointer overwrite (easiest)
1. Recruit slots 0 and 1 so their Crew structs are adjacent on the heap
2. Use promote on slot 0 with 0x100 bytes of carefully crafted data
3. The overflow from slot 0's title smashes into slot 0's own `on_inspect`
   pointer at offset 0x98
4. Overwrite `on_inspect` with address of `shanks_verdict()`
5. Inspect slot 0 → calls `shanks_verdict()` → prints flag

**Challenge**: PIE is enabled, so you need a leak first.

### Path B: Full chain (UAF leak + overflow)
1. Recruit 8 slots, dismiss 7 to fill tcache, dismiss one more → unsorted bin
2. UAF-inspect the unsorted-bin chunk → leaks libc `main_arena` fd pointer
3. Calculate libc base, find `shanks_verdict` offset via binary leak
4. Promote overflow to overwrite `on_inspect` → `shanks_verdict`
5. Inspect → flag

### Getting shanks_verdict address
```bash
# After leaking PIE base:
nm shanks | grep verdict   # won't work (stripped)
# Use the leak + known offset from local binary analysis
objdump -d shanks | grep -A5 "flag.txt"
```

## Flag
```
INFODAYS{SaamNoLimits_i_bet_my_arm_on_the_new_era_<random_hex>}
```
