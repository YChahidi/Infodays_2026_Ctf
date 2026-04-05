# var_review - Hard Mode

## Challenge Description
VAR Review System with format string vulnerability but FULL mitigations:
- PIE enabled
- Stack canary
- Full RELRO
- Flag on HEAP (not stack)

## Solution Steps

1. **Find format string offset** - Brute force %p offsets
2. **Leak heap addresses** - Find where flag pointer is stored
3. **Calculate flag location** - Flag is on heap
4. **Use %s to read flag** - With correct heap address

## Mitigations Bypassed
- PIE: Leaked addresses give base
- Canary: Format string can read it but not needed
- RELRO: Not relevant for format string
- Heap flag: Need to leak pointer first

## Flag
`INFODAYS{FORMAT_STR1NG_H4RD_M0DE_2026}`
