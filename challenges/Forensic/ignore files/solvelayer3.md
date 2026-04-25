# Wi-Fi Forensics CTF Challenge — Full Code + Solve Writeup

## Full Generator Code


---

## Solve Writeup

## Step 1 — Open PCAP

Open in Wireshark:

```bash
wireshark layer1_cracking.pcap
```

---

## Step 2 — Find the Real AP

Filter beacon frames:

```text
wlan.fc.type_subtype == 8
```

You will see many SSIDs.

The real suspicious AP is:

```text
CorpNet_Internal
```

BSSID:

```text
00:14:22:01:23:45
```

Extract string part:

```text
CorpNet
```

---

## Step 3 — Find the Real Client

Filter:

```text
eapol
```

Find the client that completes the handshake with the suspicious AP.

Real client:

```text
AA:BB:CC:11:22:33
```

Ignore fake incomplete handshakes.

---

## Step 4 — Read Hidden Hint

Search packet payloads:

```text
frame contains "Repeated values"
```

You will find the memo telling you:

* repeated values are not always truth
* trust the client that completes the exchange
* ignore isolated debug artifacts

This tells you fake FLAG_PART packets are traps.

---

## Step 5 — Recover Numeric Fragments

Search only packets involving:

* real AP
* real client

### First value

```text
frame contains "Session-ID"
```

Result:

```text
Session-ID: XJ-48
```

First part:

```text
48
```

---

### Second value

```text
frame contains "AuthToken"
```

Result:

```text
AuthToken: 29
```

Second part:

```text
29
```

---

### Third value

```text
frame contains "Reference-ID"
```

Result:

```text
Reference-ID: 1
```

Third part:

```text
1
```

---

## Step 6 — Rebuild Final Flag

String part:

```text
CorpNet
```

Number part:

```text
48 + 29 + 1 = 48291
```

Final flag:

```text
CTF{CorpNet_48291}
```
