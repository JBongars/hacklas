# hashcat

**Author:** Julien Bongars\
**Date:** 2025-11-05 14:29:11
**Path:**

---

## Hashcat Quick Start

```bash
# hashcat --help to get the code for m
echo "hash" > hash.txt
hashcat -m 1400 hash.txt /usr/share/wordlists/rockyou.txt
```
