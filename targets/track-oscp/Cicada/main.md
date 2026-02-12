# Cicada

- **Author:** Julien Bongars
- **Date:** 2026-02-09 17:34:02
- **Path:** /home/julien/.hacklas/targets/track-oscp/Cicada

---

link = https://app.hackthebox.com/machines/Cicada
ip =

# Port scanning

**rustscan**

```bash
rustscan -a "$IP_ADDRESS" -ulimit 5000 -- -sC -sV -oA "/home/julien/.hacklas/targets/track-oscp/Cicada/nmap/quick"
```

**nmap**

```bash
nmap -sC -sV -p- -oA "/home/julien/.hacklas/targets/track-oscp/Cicada/nmap/full" "$IP_ADDRESS"
```

# Enumeration

# Creds

-

# References

-
