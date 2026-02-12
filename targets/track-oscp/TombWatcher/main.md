# TombWatcher

- **Author:** Julien Bongars
- **Date:** 2026-02-09 17:29:10
- **Path:** /home/julien/.hacklas/./targets/track-oscp/TombWatcher

---

link = https://app.hackthebox.com/machines/TombWatcher
ip =

# Port scanning

**rustscan**

```bash
rustscan -a "$IP_ADDRESS" -ulimit 5000 -- -sC -sV -oA "/home/julien/.hacklas/./targets/track-oscp/TombWatcher/nmap/quick"
```

**nmap**

```bash
nmap -sC -sV -p- -oA "/home/julien/.hacklas/./targets/track-oscp/TombWatcher/nmap/full" "$IP_ADDRESS"
```

# Enumeration

# Creds

-

# References

-
