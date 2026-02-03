# LinkVortex
- **Author:** Julien Bongars
- **Date:** 2026-02-04 03:17:32
- **Path:** /home/julien/.hacklas/targets/track-oscp/LinkVortex
---

link = https://app.hackthebox.com/machines/LinkVortex
ip = 

# Port scanning

**rustscan**
```bash
rustscan -a "$IP_ADDRESS" -ulimit 5000 -- -sC -sV -oA "/home/julien/.hacklas/targets/track-oscp/LinkVortex/nmap/quick"
```

**nmap**
```bash
nmap -sC -sV -p- -oA "/home/julien/.hacklas/targets/track-oscp/LinkVortex/nmap/full" "$IP_ADDRESS"
```

# Enumeration

# Creds
- 

# References
- 
