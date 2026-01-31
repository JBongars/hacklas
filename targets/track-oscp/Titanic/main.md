# Titanic

- **Author:** Julien Bongars
- **Date:** 2026-01-31 08:44:15
- **Path:** /home/julien/.hacklas/./targets/track-oscp/Titanic

---

link = https://app.hackthebox.com/machines/Titanic
ip =

# Port scanning

**rustscan**

```bash
rustscan -a "$IP_ADDRESS" -ulimit 5000 -- -sC -sV -oA "/home/julien/.hacklas/./targets/track-oscp/Titanic/nmap/quick"
```

**nmap**

```bash
nmap -sC -sV -p- -oA "/home/julien/.hacklas/./targets/track-oscp/Titanic/nmap/full" "$IP_ADDRESS"
```

# Enumeration

# Creds

-

# References

-
