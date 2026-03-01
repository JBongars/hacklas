# 13.4

- **Author:** Julien Bongars
- **Date:** 2026-02-28 13:56:15
- **Path:** /home/julien/.hacklas/targets/treck-pen-200/13.4

---

ip = 192.168.121.188

# Port scanning

**rustscan**

```bash
rustscan -a "$IP_ADDRESS" -ulimit 5000 -- -sC -sV -oA "/home/julien/.hacklas/targets/treck-pen-200/13.4/nmap/quick"
```

**nmap**

```bash
nmap -sC -sV -p- -oA "/home/julien/.hacklas/targets/treck-pen-200/13.4/nmap/full" "$IP_ADDRESS"
```

# Enumeration

# Creds

-

# References

-
