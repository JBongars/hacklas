# Astronaut

- **Author:** Julien Bongars
- **Date:** 2026-02-28 13:49:06
- **Path:** /home/julien/.hacklas/targets/track-tjnull/Astronaut

---

link = https://app.hackthebox.com/machines/Astronaut
ip =

# Description

An Unauthenticated Arbitrary YAML Write/Update vulnerability in Grav CMS will be exploited to gain an initial foothold, leading to remote code execution (RCE). Privilege escalation will be achieved by identifying a vulnerable PHP SUID binary. This lab focuses on exploiting vulnerabilities and privilege escalation methods.

# Port scanning

**rustscan**

```bash
rustscan -a "$IP_ADDRESS" -ulimit 5000 -- -sC -sV -oA "/home/julien/.hacklas/targets/track-tjnull/Astronaut/nmap/quick"
```

**nmap**

```bash
nmap -sC -sV -p- -oA "/home/julien/.hacklas/targets/track-tjnull/Astronaut/nmap/full" "$IP_ADDRESS"
```

# Enumeration

# Creds

-

# References

-
