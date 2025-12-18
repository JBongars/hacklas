# Web Reconnaissance: Summary

Web reconnaissance is divided into two main methodologies: **active** and **passive**.

---

## Active Reconnaissance

Involves direct interaction with the target system. Provides comprehensive information but carries higher detection risk.

### Port Scanning
Identify open ports and services running on the target.

**Tools:** Nmap, Masscan, Unicornscan

```bash
# Basic port scan
nmap -p 80,443 target.com

# Scan all ports
nmap -p- target.com

# Fast scan with Masscan
masscan -p1-65535 target.com --rate=1000
```

### Vulnerability Scanning
Probe the target for known vulnerabilities like SQLi or XSS.

**Tools:** Nessus, OpenVAS, Nikto

```bash
# Web server vulnerability scan with Nikto
nikto -h https://target.com
```

### Network Mapping
Map the target's network topology and infrastructure.

**Tools:** Traceroute, Nmap

```bash
# Trace network path
traceroute target.com

# Network discovery
nmap -sn 192.168.1.0/24
```

### Banner Grabbing
Retrieve information from service banners.

**Tools:** Netcat, curl

```bash
# Grab HTTP banner with curl
curl -I https://target.com

# Banner grab with Netcat
nc -v target.com 80
```

### OS Fingerprinting
Identify the operating system running on the target.

**Tools:** Nmap, Xprobe2

```bash
# OS detection with Nmap
nmap -O target.com
```

### Service Enumeration
Determine specific versions of services on open ports.

**Tools:** Nmap

```bash
# Service version detection
nmap -sV target.com

# Aggressive scan (OS, version, scripts, traceroute)
nmap -A target.com
```

### Web Spidering
Crawl websites to discover pages, directories, and files.

**Tools:** Burp Suite Spider, OWASP ZAP, Scrapy

```bash
# Simple crawl with wget
wget --spider --recursive --level=2 https://target.com
```

---

## Passive Reconnaissance

Gathers information without direct interaction, relying on publicly available data. Stealthier but may yield less comprehensive results.

### Search Engine Queries
Uncover information via search engines.

**Tools:** Google, DuckDuckGo, Bing, Shodan

```bash
# Google dorks (run in browser)
# site:target.com filetype:pdf
# "target.com" inurl:admin

# Shodan CLI
shodan search hostname:target.com
```

### WHOIS Lookups
Retrieve domain registration details.

**Tools:** whois, online WHOIS services

```bash
# WHOIS lookup
whois target.com
```

### DNS Analysis
Identify subdomains, mail servers, and infrastructure.

**Tools:** dig, nslookup, host, dnsenum, fierce, dnsrecon

```bash
# Basic DNS lookup
dig target.com

# Get all DNS records
dig target.com ANY

# Find mail servers
dig target.com MX

# Subdomain enumeration
dnsrecon -d target.com -t std
fierce --domain target.com
```

### Web Archive Analysis
Examine historical snapshots of websites.

**Tools:** Wayback Machine

```bash
# Using waybackurls (Go tool)
waybackurls target.com

# Or via curl to Wayback API
curl "https://web.archive.org/cdx/search/cdx?url=target.com/*&output=txt"
```

### Social Media Analysis
Gather info from LinkedIn, Twitter, Facebook, etc.

**Tools:** LinkedIn, Twitter, Facebook, OSINT tools

```bash
# theHarvester for emails and names
theHarvester -d target.com -b linkedin
```

### Code Repositories
Search for exposed credentials or vulnerabilities.

**Tools:** GitHub, GitLab

```bash
# GitHub CLI search
gh search repos target.com

# GitDorker for sensitive info
python3 GitDorker.py -t <token> -d dorks.txt -q target.com
```

---

## Key Takeaway

| Approach | Depth | Stealth | Use Case |
|----------|-------|---------|----------|
| Active | High | Low | Authorized penetration testing |
| Passive | Medium | High | Initial research, OSINT |

Effective reconnaissance typically combines both approaches strategically, starting with passive techniques before moving to active methods.
