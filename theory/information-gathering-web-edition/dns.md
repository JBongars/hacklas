# DNS Summary

DNS (Domain Name System) translates human-readable domain names (e.g., `www.example.com`) into IP addresses (e.g., `192.0.2.1`) that computers use to communicate.

---

## How DNS Works

1. **DNS Query** — Your computer checks its cache, then asks a DNS resolver (usually your ISP)
2. **Recursive Lookup** — Resolver queries the DNS hierarchy: Root → TLD → Authoritative server
3. **Response** — The authoritative server returns the IP address, which is cached and sent to your computer

---

## The Hosts File

A local file that manually maps hostnames to IPs, bypassing DNS.

| OS | Location |
|----|----------|
| Windows | `C:\Windows\System32\drivers\etc\hosts` |
| Linux/macOS | `/etc/hosts` |

```txt
127.0.0.1       localhost
127.0.0.1       myapp.local        # Local dev
0.0.0.0         unwanted-site.com  # Block site
```

---

## Key Concepts

| Concept | Description |
|---------|-------------|
| Zone | A managed portion of the domain namespace (e.g., `example.com` + subdomains) |
| Zone File | Text file defining DNS records for a zone |
| DNS Resolver | Server that translates domains to IPs (e.g., `8.8.8.8`) |
| Root Server | Top-level DNS servers (13 worldwide, A-M) |
| TLD Server | Manages top-level domains (`.com`, `.org`, etc.) |
| Authoritative Server | Holds the actual IP for a domain |

---

## DNS Record Types

| Type | Name | Purpose | Example |
|------|------|---------|---------|
| A | Address | IPv4 mapping | `www.example.com. IN A 192.0.2.1` |
| AAAA | IPv6 Address | IPv6 mapping | `www.example.com. IN AAAA 2001:db8::1` |
| CNAME | Canonical Name | Alias to another hostname | `blog.example.com. IN CNAME webserver.example.net.` |
| MX | Mail Exchange | Mail server for domain | `example.com. IN MX 10 mail.example.com.` |
| NS | Name Server | Authoritative DNS server | `example.com. IN NS ns1.example.com.` |
| TXT | Text | Arbitrary text (SPF, verification) | `example.com. IN TXT "v=spf1 mx -all"` |
| SOA | Start of Authority | Zone admin info | Primary NS, email, serial, timers |
| SRV | Service | Service hostname + port | `_sip._udp.example.com. IN SRV 10 5 5060 sipserver.example.com.` |
| PTR | Pointer | Reverse DNS (IP → hostname) | `1.2.0.192.in-addr.arpa. IN PTR www.example.com.` |

> **Note:** "IN" = Internet class (standard for modern DNS)

---

## Why DNS Matters for Recon

- **Uncover Assets** — Find subdomains, mail servers, outdated systems
- **Map Infrastructure** — Identify hosting providers, load balancers, network topology
- **Monitor Changes** — Detect new subdomains (`vpn.example.com`), service indicators in TXT records

---

## DNS Tools

| Tool | Purpose | Use Case |
|------|---------|----------|
| `dig` | Versatile DNS queries, detailed output | Manual queries, zone transfers, troubleshooting |
| `nslookup` | Simple DNS lookups | Quick A, AAAA, MX checks |
| `host` | Streamlined lookups | Fast record checks |
| `dnsenum` | Automated enumeration, brute-forcing | Subdomain discovery |
| `fierce` | Recursive subdomain enumeration | Finding subdomains, wildcard detection |
| `dnsrecon` | Comprehensive DNS recon | Full enumeration with multiple techniques |
| `theHarvester` | OSINT gathering | Emails, employee info from DNS + other sources |

### Common Commands

```bash
# Basic lookup
dig example.com

# Specific record types
dig example.com MX
dig example.com NS
dig example.com TXT
dig example.com ANY

# Reverse lookup
dig -x 192.0.2.1

# Using nslookup
nslookup example.com
nslookup -type=MX example.com

# Using host
host example.com
host -t MX example.com

# Subdomain enumeration
dnsenum example.com
fierce --domain example.com
dnsrecon -d example.com -t std
```

# Enumeration

An active discovery technique that systematically tests potential subdomain names against a target domain using wordlists.

---

## The Process

1. **Wordlist Selection** — Choose a list of potential subdomain names
2. **Iteration & Querying** — Append each word to the target domain (e.g., `dev.example.com`)
3. **DNS Lookup** — Query each potential subdomain for A/AAAA records
4. **Filtering & Validation** — Confirm valid subdomains resolve and are functional

---

## Wordlist Types

| Type | Description | Best For |
|------|-------------|----------|
| General-Purpose | Common names (dev, staging, admin, mail, test) | Unknown target structure |
| Targeted | Industry/technology-specific patterns | Known target context |
| Custom | Built from gathered intelligence | Refined engagements |

---

## Popular Tools

| Tool | Description |
|------|-------------|
| **dnsenum** | Comprehensive DNS enumeration with dictionary/brute-force support |
| **fierce** | User-friendly recursive discovery with wildcard detection |
| **dnsrecon** | Versatile tool with multiple techniques and custom output formats |
| **amass** | Actively maintained, integrates with many data sources |
| **assetfinder** | Lightweight and fast subdomain finder |
| **puredns** | Powerful brute-forcing with effective filtering |

---

## DNSenum Deep Dive

A Perl-based command-line tool offering comprehensive DNS reconnaissance:

- **DNS Record Enumeration** — Retrieves A, AAAA, NS, MX, TXT records
- **Zone Transfer Attempts** — Automatically tries AXFR on discovered name servers
- **Subdomain Brute-Forcing** — Tests wordlist entries against target
- **Google Scraping** — Finds additional subdomains via search results
- **Reverse Lookup** — Identifies domains sharing an IP address
- **WHOIS Lookups** — Gathers domain ownership info

### Example Command

```bash
dnsenum --enum inlanefreight.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -r
```

| Flag | Purpose |
|------|---------|
| `--enum` | Shortcut enabling enumeration options |
| `-f <wordlist>` | Path to subdomain wordlist |
| `-r` | Enable recursive brute-forcing (enumerate subdomains of subdomains) |

### Sample Output

```
inlanefreight.com.         300  IN  A  134.209.24.248
www.inlanefreight.com.     300  IN  A  134.209.24.248
support.inlanefreight.com. 300  IN  A  134.209.24.248
```

# Zone Transfer Request (AXFR)

A potentially efficient method for uncovering subdomains by exploiting misconfigured DNS servers.

A wholesale copy of all DNS records within a zone (domain + subdomains) from one name server to another. Designed for maintaining consistency between DNS servers, but can expose sensitive data if misconfigured.

---

## How It Works

1. **AXFR Request** — Secondary server sends a full zone transfer request to the primary server
2. **SOA Record Transfer** — Primary responds with Start of Authority record (contains zone serial number)
3. **DNS Records Transmission** — All records (A, AAAA, MX, CNAME, NS, etc.) are transferred one by one
4. **Transfer Complete** — Primary signals end of transfer
5. **Acknowledgement** — Secondary confirms successful receipt

---

## The Vulnerability

Misconfigured servers may allow *anyone* to request a zone transfer, exposing:

| Exposed Data | Risk |
|--------------|------|
| **Subdomains** | Reveals hidden dev servers, staging environments, admin panels |
| **IP Addresses** | Provides targets for further attacks |
| **Name Server Records** | Exposes hosting provider and potential misconfigurations |

> Early internet practice allowed open zone transfers. Modern servers restrict transfers to trusted secondary servers only — but misconfigurations still occur.

---

## Exploiting Zone Transfers

Use `dig` to attempt a zone transfer:

```bash
dig axfr @nsztm1.digi.ninja zonetransfer.me
```

| Component | Description |
|-----------|-------------|
| `dig` | DNS lookup utility |
| `axfr` | Request type — Asynchronous Full Transfer (complete zone copy) |
| `@nsztm1.digi.ninja` | Target DNS server to query (the `@` specifies which server) |
| `zonetransfer.me` | Domain to request zone data for |

### Successful Output Example

```
zonetransfer.me.           7200  IN  SOA   nsztm1.digi.ninja. robin.digi.ninja. ...
zonetransfer.me.           7200  IN  A     5.196.105.14
zonetransfer.me.           7200  IN  NS    nsztm1.digi.ninja.
zonetransfer.me.           7200  IN  NS    nsztm2.digi.ninja.
zonetransfer.me.           7200  IN  MX    0 ASPMX.L.GOOGLE.COM.
canberra-office.zonetransfer.me. 7200 IN A 202.14.81.230
asfdbbox.zonetransfer.me.  7200  IN  A     127.0.0.1
...
;; XFR size: 50 records (messages 1, bytes 2085)
```

> **Note:** `zonetransfer.me` is intentionally configured to allow transfers for demonstration purposes.

---

## Key Takeaways

- Zone transfers are a legitimate DNS replication mechanism
- Misconfiguration can expose complete DNS infrastructure
- Always attempt with proper authorization during assessments
- Even failed attempts reveal info about server security posture
