# dns-dnsenum

**Author:** Julien Bongars\
**Date:** 2025-12-14 23:47:52
**Path:**

---

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

| Flag            | Purpose                                                             |
| --------------- | ------------------------------------------------------------------- |
| `--enum`        | Shortcut enabling enumeration options                               |
| `-f <wordlist>` | Path to subdomain wordlist                                          |
| `-r`            | Enable recursive brute-forcing (enumerate subdomains of subdomains) |

### Sample Output

```
inlanefreight.com.         300  IN  A  134.209.24.248
www.inlanefreight.com.     300  IN  A  134.209.24.248
support.inlanefreight.com. 300  IN  A  134.209.24.248
```

# Appendix

## Aleternative Tools

| Tool            | Description                                                       |
| --------------- | ----------------------------------------------------------------- |
| **dnsenum**     | Comprehensive DNS enumeration with dictionary/brute-force support |
| **fierce**      | User-friendly recursive discovery with wildcard detection         |
| **dnsrecon**    | Versatile tool with multiple techniques and custom output formats |
| **amass**       | Actively maintained, integrates with many data sources            |
| **assetfinder** | Lightweight and fast subdomain finder                             |
| **puredns**     | Powerful brute-forcing with effective filtering                   |
