# Certificate Transparency Logs: Summary

## What Are CT Logs?

Certificate Transparency (CT) logs are **public, append-only ledgers** that record the issuance of SSL/TLS certificates. When a Certificate Authority (CA) issues a new certificate, it must submit it to multiple CT logs maintained by independent organizations.

## Why CT Logs Matter

| Purpose | Description |
|---------|-------------|
| Early Detection | Identify rogue or misissued certificates before they're exploited |
| CA Accountability | Hold Certificate Authorities accountable for improper issuance |
| Web PKI Security | Strengthen the public trust infrastructure of the internet |

## CT Logs for Reconnaissance

CT logs offer significant advantages for **subdomain enumeration**:

- Provide a **definitive record** of certificates issued for a domain and its subdomains
- Not limited by wordlists or brute-force effectiveness
- Reveal **historical subdomains**, including old or expired ones
- Can uncover subdomains hosting outdated, potentially vulnerable software

## Tools for Searching CT Logs

| Tool | Best For | Pros | Cons |
|------|----------|------|------|
| **crt.sh** | Quick searches, subdomain discovery | Free, no registration, easy web interface | Limited filtering options |
| **Censys** | In-depth analysis, advanced filtering | Extensive data, API access | Requires registration |

## Example: Finding Subdomains via crt.sh API

```bash
curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[]
 | select(.name_value | contains("dev")) | .name_value' | sort -u
```

**Breakdown:**
- `curl -s` — Fetches JSON output from crt.sh
- `jq -r '... | contains("dev")'` — Filters for entries containing "dev"
- `sort -u` — Sorts and removes duplicates

## Key Takeaway

CT logs provide a reliable, efficient method for discovering subdomains without brute-forcing. They offer a transparent window into a domain's certificate history, often revealing hidden or forgotten subdomains.
