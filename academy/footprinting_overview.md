# footprinting_overview

**Author:** Julien Bongars\
**Date:** 2026-02-18 23:22:36
**Path:**

---

## Enumeration Methodology

**Tiers of enumeration**
![](.media/20260219002222.png)

**Exploiting tiers of enumeration**
![](.media/20260219002232.png)

### Infra Enumeration

I guess in short, you want to find all possible footholds using OSINT. Get domains, possible subdomains using the DNS records. Possible

#### Internet Presence

- Domains
- Subdomains
- vHosts
- ASN

> ASN (Autonomous System Number): An identifier for a network block owned by an organization. Look up a company's ASN and you find all IP ranges they own. Tools: whois, bgp.he.net, asnlookup

- Netblocks

> Netblocks: The actual IP ranges (CIDR blocks) registered to that ASN. E.g., company owns 203.0.113.0/24

- IP Addresses
- Cloud Instances

> Cloud Instances: S3 buckets, Azure blobs, EC2 instances, etc. that belong to the target. Tools: cloud_enum, grayhatwarfare

- Security Measures

Security Measures: At this layer it's mostly passive detection—do they use Cloudflare? Is there a WAF? Check HTTP headers, DNS records, certificate transparency logs

#### Gateway

- Firewalls
- DMZ
- IPS/IDS
- EDR
- Proxios
- NAC
- Network Segmentation
- VPN
- Cloudflare

> For HTB maybe the following:-
>
> - IP Address
> - Vhost (Referrer Header)
> - Open ports (0.0.0.0)

### Host Based Enumeration

#### Accessible Services

- Service Type
- Functionality
- Configuration
- Port
- Version
- Interface

#### Processes

- PiD
- Prossesed Data
- Tasks
- Source
- Destination

### OS Based Enumeration

#### Privelege

- Groups
- Users
- Permissions
- Restrictions
- Environment

#### OS Setup

- OS Type
- Patch Level
- Network Config
- OS Environment
- Configuration Files
- Sensitive Private Files
