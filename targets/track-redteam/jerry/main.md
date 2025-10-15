link = https://app.hackthebox.com/machines/144

# Port Scanning

**rustscan**

```bash
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
TCP handshake? More like a friendly high-five!

[~] The config file is expected to be at "/home/julien23/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.129.114.148:8080
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -Pn -oN rustscan.txt -sV --script vuln" on ip 10.129.114.148
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-10-15 10:33 CDT
NSE: Loaded 150 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 10:33
Completed NSE at 10:33, 10.00s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 10:33
Completed NSE at 10:33, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 10:33
Completed Parallel DNS resolution of 1 host. at 10:33, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 10:33
Scanning 10.129.114.148 [1 port]
Discovered open port 8080/tcp on 10.129.114.148
Completed SYN Stealth Scan at 10:33, 0.11s elapsed (1 total ports)
Initiating Service scan at 10:33
Scanning 1 service on 10.129.114.148
Completed Service scan at 10:33, 9.04s elapsed (1 service on 1 host)
NSE: Script scanning 10.129.114.148.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 10:33
NSE Timing: About 96.64% done; ETC: 10:34 (0:00:01 remaining)
NSE Timing: About 99.33% done; ETC: 10:34 (0:00:00 remaining)
NSE Timing: About 99.33% done; ETC: 10:35 (0:00:01 remaining)
NSE Timing: About 99.33% done; ETC: 10:35 (0:00:01 remaining)
NSE Timing: About 99.33% done; ETC: 10:36 (0:00:01 remaining)
NSE Timing: About 99.33% done; ETC: 10:36 (0:00:01 remaining)
NSE Timing: About 99.33% done; ETC: 10:37 (0:00:01 remaining)
Completed NSE at 10:37, 228.50s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 10:37
Completed NSE at 10:37, 0.45s elapsed
Nmap scan report for 10.129.114.148
Host is up, received user-set (0.081s latency).
Scanned at 2025-10-15 10:33:47 CDT for 238s

PORT     STATE SERVICE REASON          VERSION
8080/tcp open  http    syn-ack ttl 127 Apache Tomcat/Coyote JSP engine 1.1
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
|_http-server-header: Apache-Coyote/1.1
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /examples/: Sample scripts
|   /manager/html/upload: Apache Tomcat (401 Unauthorized)
|   /manager/html: Apache Tomcat (401 Unauthorized)
|_  /docs/: Potentially interesting folder

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 10:37
Completed NSE at 10:37, 0.00s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 10:37
Completed NSE at 10:37, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 248.42 seconds
           Raw packets sent: 1 (44B) | Rcvd: 2 (128B)

```



# 
