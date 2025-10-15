link = https://app.hackthebox.com/machines/351

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
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/julien23/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.129.89.193:22
Open 10.129.89.193:21
Open 10.129.89.193:80
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -Pn -oN rustscan.txt -sV --script vuln" on ip 10.129.89.193
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-10-15 09:25 CDT
NSE: Loaded 150 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 09:25
Completed NSE at 09:25, 10.00s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 09:25
Completed NSE at 09:25, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 09:25
Completed Parallel DNS resolution of 1 host. at 09:25, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 09:25
Scanning 10.129.89.193 [3 ports]
Discovered open port 22/tcp on 10.129.89.193
Discovered open port 80/tcp on 10.129.89.193
Discovered open port 21/tcp on 10.129.89.193
Completed SYN Stealth Scan at 09:25, 2.10s elapsed (3 total ports)
Initiating Service scan at 09:25
Scanning 3 services on 10.129.89.193
Completed Service scan at 09:27, 116.24s elapsed (3 services on 1 host)
NSE: Script scanning 10.129.89.193.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 09:27
NSE Timing: About 94.95% done; ETC: 09:28 (0:00:02 remaining)
NSE Timing: About 98.74% done; ETC: 09:28 (0:00:01 remaining)
NSE Timing: About 98.99% done; ETC: 09:29 (0:00:01 remaining)
NSE Timing: About 98.99% done; ETC: 09:29 (0:00:01 remaining)
NSE Timing: About 98.99% done; ETC: 09:30 (0:00:02 remaining)
NSE Timing: About 99.24% done; ETC: 09:30 (0:00:01 remaining)
NSE Timing: About 99.24% done; ETC: 09:31 (0:00:02 remaining)
NSE Timing: About 99.24% done; ETC: 09:31 (0:00:02 remaining)
NSE Timing: About 99.24% done; ETC: 09:32 (0:00:02 remaining)
NSE Timing: About 99.24% done; ETC: 09:32 (0:00:02 remaining)
NSE Timing: About 99.24% done; ETC: 09:33 (0:00:03 remaining)
NSE Timing: About 99.24% done; ETC: 09:33 (0:00:03 remaining)
Stats: 0:08:15 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE: Active NSE Script Threads: 3 (3 waiting)
NSE Timing: About 99.24% done; ETC: 09:33 (0:00:03 remaining)
Stats: 0:08:18 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE: Active NSE Script Threads: 3 (3 waiting)
NSE Timing: About 99.24% done; ETC: 09:33 (0:00:03 remaining)
Stats: 0:08:18 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE: Active NSE Script Threads: 3 (3 waiting)
NSE Timing: About 99.24% done; ETC: 09:33 (0:00:03 remaining)
Stats: 0:08:18 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE: Active NSE Script Threads: 3 (3 waiting)
NSE Timing: About 99.24% done; ETC: 09:33 (0:00:03 remaining)
NSE Timing: About 99.24% done; ETC: 09:34 (0:00:03 remaining)
NSE Timing: About 99.24% done; ETC: 09:34 (0:00:03 remaining)
NSE Timing: About 99.24% done; ETC: 09:35 (0:00:04 remaining)
NSE Timing: About 99.24% done; ETC: 09:35 (0:00:04 remaining)
Completed NSE at 09:36, 510.88s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 09:36
Completed NSE at 09:36, 1.10s elapsed
Nmap scan report for 10.129.89.193
Host is up, received user-set (0.081s latency).
Scanned at 2025-10-15 09:25:41 CDT for 631s

PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 63 vsftpd 3.0.3
| vulners: 
|   vsftpd 3.0.3: 
|     	CVE-2021-30047	7.5	https://vulners.com/cve/CVE-2021-30047
|_    	CVE-2021-3618	7.4	https://vulners.com/cve/CVE-2021-3618
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| vulners: 
|   cpe:/a:openbsd:openssh:8.2p1: 
|     	PACKETSTORM:173661	9.8	https://vulners.com/packetstorm/PACKETSTORM:173661	*EXPLOIT*
|     	F0979183-AE88-53B4-86CF-3AF0523F3807	9.8	https://vulners.com/githubexploit/F0979183-AE88-53B4-86CF-3AF0523F3807	*EXPLOIT*
|     	CVE-2023-38408	9.8	https://vulners.com/cve/CVE-2023-38408
|     	B8190CDB-3EB9-5631-9828-8064A1575B23	9.8	https://vulners.com/githubexploit/B8190CDB-3EB9-5631-9828-8064A1575B23	*EXPLOIT*
|     	8FC9C5AB-3968-5F3C-825E-E8DB5379A623	9.8	https://vulners.com/githubexploit/8FC9C5AB-3968-5F3C-825E-E8DB5379A623	*EXPLOIT*
|     	8AD01159-548E-546E-AA87-2DE89F3927EC	9.8	https://vulners.com/githubexploit/8AD01159-548E-546E-AA87-2DE89F3927EC	*EXPLOIT*
|     	2227729D-6700-5C8F-8930-1EEAFD4B9FF0	9.8	https://vulners.com/githubexploit/2227729D-6700-5C8F-8930-1EEAFD4B9FF0	*EXPLOIT*
|     	0221525F-07F5-5790-912D-F4B9E2D1B587	9.8	https://vulners.com/githubexploit/0221525F-07F5-5790-912D-F4B9E2D1B587	*EXPLOIT*
|     	BA3887BD-F579-53B1-A4A4-FF49E953E1C0	8.1	https://vulners.com/githubexploit/BA3887BD-F579-53B1-A4A4-FF49E953E1C0	*EXPLOIT*
|     	4FB01B00-F993-5CAF-BD57-D7E290D10C1F	8.1	https://vulners.com/githubexploit/4FB01B00-F993-5CAF-BD57-D7E290D10C1F	*EXPLOIT*
|     	CVE-2020-15778	7.8	https://vulners.com/cve/CVE-2020-15778
|     	C94132FD-1FA5-5342-B6EE-0DAF45EEFFE3	7.8	https://vulners.com/githubexploit/C94132FD-1FA5-5342-B6EE-0DAF45EEFFE3	*EXPLOIT*
|     	2E719186-2FED-58A8-A150-762EFBAAA523	7.8	https://vulners.com/gitee/2E719186-2FED-58A8-A150-762EFBAAA523	*EXPLOIT*
|     	23CC97BE-7C95-513B-9E73-298C48D74432	7.8	https://vulners.com/githubexploit/23CC97BE-7C95-513B-9E73-298C48D74432	*EXPLOIT*
|     	10213DBE-F683-58BB-B6D3-353173626207	7.8	https://vulners.com/githubexploit/10213DBE-F683-58BB-B6D3-353173626207	*EXPLOIT*
|     	SSV:92579	7.5	https://vulners.com/seebug/SSV:92579	*EXPLOIT*
|     	CVE-2020-12062	7.5	https://vulners.com/cve/CVE-2020-12062
|     	1337DAY-ID-26576	7.5	https://vulners.com/zdt/1337DAY-ID-26576	*EXPLOIT*
|     	CVE-2021-28041	7.1	https://vulners.com/cve/CVE-2021-28041
|     	CVE-2021-41617	7.0	https://vulners.com/cve/CVE-2021-41617
|     	284B94FC-FD5D-5C47-90EA-47900DAD1D1E	7.0	https://vulners.com/githubexploit/284B94FC-FD5D-5C47-90EA-47900DAD1D1E	*EXPLOIT*
|     	PACKETSTORM:189283	6.8	https://vulners.com/packetstorm/PACKETSTORM:189283	*EXPLOIT*
|     	CVE-2025-26465	6.8	https://vulners.com/cve/CVE-2025-26465
|     	9D8432B9-49EC-5F45-BB96-329B1F2B2254	6.8	https://vulners.com/githubexploit/9D8432B9-49EC-5F45-BB96-329B1F2B2254	*EXPLOIT*
|     	85FCDCC6-9A03-597E-AB4F-FA4DAC04F8D0	6.8	https://vulners.com/githubexploit/85FCDCC6-9A03-597E-AB4F-FA4DAC04F8D0	*EXPLOIT*
|     	1337DAY-ID-39918	6.8	https://vulners.com/zdt/1337DAY-ID-39918	*EXPLOIT*
|     	D104D2BF-ED22-588B-A9B2-3CCC562FE8C0	6.5	https://vulners.com/githubexploit/D104D2BF-ED22-588B-A9B2-3CCC562FE8C0	*EXPLOIT*
|     	CVE-2023-51385	6.5	https://vulners.com/cve/CVE-2023-51385
|     	C07ADB46-24B8-57B7-B375-9C761F4750A2	6.5	https://vulners.com/githubexploit/C07ADB46-24B8-57B7-B375-9C761F4750A2	*EXPLOIT*
|     	A88CDD3E-67CC-51CC-97FB-AB0CACB6B08C	6.5	https://vulners.com/githubexploit/A88CDD3E-67CC-51CC-97FB-AB0CACB6B08C	*EXPLOIT*
|     	65B15AA1-2A8D-53C1-9499-69EBA3619F1C	6.5	https://vulners.com/githubexploit/65B15AA1-2A8D-53C1-9499-69EBA3619F1C	*EXPLOIT*
|     	5325A9D6-132B-590C-BDEF-0CB105252732	6.5	https://vulners.com/gitee/5325A9D6-132B-590C-BDEF-0CB105252732	*EXPLOIT*
|     	530326CF-6AB3-5643-AA16-73DC8CB44742	6.5	https://vulners.com/githubexploit/530326CF-6AB3-5643-AA16-73DC8CB44742	*EXPLOIT*
|     	CVE-2023-48795	5.9	https://vulners.com/cve/CVE-2023-48795
|     	CVE-2020-14145	5.9	https://vulners.com/cve/CVE-2020-14145
|     	CVE-2016-20012	5.3	https://vulners.com/cve/CVE-2016-20012
|     	CVE-2025-32728	4.3	https://vulners.com/cve/CVE-2025-32728
|     	CVE-2021-36368	3.7	https://vulners.com/cve/CVE-2021-36368
|     	CVE-2025-61985	3.6	https://vulners.com/cve/CVE-2025-61985
|     	CVE-2025-61984	3.6	https://vulners.com/cve/CVE-2025-61984
|     	B7EACB4F-A5CF-5C5A-809F-E03CCE2AB150	3.6	https://vulners.com/githubexploit/B7EACB4F-A5CF-5C5A-809F-E03CCE2AB150	*EXPLOIT*
|     	4C6E2182-0E99-5626-83F6-1646DD648C57	3.6	https://vulners.com/githubexploit/4C6E2182-0E99-5626-83F6-1646DD648C57	*EXPLOIT*
|_    	PACKETSTORM:140261	0.0	https://vulners.com/packetstorm/PACKETSTORM:140261	*EXPLOIT*
80/tcp open  http    syn-ack ttl 63 gunicorn
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 NOT FOUND
|     Server: gunicorn
|     Date: Wed, 15 Oct 2025 14:25:55 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 232
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Wed, 15 Oct 2025 14:25:49 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 19386
|     <!DOCTYPE html>
|     <html class="no-js" lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>Security Dashboard</title>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link rel="shortcut icon" type="image/png" href="/static/images/icon/favicon.ico">
|     <link rel="stylesheet" href="/static/css/bootstrap.min.css">
|     <link rel="stylesheet" href="/static/css/font-awesome.min.css">
|     <link rel="stylesheet" href="/static/css/themify-icons.css">
|     <link rel="stylesheet" href="/static/css/metisMenu.css">
|     <link rel="stylesheet" href="/static/css/owl.carousel.min.css">
|     <link rel="stylesheet" href="/static/css/slicknav.min.css">
|     <!-- amchar
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Wed, 15 Oct 2025 14:25:50 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Allow: GET, HEAD, OPTIONS
|     Content-Length: 0
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|     Content-Type: text/html
|     Content-Length: 196
|     <html>
|     <head>
|     <title>Bad Request</title>
|     </head>
|     <body>
|     <h1><p>Bad Request</p></h1>
|     Invalid HTTP Version &#x27;Invalid HTTP Version: &#x27;RTSP/1.0&#x27;&#x27;
|     </body>
|_    </html>
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.129.89.193
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://10.129.89.193:80/
|     Form id: 
|     Form action: #
|     
|     Path: http://10.129.89.193:80/netstat
|     Form id: 
|     Form action: #
|     
|     Path: http://10.129.89.193:80/ip
|     Form id: 
|     Form action: #
|     
|     Path: http://10.129.89.193:80/data/1
|     Form id: 
|_    Form action: #
|_http-server-header: gunicorn
|_http-litespeed-sourcecode-download: Page: /index.php was not found. Try with an existing file.
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
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
|_http-dombased-xss: Couldn't find any DOM based XSS.
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.94SVN%I=7%D=10/15%Time=68EFAEEE%P=x86_64-pc-linux-gnu%r(
SF:GetRequest,3012,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gunicorn\r\nDate:
SF:\x20Wed,\x2015\x20Oct\x202025\x2014:25:49\x20GMT\r\nConnection:\x20clos
SF:e\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x2
SF:019386\r\n\r\n<!DOCTYPE\x20html>\n<html\x20class=\"no-js\"\x20lang=\"en
SF:\">\n\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x2
SF:0\x20<meta\x20http-equiv=\"x-ua-compatible\"\x20content=\"ie=edge\">\n\
SF:x20\x20\x20\x20<title>Security\x20Dashboard</title>\n\x20\x20\x20\x20<m
SF:eta\x20name=\"viewport\"\x20content=\"width=device-width,\x20initial-sc
SF:ale=1\">\n\x20\x20\x20\x20<link\x20rel=\"shortcut\x20icon\"\x20type=\"i
SF:mage/png\"\x20href=\"/static/images/icon/favicon\.ico\">\n\x20\x20\x20\
SF:x20<link\x20rel=\"stylesheet\"\x20href=\"/static/css/bootstrap\.min\.cs
SF:s\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/static/css
SF:/font-awesome\.min\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"
SF:\x20href=\"/static/css/themify-icons\.css\">\n\x20\x20\x20\x20<link\x20
SF:rel=\"stylesheet\"\x20href=\"/static/css/metisMenu\.css\">\n\x20\x20\x2
SF:0\x20<link\x20rel=\"stylesheet\"\x20href=\"/static/css/owl\.carousel\.m
SF:in\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/stat
SF:ic/css/slicknav\.min\.css\">\n\x20\x20\x20\x20<!--\x20amchar")%r(HTTPOp
SF:tions,B3,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gunicorn\r\nDate:\x20Wed
SF:,\x2015\x20Oct\x202025\x2014:25:50\x20GMT\r\nConnection:\x20close\r\nCo
SF:ntent-Type:\x20text/html;\x20charset=utf-8\r\nAllow:\x20GET,\x20HEAD,\x
SF:20OPTIONS\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest,121,"HTTP/1\.
SF:1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\nContent-Type:\x20
SF:text/html\r\nContent-Length:\x20196\r\n\r\n<html>\n\x20\x20<head>\n\x20
SF:\x20\x20\x20<title>Bad\x20Request</title>\n\x20\x20</head>\n\x20\x20<bo
SF:dy>\n\x20\x20\x20\x20<h1><p>Bad\x20Request</p></h1>\n\x20\x20\x20\x20In
SF:valid\x20HTTP\x20Version\x20&#x27;Invalid\x20HTTP\x20Version:\x20&#x27;
SF:RTSP/1\.0&#x27;&#x27;\n\x20\x20</body>\n</html>\n")%r(FourOhFourRequest
SF:,189,"HTTP/1\.0\x20404\x20NOT\x20FOUND\r\nServer:\x20gunicorn\r\nDate:\
SF:x20Wed,\x2015\x20Oct\x202025\x2014:25:55\x20GMT\r\nConnection:\x20close
SF:\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x20
SF:232\r\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x203\.2
SF:\x20Final//EN\">\n<title>404\x20Not\x20Found</title>\n<h1>Not\x20Found<
SF:/h1>\n<p>The\x20requested\x20URL\x20was\x20not\x20found\x20on\x20the\x2
SF:0server\.\x20If\x20you\x20entered\x20the\x20URL\x20manually\x20please\x
SF:20check\x20your\x20spelling\x20and\x20try\x20again\.</p>\n");
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 09:36
Completed NSE at 09:36, 0.00s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 09:36
Completed NSE at 09:36, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 640.62 seconds
           Raw packets sent: 6 (264B) | Rcvd: 5 (300B)
```

**nmap result**

```bash
```

# Enumeration

## Web

**FUFF directory**

```bash
┌─[eu-dedivip-1]─[10.10.14.47]─[julien23@htb-momcl5uwrw]─[~]
└──╼ [★]$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.129.89.193/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.89.193/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

# on at least 2 different hosts [Status: 200, Size: 19386, Words: 8716, Lines: 389, Duration: 95ms]
#                       [Status: 200, Size: 19386, Words: 8716, Lines: 389, Duration: 97ms]
#                       [Status: 200, Size: 19386, Words: 8716, Lines: 389, Duration: 99ms]
# Priority ordered case-sensitive list, where entries were found [Status: 200, Size: 19386, Words: 8716, Lines: 389, Duration: 99ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 19386, Words: 8716, Lines: 389, Duration: 100ms]
#                       [Status: 200, Size: 19386, Words: 8716, Lines: 389, Duration: 101ms]
# This work is licensed under the Creative Commons [Status: 200, Size: 19386, Words: 8716, Lines: 389, Duration: 101ms]
                        [Status: 200, Size: 19386, Words: 8716, Lines: 389, Duration: 103ms]
# Attribution-Share Alike 3.0 License. To view a copy of this [Status: 200, Size: 19386, Words: 8716, Lines: 389, Duration: 105ms]
# Copyright 2007 James Fisher [Status: 200, Size: 19386, Words: 8716, Lines: 389, Duration: 105ms]
# directory-list-2.3-medium.txt [Status: 200, Size: 19386, Words: 8716, Lines: 389, Duration: 108ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/ [Status: 200, Size: 19386, Words: 8716, Lines: 389, Duration: 107ms]
# or send a letter to Creative Commons, 171 Second Street, [Status: 200, Size: 19386, Words: 8716, Lines: 389, Duration: 99ms]
#                       [Status: 200, Size: 19386, Words: 8716, Lines: 389, Duration: 107ms]
data                    [Status: 302, Size: 208, Words: 21, Lines: 4, Duration: 87ms]
ip                      [Status: 200, Size: 17459, Words: 7275, Lines: 355, Duration: 92ms]
netstat                 [Status: 200, Size: 62768, Words: 31135, Lines: 700, Duration: 90ms]
capture                 [Status: 302, Size: 220, Words: 21, Lines: 4, Duration: 5145ms]
                        [Status: 200, Size: 19386, Words: 8716, Lines: 389, Duration: 89ms]
:: Progress: [220560/220560] :: Job [1/1] :: 263 req/sec :: Duration: [0:09:20] :: Errors: 0 ::

```

**General**

Seemed to be logged in as Nathan

is a static website with no functionality


**Netstat**

running `/netstat` seems to run dashboard

going to `/data/1` gives inbound request. Going to `/data/0` goes to the first request where we can see inbound FTP requests

## FTP

there is an FTP port open. Tried anonymous login but not working

username = nathan
password = Buck3tH4TF0RM3!
