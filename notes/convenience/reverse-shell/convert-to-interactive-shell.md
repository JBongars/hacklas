# convert-to-interactive-shell

Author: Julien Bongars
Date: 2025-09-20 19:46:51
Path: /opt/development/cybersec/hacklas/notes/convenience/reverse-shell/convert-to-interactive-shell.md

---

### Make fully interactive

**Method 1**

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
CTRL-Z
stty raw -echo
fg
export TERM=xterm
```

**Method 2**

```bash
# Step 1: Spawn PTY
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Step 2: Background shell
# Press: Ctrl+Z

# Step 3: In your local terminal
stty raw -echo; fg

# Step 4: Back in reverse shell
export TERM=xterm
export SHELL=/bin/bash
stty rows 24 columns 80
```

