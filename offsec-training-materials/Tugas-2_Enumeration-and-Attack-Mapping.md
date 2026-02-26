# TUGAS HARIAN 2: ENUMERATION AND ATTACK MAPPING

---

> **Referensi:** Man Behind the Hat — Chapter 3 (Enumeration and Attack Mapping)
> **Prasyarat:** Reconnaissance report dari Tugas 1 selesai, lab environment aktif
> **Deliverable:** Enumeration report + Attack Tree + Priority Matrix

---

## Objective

Peserta mampu melakukan **deep-dive service enumeration** pada setiap service yang ditemukan di fase reconnaissance, membangun **attack surface map** dan **attack tree**, serta melakukan **web application fingerprinting** dan **content discovery** secara komprehensif.

---

## Bagian A: Deep-Dive Service Enumeration (120 menit)

### Task A1 — Enumerasi SSH (25 menit)

**Konteks:** SSH (TCP port 22) adalah salah satu service paling umum pada Linux server. Meskipun secara desain aman, misconfiguration sering membuka attack surface.

**Instruksi:**

1. **Banner grabbing dan version detection:**
   ```bash
   # Banner grab manual
   nc -nv <target_IP> 22

   # Nmap version detection
   nmap -sV -p22 <target_IP>
   ```

2. **SSH configuration enumeration:**
   ```bash
   # Algoritma yang didukung
   nmap -p22 --script=ssh2-enum-algos <target_IP>

   # Metode autentikasi yang diizinkan
   nmap -p22 --script=ssh-auth-methods --script-args="ssh.user=root" <target_IP>

   # SSH audit (jika ssh-audit terinstall)
   ssh-audit <target_IP>
   ```

3. **Dokumentasikan temuan:**

   | Parameter | Nilai | Security Assessment |
   |-----------|-------|---------------------|
   | SSH Version | | Outdated / Current? |
   | PermitRootLogin | | Yes = HIGH RISK |
   | PasswordAuthentication | | Yes = Brute-force possible |
   | Weak Algorithms | | Deprecated ciphers/KEX? |
   | Key Exchange Methods | | Vulnerable methods? |

4. **Jawab Saya:**
   - Apakah root login diizinkan? Apa implikasinya?
   - Adakah algoritma deprecated yang masih didukung?
   - Apakah password-based authentication aktif? Jika ya, vektor serangan apa yang terbuka?

---

### Task A2 — Enumerasi HTTP/HTTPS (35 menit)

**Konteks:** HTTP merupakan primary attack surface pada mayoritas engagement. Enumerasi HTTP mencakup technology fingerprinting, security header analysis, dan content discovery.

**Instruksi:**

1. **Technology fingerprinting:**
   ```bash
   # WhatWeb (passive → aggressive)
   whatweb http://<target_IP>:<port>
   whatweb -v http://<target_IP>:<port>
   whatweb -a 3 http://<target_IP>:<port>
   ```

2. **HTTP header analysis:**
   ```bash
   # Response headers
   curl -I http://<target_IP>:<port>

   # Verbose headers (termasuk request)
   curl -v http://<target_IP>:<port> 2>&1 | head -30
   ```

3. **Analisis security headers** — periksa keberadaan header berikut:

   | Security Header | Present? | Value | Assessment |
   |----------------|----------|-------|------------|
   | Content-Security-Policy | | | Missing = XSS risk |
   | X-Frame-Options | | | Missing = Clickjacking risk |
   | X-Content-Type-Options | | | Missing = MIME sniffing risk |
   | Strict-Transport-Security | | | Missing = MITM risk |
   | X-XSS-Protection | | | Deprecated but indicative |
   | Server | | | Information disclosure? |
   | X-Powered-By | | | Technology disclosure? |

4. **WAF detection:**
   ```bash
   wafw00f http://<target_IP>:<port>
   ```

5. **NSE HTTP scripts:**
   ```bash
   nmap -p80,443,5000 --script=http-enum,http-headers,http-methods,http-title <target_IP>
   ```

6. **Jawab Saya:**
   - Framework/bahasa pemrograman apa yang digunakan? (dari Server header, cookie names, error pages)
   - Security headers mana yang hilang? Apa dampaknya?
   - Apakah WAF terdeteksi? Jika tidak, apa implikasinya?

---

### Task A3 — Enumerasi SMB/CIFS (25 menit)

**Konteks:** SMB sering terekspos dan memiliki sejarah panjang kerentanan kritikal (EternalBlue, SMBGhost). Null sessions memungkinkan enumerasi tanpa kredensial.

**Instruksi:**

1. **Version detection:**
   ```bash
   nmap -p445 --script=smb-protocols <target_IP>
   ```

2. **Null session testing:**
   ```bash
   # List shares tanpa password
   smbclient -L //<target_IP> -N

   # Comprehensive enum
   enum4linux -a <target_IP>
   ```

3. **Share mapping dan permission check:**
   ```bash
   smbmap -H <target_IP>
   smbmap -H <target_IP> -u '' -p ''
   ```

4. **Vulnerability check:**
   ```bash
   nmap -p445 --script=smb-vuln* <target_IP>
   ```

5. **RID Cycling (user enumeration tanpa credential):**
   ```bash
   crackmapexec smb <target_IP> -u '' -p '' --rid-brute
   ```

6. **Dokumentasikan:**

   | Finding | Detail | Risk Level |
   |---------|--------|------------|
   | SMB Version | | |
   | Null Session | Allowed/Denied | |
   | Writable Shares | | |
   | User List | | |
   | Known Vulnerabilities | | |

7. **Jawab Saya:**
   - Apakah null session berhasil? Informasi apa yang terungkap?
   - Adakah share yang writable? Apa potensi exploitasi-nya?
   - Apakah SMBv1 aktif? Apa implikasi terhadap EternalBlue?

---

### Task A4 — Enumerasi SNMP (20 menit)

**Konteks:** SNMP menggunakan community strings sebagai "password" dalam plaintext. Default strings (`public`/`private`) masih sering digunakan.

**Instruksi:**

1. **Deteksi SNMP:**
   ```bash
   nmap -sU -p161 <target_IP> -sV
   ```

2. **Community string brute-force:**
   ```bash
   onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt <target_IP>
   ```

3. **SNMP walk** (jika community string ditemukan):
   ```bash
   # Full walk
   snmpwalk -v2c -c public <target_IP>

   # Targeted queries
   snmpwalk -v2c -c public <target_IP> 1.3.6.1.2.1.1.1.0        # System description
   snmpwalk -v2c -c public <target_IP> 1.3.6.1.4.1.77.1.2.25     # User accounts
   snmpwalk -v2c -c public <target_IP> 1.3.6.1.2.1.25.4.2.1.2    # Running processes
   snmpwalk -v2c -c public <target_IP> 1.3.6.1.2.1.25.6.3.1.2    # Installed software
   snmpwalk -v2c -c public <target_IP> 1.3.6.1.2.1.6.13.1.3      # Open TCP ports
   snmpwalk -v2c -c public <target_IP> 1.3.6.1.2.1.2.2.1.2       # Network interfaces
   ```

4. **Dokumentasikan** informasi yang diperoleh dari SNMP:

   | OID Category | Data Extracted | Intelligence Value |
   |-------------|----------------|-------------------|
   | System Info | | |
   | User Accounts | | |
   | Running Processes | | |
   | Installed Software | | |
   | Network Interfaces | | |
   | Open TCP Ports | | |

5. **Jawab Saya:**
   - Community string mana yang berhasil? Apakah default?
   - Informasi apa yang paling valuable dari SNMP walk?
   - Bagaimana SNMP data bisa digunakan untuk membangun attack plan?

---

### Task A5 — Enumerasi SMTP (15 menit)

**Konteks:** SMTP commands seperti VRFY dan EXPN dapat digunakan untuk username enumeration.

**Instruksi:**

1. **Banner grabbing:**
   ```bash
   nmap -p25,587,465 --script=smtp-commands <target_IP>
   ```

2. **Manual VRFY test:**
   ```bash
   # Koneksi manual
   nc -nv <target_IP> 25
   # Ketik: VRFY root
   # Ketik: VRFY admin
   # Ketik: VRFY nonexistentuser
   ```

3. **Automated user enumeration:**
   ```bash
   smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t <target_IP>
   ```

4. **Open relay check:**
   ```bash
   nmap -p25 --script=smtp-open-relay <target_IP>
   ```

5. **Jawab Saya:**
   - Apakah VRFY command diizinkan? Username mana yang valid?
   - Apakah server merupakan open relay? Apa implikasinya?

---

## Bagian B: Web Attack Surface Intelligence (60 menit)

### Task B1 — Web Application Fingerprinting (20 menit)

**Target:** Web application pada Ubuntu Server lab

**Instruksi:**

1. **Passive fingerprinting** — analisis HTTP response tanpa intrusive scanning:
   ```bash
   # Header analysis
   curl -I http://<target_IP>:<port>

   # Cookie analysis — identifikasi framework dari cookie name
   curl -c - http://<target_IP>:<port>/login -d "username=test&password=test" 2>/dev/null
   ```

2. **Identifikasi tech stack** dari hasil analisis:

   | Indicator | Value | Technology Implied |
   |-----------|-------|--------------------|
   | Server header | | Apache/Nginx/Werkzeug/IIS |
   | Cookie name | | PHPSESSID=PHP, session=Flask |
   | Error page format | | Framework-specific errors |
   | URL patterns | | .php/.py/.aspx/REST-style |
   | X-Powered-By | | PHP/ASP.NET/Express |

3. **Active fingerprinting:**
   ```bash
   # WhatWeb aggressive mode
   whatweb -a 3 http://<target_IP>:<port>

   # Nikto scan
   nikto -h http://<target_IP>:<port>
   ```

4. **Jawab Saya:**
   - Tech stack apa yang teridentifikasi? (bahasa, framework, database, web server)
   - Berdasarkan tech stack, vulnerability profile apa yang relevan?
     - PHP + MySQL → SQL Injection, File Inclusion, Type Juggling
     - Python + SQLite → SQL Injection, SSTI, Command Injection
     - Node.js + MongoDB → NoSQL Injection, Prototype Pollution

---

### Task B2 — Content Discovery (25 menit)

**Instruksi:**

1. **Directory dan file discovery dengan ffuf:**
   ```bash
   # Basic directory discovery
   ffuf -u http://<target_IP>:<port>/FUZZ \
       -w /usr/share/wordlists/dirb/common.txt

   # Filtered discovery (hapus noise)
   ffuf -u http://<target_IP>:<port>/FUZZ \
       -w /usr/share/wordlists/dirb/common.txt \
       -mc all -fs 0

   # File extension discovery
   ffuf -u http://<target_IP>:<port>/FUZZ \
       -w /usr/share/wordlists/dirb/common.txt \
       -e .py,.bak,.old,.conf,.sql,.db,.log,.txt,.php

   # Recursive discovery
   ffuf -u http://<target_IP>:<port>/FUZZ \
       -w /usr/share/wordlists/dirb/common.txt \
       -recursion -recursion-depth 2
   ```

2. **Gobuster sebagai verifikasi:**
   ```bash
   gobuster dir -u http://<target_IP>:<port> \
       -w /usr/share/wordlists/dirb/common.txt \
       -t 50 -b 302,404
   ```

3. **Sensitive file check manual:**
   ```bash
   for path in .git/HEAD .env robots.txt sitemap.xml .htaccess phpinfo.php \
       server-status debug admin api/v1 swagger config.php wp-config.php; do
       STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://<target_IP>:<port>/$path)
       echo "$path → $STATUS"
   done
   ```

4. **Dokumentasikan** semua endpoint yang ditemukan:

   | Path | Status Code | Content Type | Assessment |
   |------|-------------|-------------|------------|
   | /login | | | Authentication endpoint |
   | /admin | | | Administrative panel |
   | /debug | | | Information disclosure |
   | | | | |

5. **Jawab Saya:**
   - Endpoint mana yang paling menarik dari sudut pandang security?
   - Apakah ada backup files, configuration files, atau debug endpoints yang terekspos?
   - Adakah hidden administrative endpoints?

---

### Task B3 — Parameter Discovery (15 menit)

**Instruksi:**

1. **Arjun — automated parameter discovery:**
   ```bash
   # Discover parameters pada endpoint tertentu
   arjun -u http://<target_IP>:<port>/search
   arjun -u http://<target_IP>:<port>/login
   ```

2. **Manual parameter extraction dari HTML:**
   ```bash
   # Ekstrak semua form fields
   curl -s http://<target_IP>:<port>/login | grep -iE "input|name=|type=|hidden|form"
   curl -s http://<target_IP>:<port>/search | grep -iE "input|name=|type=|hidden|form"
   curl -s http://<target_IP>:<port>/ping | grep -iE "input|name=|type=|hidden|form"
   ```

3. **Dokumentasikan** semua parameter per endpoint:

   | Endpoint | Parameter | Type | Input Validation? | Potential Vulnerability |
   |----------|-----------|------|-------------------|----------------------|
   | /login | username | POST | | SQLi, Username Enum |
   | /login | password | POST | | Brute-force |
   | /search | q | GET | | SQLi, XSS |
   | /ping | ip/host | POST | | Command Injection |
   | | | | | |

---

## Bagian C: Attack Surface Mapping (60 menit)

### Task C1 — Attack Tree Construction (30 menit)

**Konteks:** Berdasarkan model Bruce Schneier (1999), bangun attack tree yang memetakan semua kemungkinan attack path.

**Instruksi:**

1. Buat **Attack Tree** dengan format berikut:

   ```
   ROOT: Gain Initial Access to Target System
   ├── [AND] Exploit Web Application
   │   ├── [OR] SQL Injection
   │   │   ├── /search endpoint (parameter: q)
   │   │   │   ├── UNION-based extraction
   │   │   │   ├── Boolean-based blind
   │   │   │   └── Time-based blind
   │   │   └── /login endpoint (parameter: username)
   │   │       └── Authentication bypass
   │   ├── [OR] Command Injection
   │   │   └── /ping endpoint (parameter: ip/host)
   │   │       ├── Semicolon separator (;)
   │   │       ├── AND operator (&&)
   │   │       └── Pipe operator (|)
   │   ├── [OR] File Upload Exploitation
   │   │   └── /upload endpoint
   │   │       ├── Web shell upload
   │   │       └── Reverse shell upload
   │   └── [OR] Authentication Attack
   │       ├── Brute-force /login
   │       ├── Default credentials
   │       └── Session hijacking
   ├── [AND] Exploit Network Services
   │   ├── [OR] SSH Attack
   │   │   ├── Brute-force (jika PasswordAuth enabled)
   │   │   └── Known CVE (jika version vulnerable)
   │   ├── [OR] SMB Exploitation
   │   │   └── EternalBlue (jika SMBv1 enabled)
   │   └── [OR] SNMP Exploitation
   │       └── Community string → info disclosure
   └── [AND] Social Engineering
       └── Credential phishing (username dari OSINT)
   ```

2. **Sesuaikan attack tree** berdasarkan **temuan aktual** dari reconnaissance dan enumeration anda.

---

### Task C2 — Entry Point Prioritization (30 menit)

**Instruksi:**

1. Gunakan **scoring matrix** dari materi (5 dimensi) untuk memprioritaskan setiap entry point:

   | Entry Point | Exploit Reliability (1-5) | Access Level (1-5) | Detection Risk (1-5 inv) | Prerequisites (1-5 inv) | Time to Exploit (1-5 inv) | **Total** |
   |------------|--------------------------|-------------------|------------------------|----------------------|--------------------------|-----------|
   | SQLi /search | | | | | | **/25** |
   | CMDi /ping | | | | | | **/25** |
   | File Upload | | | | | | **/25** |
   | Brute SSH | | | | | | **/25** |
   | Auth Bypass /login | | | | | | **/25** |
   | | | | | | | |

2. **Ranking dan justifikasi** — urutkan entry points dari skor tertinggi ke terendah:

   | Ranking | Entry Point | Total Score | Justifikasi |
   |---------|------------|-------------|-------------|
   | 1 | | | |
   | 2 | | | |
   | 3 | | | |

3. **Tentukan attack plan** — berdasarkan prioritas, tuliskan rencana eksploitasi:
   ```
   ATTACK PLAN
   ═══════════
   Primary Vector  : [entry point #1] — [alasan]
   Fallback Vector : [entry point #2] — [alasan]
   Last Resort     : [entry point #3] — [alasan]

   Estimated Timeline:
   - Phase 1 (Exploitation): XX menit
   - Phase 2 (Post-exploitation): XX menit
   - Phase 3 (Documentation): XX menit
   ```

---

## Bagian D: Deliverable & Laporan (30 menit)

### Instruksi Penulisan Laporan

Buat **Enumeration & Attack Mapping Report** dengan struktur:

```markdown
# ENUMERATION & ATTACK MAPPING REPORT
## Target: [nama/IP target]
## Tanggal: [tanggal pengerjaan]
## Operator: [nama peserta]

---

## 1. Executive Summary
- Jumlah services yang dienumerasi
- Temuan utama per service
- Attack surface assessment

## 2. Service Enumeration Results
### 2.1 SSH Enumeration
### 2.2 HTTP/HTTPS Enumeration
### 2.3 SMB Enumeration
### 2.4 SNMP Enumeration
### 2.5 SMTP Enumeration

## 3. Web Application Intelligence
### 3.1 Technology Stack Identification
### 3.2 Security Header Assessment
### 3.3 Content Discovery Results
### 3.4 Parameter Mapping

## 4. Attack Surface Map
### 4.1 Attack Tree (visual/text)
### 4.2 Entry Point Prioritization Matrix
### 4.3 Attack Plan

## 5. Risk Assessment Summary

| Risk Level | Count | Examples |
|-----------|-------|---------|
| CRITICAL | | |
| HIGH | | |
| MEDIUM | | |
| LOW | | |
| INFO | | |

## 6. Recommendations for Exploitation Phase
```

---

## Rubrik Penilaian

| Kriteria | Bobot | Deskripsi |
|----------|-------|-----------|
| **Service Enumeration** | 30% | Semua 5 service types dienumerasi dengan output lengkap |
| **Web Application Intelligence** | 20% | Fingerprinting, content discovery, parameter discovery komprehensif |
| **Attack Tree** | 15% | Logis, berdasarkan temuan aktual, mencakup semua paths |
| **Prioritization Matrix** | 15% | Scoring objektif, justifikasi setiap ranking |
| **Kualitas Laporan** | 15% | Profesional, terstruktur, evidence-based |
| **Analisis & Interpretasi** | 5% | Pertanyaan dijawab menunjukkan pemahaman mendalam |
| **Total** | **100%** | **70+ = Pass** |

---

## Catatan Penting

1. **Enumeration ≠ Exploitation** — di fase ini kita **hanya mengumpulkan informasi**, belum melakukan exploit
2. Jika service tidak tersedia di lab (misalnya SNMP/SMTP), **dokumentasikan bahwa service tidak ditemukan** dan jelaskan bagaimana anda akan melakukan enumerasi jika service tersedia
3. **Simpan semua output** dalam direktori: `~/enum/<target>/`
4. Bandingkan hasil **ffuf vs gobuster** — adakah perbedaan? Mengapa?
5. Attack tree harus **berdasarkan temuan aktual**, bukan template generik

---

*Referensi: Man Behind the Hat — Chapter 3 (Enumeration and Attack Mapping), Section 3.1-3.3*
