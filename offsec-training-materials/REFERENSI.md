# DAFTAR REFERENSI LENGKAP

## Man Behind the Hat — Offensive Security Training

---

> Dokumen ini mengompilasi seluruh referensi yang digunakan dalam keseluruhan materi
> pelatihan **Man Behind the Hat**, mencakup standar industri, framework, RFC, tools,
> dan sumber akademis yang menjadi fondasi metodologis modul.

---

## 1. Framework & Standar Industri

### 1.1 Penetration Testing Frameworks

| Framework | Organisasi | Deskripsi | Referensi |
|-----------|-----------|-----------|-----------|
| **PTES** (Penetration Testing Execution Standard) | PTES.org | Standar 7 fase penetration testing: Pre-engagement, Intelligence Gathering, Threat Modeling, Vulnerability Analysis, Exploitation, Post-Exploitation, Reporting | http://www.pentest-standard.org |
| **OWASP Testing Guide** | OWASP Foundation | Panduan komprehensif pengujian keamanan web application | https://owasp.org/www-project-web-security-testing-guide/ |
| **OSSTMM 3** (Open Source Security Testing Methodology Manual) | ISECOM | Metodologi open-source untuk security testing, termasuk channel-based testing | https://www.isecom.org/OSSTMM.3.pdf |
| **ISSAF** (Information Systems Security Assessment Framework) | OISSG | Framework penilaian keamanan sistem informasi | — |

### 1.2 Threat Intelligence & Attack Frameworks

| Framework | Organisasi | Deskripsi | Referensi |
|-----------|-----------|-----------|-----------|
| **MITRE ATT&CK** | MITRE Corporation | Knowledge base taktik dan teknik adversary berdasarkan observasi real-world | https://attack.mitre.org |
| **Cyber Kill Chain** | Lockheed Martin (2011) | Model 7 fase serangan siber: Reconnaissance, Weaponization, Delivery, Exploitation, Installation, C2, Actions on Objectives | https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html |
| **Attack Trees** | Bruce Schneier (1999) | Model formal analisis keamanan menggunakan representasi hierarkis; paper: "Attack Trees: Modeling Security Threats" | — |

### 1.3 Standar Keamanan & Compliance

| Standar | Organisasi | Deskripsi | Referensi |
|---------|-----------|-----------|-----------|
| **NIST SP 800-115** | NIST | Technical Guide to Information Security Testing and Assessment | https://csrc.nist.gov/publications/detail/sp/800-115/final |
| **ISO/IEC 27001** | ISO | Standar internasional untuk sistem manajemen keamanan informasi (ISMS) | https://www.iso.org/isoiec-27001-information-security.html |
| **GDPR** | European Union | General Data Protection Regulation — peraturan perlindungan data umum untuk privasi data | https://gdpr.eu |
| **HIPAA** | U.S. Government | Health Insurance Portability and Accountability Act — perlindungan informasi kesehatan | https://www.hhs.gov/hipaa |
| **PCI-DSS** | PCI SSC | Payment Card Industry Data Security Standard — standar keamanan data pemegang kartu | https://www.pcisecuritystandards.org |
| **UU PDP** | Pemerintah Indonesia | Undang-Undang Perlindungan Data Pribadi — mengatur kewajiban pengelolaan data pribadi, hak data, serta denda administratif hingga 2% dari pendapatan tahunan | — |
| **UU ITE** | Pemerintah Indonesia | Undang-Undang Informasi dan Transaksi Elektronik — dasar hukum penindakan kejahatan siber | — |
| **SEC Cybersecurity Rules** | U.S. SEC | Peraturan manajemen risiko keamanan siber dan pelaporan insiden untuk perusahaan publik | https://www.sec.gov/rules/final/2023/33-11216.pdf |
| **AJP-2.5** | NATO | Allied Joint Doctrine for Joint Intelligence — doktrin intelijen bersama NATO | — |

---

## 2. RFC (Request for Comments) — IETF Standards

| RFC | Judul | Relevansi dalam Modul |
|-----|-------|----------------------|
| **RFC 791** | Internet Protocol (IP) | Fragmentasi IP untuk IDS/IPS evasion |
| **RFC 1035** | Domain Names — Implementation and Specification | DNS sebagai sistem hierarkis terdistribusi, UDP port 53 |
| **RFC 1157** | Simple Network Management Protocol (SNMP) | Protokol SNMP v1, community strings |
| **RFC 2616** | Hypertext Transfer Protocol — HTTP/1.1 | Fondasi protokol HTTP |
| **RFC 2818** | HTTP Over TLS (HTTPS) | HTTP over TLS untuk komunikasi terenkripsi |
| **RFC 3416** | Version 2 of the Protocol Operations for SNMPv2 | Operasi SNMP v2c |
| **RFC 3912** | WHOIS Protocol Specification | Protokol query-response untuk informasi registrasi domain |
| **RFC 4253** | The Secure Shell (SSH) Transport Layer Protocol | Protokol SSH, tiga layer keamanan |
| **RFC 7230-7235** | HTTP/1.1 Message Syntax and Routing (series) | Spesifikasi modern HTTP/1.1 |

---

## 3. CWE (Common Weakness Enumeration)

| CWE ID | Nama | Konteks dalam Modul |
|--------|------|---------------------|
| **CWE-78** | Improper Neutralization of Special Elements used in an OS Command (OS Command Injection) | Eksploitasi endpoint `/ping` melalui metacharacter injection |
| **CWE-89** | Improper Neutralization of Special Elements used in an SQL Command (SQL Injection) | Auth bypass pada `/login`, data extraction pada `/search` |
| **CWE-204** | Observable Response Discrepancy | Username enumeration melalui perbedaan error message |
| **CWE-307** | Improper Restriction of Excessive Authentication Attempts | Tidak adanya rate limiting pada login page |
| **CWE-614** | Sensitive Cookie in HTTPS Session Without 'Secure' Attribute | Session cookie tanpa flag keamanan (Secure, HttpOnly, SameSite) |

---

## 4. Tools & Software

### 4.1 Reconnaissance Tools

| Tool | Developer/Organisasi | Fungsi | URL |
|------|---------------------|--------|-----|
| **Nmap** | Gordon Lyon (Fyodor) | Network discovery dan security auditing | https://nmap.org |
| **Amass** | OWASP | Subdomain enumeration multi-source (20+ sumber) | https://github.com/owasp-amass/amass |
| **Subfinder** | ProjectDiscovery | Passive subdomain discovery | https://github.com/projectdiscovery/subfinder |
| **theHarvester** | Christian Martorella | Email, subdomain, IP harvesting dari public sources | https://github.com/laramies/theHarvester |
| **Shodan** | John Matherly | Internet-connected device search engine | https://www.shodan.io |
| **crt.sh** | Sectigo (ComodoCA) | Certificate Transparency log search | https://crt.sh |
| **Wayback Machine** | Internet Archive | Arsip historis halaman web | https://web.archive.org |
| **Gitleaks** | Zachary Rice | Secret detection dan entropy analysis dalam git repositories | https://github.com/gitleaks/gitleaks |
| **Google Dorking** | — | Teknik advanced search menggunakan operator Google | https://www.exploit-db.com/google-hacking-database |

### 4.2 Scanning & Enumeration Tools

| Tool | Developer/Organisasi | Fungsi | URL |
|------|---------------------|--------|-----|
| **Nmap NSE Scripts** | Nmap Project | Scripting engine untuk vulnerability detection dan enumeration | https://nmap.org/nsedoc/ |
| **enum4linux** | Mark Lowe | SMB/NetBIOS enumeration pada Windows/Samba | https://github.com/CiscoCXSecurity/enum4linux |
| **smbclient** | Samba Project | SMB/CIFS client untuk share access | https://www.samba.org |
| **smbmap** | ShawnDEvans | SMB share enumeration dan access check | https://github.com/ShawnDEvans/smbmap |
| **CrackMapExec** | byt3bl33d3r | Swiss army knife untuk pentesting networks (SMB, WinRM, LDAP) | https://github.com/byt3bl33d3r/CrackMapExec |
| **ssh-audit** | jtesta | SSH server & client configuration auditing | https://github.com/jtesta/ssh-audit |
| **snmpwalk** | Net-SNMP | SNMP MIB tree walking | http://www.net-snmp.org |
| **onesixtyone** | Patrik Karlsson | SNMP community string brute-forcer | https://github.com/trailofbits/onesixtyone |
| **smtp-user-enum** | pentestmonkey | SMTP user enumeration via VRFY/EXPN/RCPT | https://pentestmonkey.net/tools/smtp-user-enum |

### 4.3 Web Application Testing Tools

| Tool | Developer/Organisasi | Fungsi | URL |
|------|---------------------|--------|-----|
| **WhatWeb** | Andrew Horton | Web technology fingerprinting (passive → aggressive) | https://github.com/urbanadventurer/WhatWeb |
| **Nikto** | Chris Sullo, David Lodge | Open-source web server scanner, misconfiguration detection | https://github.com/sullo/nikto |
| **ffuf** | Joohoi | Fast web fuzzer untuk content/parameter discovery | https://github.com/ffuf/ffuf |
| **Gobuster** | OJ Reeves | Directory/file/DNS/vhost brute-forcing | https://github.com/OJ/gobuster |
| **Feroxbuster** | epi052 | Fast, recursive content discovery tool | https://github.com/epi052/feroxbuster |
| **Arjun** | s0md3v | HTTP parameter discovery | https://github.com/s0md3v/Arjun |
| **wafw00f** | EnableSecurity | Web Application Firewall (WAF) detection | https://github.com/EnableSecurity/wafw00f |
| **curl** | Daniel Stenberg | Command-line HTTP client | https://curl.se |

### 4.4 Exploitation Tools

| Tool | Developer/Organisasi | Fungsi | URL |
|------|---------------------|--------|-----|
| **SQLMap** | Bernardo Damele A.G., Miroslav Stampar (sejak 2006) | Automated SQL injection dan database takeover | https://sqlmap.org |
| **Hydra** | THC (The Hacker's Choice) | Network login brute-forcer (HTTP, SSH, FTP, SMB, dll.) | https://github.com/vanhauser-thc/thc-hydra |

### 4.5 Utility & Supporting Tools

| Tool | Fungsi | URL |
|------|--------|-----|
| **SecLists** | Kumpulan wordlist untuk security testing (usernames, passwords, URLs, fuzzing payloads) | https://github.com/danielmiessler/SecLists |
| **netcat (nc)** | Network utility: banner grabbing, port scanning, file transfer | — (built-in) |
| **dig** | DNS lookup utility | — (bind-utils) |
| **whois** | Domain registration query tool | https://whois.domaintools.com |

---

## 5. OSINT & Intelligence Sources

| Sumber | Deskripsi | URL |
|--------|-----------|-----|
| **Certificate Transparency Logs** | Log publik semua sertifikat SSL/TLS yang diterbitkan | https://crt.sh |
| **MerkleMap** | Alternatif CT log search | https://www.merklemap.com |
| **Censys** | Internet-wide scan data dan certificate search | https://search.censys.io |
| **DomainTools / WHOIS** | Domain registration intelligence | https://whois.domaintools.com |
| **Wayback Machine** | Arsip historis web untuk menemukan endpoint lama dan perubahan infrastruktur | https://web.archive.org |
| **LinkedIn** | OSINT sumber informasi karyawan, teknologi, dan struktur organisasi | https://linkedin.com |
| **GitHub** | Source code repositories, secret exposure, developer intelligence | https://github.com |
| **Google Hacking Database (GHDB)** | Kumpulan Google dork queries untuk information disclosure | https://www.exploit-db.com/google-hacking-database |
| **CrowdStrike Global Threat Report** | Laporan tahunan threat intelligence — pola APT dan attack trends | https://www.crowdstrike.com/global-threat-report/ |
| **DNS Lookup Tools** | Kloth.net online DNS lookup | https://www.kloth.net/services/nslookup.php |

---

## 6. Threat Reports & Publikasi Industri

| Publikasi | Organisasi | Relevansi |
|-----------|-----------|-----------|
| **CrowdStrike Global Threat Report** | CrowdStrike | Pola APT, statistik reconnaissance phase dalam serangan modern |
| **MITRE ATT&CK Evaluations** | MITRE | Evaluasi technique sequences dan attack chains |
| **OWASP Top 10** | OWASP Foundation | Referensi vulnerability classification untuk web application |

---

## 7. Konsep & Metodologi Kunci

### 7.1 Model & Teori

| Konsep | Pencetus | Tahun | Deskripsi |
|--------|---------|-------|-----------|
| **Attack Trees** | Bruce Schneier | 1999 | Model hierarkis formal untuk analisis keamanan — root node = objective, child nodes = sub-goals dengan relasi AND/OR |
| **Cyber Kill Chain** | Lockheed Martin | 2011 | Model 7 fase yang memetakan lifecycle serangan siber |
| **Scoring Matrix (5 Dimensi)** | Berdasarkan PTES/OWASP | — | Prioritisasi entry point: Exploit Reliability, Access Level, Detection Risk, Prerequisites, Time to Exploit |
| **Source Diversification** | Intelligence tradecraft | — | Prinsip menggunakan multiple source IPs dan collection methods untuk menghindari deteksi |
| **Threshold-based Detection** | IDS/IPS methodology | — | Metode deteksi berdasarkan ambang batas traffic volume per source dalam periode waktu |

### 7.2 Teknik Evasion (IDS/IPS/Firewall)

| Teknik | Deskripsi | Dasar |
|--------|-----------|-------|
| **Fragmentasi IP** | Pemecahan paket berdasarkan RFC 791 untuk menghindari signature matching | RFC 791 |
| **Decoys** | Pengiriman probes dari multiple source IPs (real + spoofed) | Nmap `-D` |
| **Timing Control** | Pengaturan kecepatan scanning di bawah threshold deteksi | Nmap `-T0` s/d `-T5` |
| **Source Port Manipulation** | Penggunaan trusted source ports (53/DNS, 80/HTTP, 443/HTTPS) | Nmap `-g` |
| **Encoding/Case Variation** | Nikto IDS evasion techniques | Nikto `-evasion` |

---

## 8. Lab Environment & Technology Stack

### 8.1 Infrastruktur Lab

| Komponen | Spesifikasi | Fungsi |
|----------|------------|--------|
| **Kali Linux** | Attacker machine | Seluruh tools offsec terinstal |
| **Ubuntu Server 22.04** | Target machine | Hosting vulnerable web application |
| **NAT Network** | 10.10.2.0/24 | Isolasi jaringan lab |
| **VirtualBox** | Hypervisor | Virtualisasi kedua VM |

### 8.2 Target Application (VulnShop / BootCamp-Lab)

| Teknologi | Detail |
|-----------|--------|
| **Python / Flask** | Backend framework web application |
| **SQLite** | Database (vulnerable to SQL injection) |
| **Jinja2** | Template engine |
| **Werkzeug** | WSGI server (development) |
| **Docker** | Container deployment (opsional) |

### 8.3 Vulnerable Endpoints

| Endpoint | Vulnerability | CWE |
|----------|--------------|-----|
| `/login` | SQL Injection (auth bypass), brute-force, username enumeration | CWE-89, CWE-307, CWE-204 |
| `/search` | SQL Injection (UNION-based data extraction) | CWE-89 |
| `/ping` | OS Command Injection | CWE-78 |
| `/upload` | Unrestricted File Upload | CWE-434 |
| `/debug` | Information Disclosure (SECRET_KEY, config) | CWE-200 |
| `/about` | System Information Disclosure | CWE-200 |
| `/admin` | Broken Access Control | CWE-284 |
| `/dns_lookup` | OS Command Injection | CWE-78 |

---

## 9. Wordlists & Resources

| Resource | Lokasi / URL | Penggunaan |
|----------|-------------|------------|
| **SecLists** | `/usr/share/seclists/` | Comprehensive wordlist collection |
| **SecLists — DNS Subdomain** | `Discovery/DNS/subdomains-top1million-20000.txt` | DNS brute-force |
| **SecLists — SNMP** | `Discovery/SNMP/snmp-onesixtyone.txt` | SNMP community string brute-force |
| **SecLists — Web Content** | `Discovery/Web-Content/raft-medium-directories.txt` | Directory brute-force |
| **SecLists — Burp Parameters** | `Discovery/Web-Content/burp-parameter-names.txt` | Parameter discovery |
| **SecLists — Usernames** | `Usernames/top-usernames-shortlist.txt` | Username brute-force |
| **Dirb Common** | `/usr/share/wordlists/dirb/common.txt` | Basic content discovery |

---

## 10. Pemetaan Referensi per Chapter

### Chapter 1 — Lab Setup
- VirtualBox NAT Network configuration
- Kali Linux & Ubuntu Server deployment

### Chapter 2 — Reconnaissance Basic
- **Frameworks:** PTES (fase 1), NIST SP 800-115, MITRE ATT&CK (Reconnaissance tactic), OSSTMM 3, Cyber Kill Chain
- **RFC:** RFC 3912 (WHOIS), RFC 1035 (DNS)
- **Tools:** whois, dig, amass, subfinder, gobuster, crt.sh, Shodan, Google Dorking, theHarvester, waybackurls, gitleaks, Nmap
- **Konsep:** Source diversification, passive vs active reconnaissance, OPSEC, IDS/IPS evasion (fragmentasi, decoys, timing, source port manipulation)
- **Sumber:** CrowdStrike Global Threat Report, Certificate Transparency Logs, Wayback Machine

### Chapter 3 — Enumeration and Attack Mapping
- **Frameworks:** PTES, OWASP, NIST SP 800-115, MITRE ATT&CK
- **RFC:** RFC 4253 (SSH), RFC 2616/7230-7235 (HTTP), RFC 2818 (HTTPS), RFC 1157/3416 (SNMP)
- **Tools:** enum4linux, smbclient, smbmap, CrackMapExec, ssh-audit, WhatWeb, Nikto, Gobuster, Feroxbuster, ffuf, Arjun, wafw00f, curl, snmpwalk, onesixtyone, smtp-user-enum
- **Konsep:** Attack Trees (Bruce Schneier, 1999), Scoring Matrix (5 dimensi), Attack Surface Mapping

### Chapter 4 — Web Application Exploitation and Security
- **CWE:** CWE-89 (SQLi), CWE-78 (Command Injection), CWE-307 (No Rate Limiting), CWE-204 (Username Enumeration), CWE-614 (Insecure Cookie)
- **Tools:** SQLMap (Bernardo Damele & Miroslav Stampar, 2006), Hydra, curl
- **Konsep:** UNION-based SQLi, blind SQLi (boolean/time-based), auth bypass, OS metacharacters, session analysis, credential attacks, rate limiting bypass techniques

---

## 11. Sumber Tambahan (Recommended Reading)

| Judul | Penulis/Sumber | Topik |
|-------|---------------|-------|
| *The Web Application Hacker's Handbook* | Dafydd Stuttard, Marcus Pinto | Web application security testing |
| *Penetration Testing* | Georgia Weidman | Hands-on penetration testing methodology |
| *RTFM: Red Team Field Manual* | Ben Clark | Quick reference untuk red team operators |
| *OWASP Testing Guide v4* | OWASP Foundation | Comprehensive web security testing guide |
| *Nmap Network Scanning* | Gordon Lyon (Fyodor) | Official Nmap reference guide |
| *MITRE ATT&CK Documentation* | MITRE Corporation | Threat-informed defense knowledge base |
| *NIST Cybersecurity Framework* | NIST | Risk management framework |

---

