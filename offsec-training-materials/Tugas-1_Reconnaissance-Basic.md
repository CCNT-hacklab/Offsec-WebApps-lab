# TUGAS HARIAN 1: RECONNAISSANCE BASIC

---

> **Referensi:** Man Behind the Hat — (Reconnaissance Basic)
> **Prasyarat:** Lab environment aktif (Kali Linux + Ubuntu Server pada segmen 10.10.2.0/24)
> **Deliverable:** Laporan reconnaissance dalam format markdown atau PDF

---

## Objective

Peserta mampu melakukan **passive dan active reconnaissance** secara metodologis terhadap target lab, menghasilkan **intelligence report** yang komprehensif sebagai fondasi untuk fase exploitation.

---

## Bagian A: Passive Reconnaissance (90 menit)

### Task A1 — WHOIS & Domain Intelligence (20 menit)

**Konteks:** Sebelum menyentuh target, kumpulkan informasi dari sumber publik.

**Instruksi:**

1. Pilih **satu domain publik** yang diizinkan untuk reconnaissance pasif (contoh: `scanme.nmap.org`, `testphp.vulnweb.com`, atau domain lab jika tersedia).

2. Lakukan WHOIS lookup dan dokumentasikan:
   ```bash
   whois <target_domain>
   ```

3. **Identifikasi dan catat** informasi berikut dalam format tabel:

   | Data Point | Nilai yang Ditemukan | Intelligence Value |
   |-----------|---------------------|-------------------|
   | Registrant Organization | | |
   | Registrant Email | | |
   | Name Servers | | |
   | Creation Date | | |
   | Update Date | | |
   | Registrar | | |

4. **Jawab Saya:**
   - Apakah name server internal (self-hosted) atau menggunakan cloud provider?
   - Apa implikasi keamanan dari pola email yang ditemukan?
   - Apakah ada indikasi perubahan infrastruktur terkini dari update date?

---

### Task A2 — DNS Intelligence & Zone Transfer (25 menit)

**Instruksi:**

1. Lakukan **comprehensive DNS enumeration** terhadap domain target:

   ```bash
   # A Record (IPv4)
   dig A <target_domain> +short

   # AAAA Record (IPv6)
   dig AAAA <target_domain> +short

   # Name Servers
   dig NS <target_domain> +short

   # Mail Servers
   dig MX <target_domain> +short

   # TXT Records (SPF, DKIM, DMARC)
   dig TXT <target_domain> +short
   ```

2. **Percobaan Zone Transfer:**
   ```bash
   # Identifikasi name servers
   dig NS <target_domain> +short

   # Coba zone transfer dari setiap NS
   dig axfr <target_domain> @<nameserver_1>
   dig axfr <target_domain> @<nameserver_2>
   ```

3. **Dokumentasikan** semua DNS records yang ditemukan dalam tabel:

   | Record Type | Value | Intelligence Analysis |
   |------------|-------|----------------------|
   | A | | |
   | AAAA | | |
   | NS | | |
   | MX | | |
   | TXT (SPF) | | |
   | TXT (DMARC) | | |

4. **Jawab Saya:**
   - Apakah zone transfer berhasil? Jika ya, informasi apa yang terungkap?
   - Apakah email menggunakan layanan cloud (Google Workspace, O365) atau self-hosted?
   - Bagaimana SPF/DMARC configuration — apakah rentan terhadap email spoofing?

---

### Task A3 — Subdomain Discovery (25 menit)

**Instruksi:**

1. Gunakan **minimal 3 metode berbeda** untuk subdomain enumeration:

   ```bash
   # Method 1: Certificate Transparency Logs
   curl -s "https://crt.sh/?q=%25.<target_domain>&output=json" | \
       jq -r '.[].name_value' | sort -u | tee ct_subdomains.txt

   # Method 2: Subfinder (passive)
   subfinder -d <target_domain> -silent -o subfinder_subdomains.txt

   # Method 3: DNS Brute-force
   gobuster dns -d <target_domain> -w \
       /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
       -o bruteforce_subdomains.txt
   ```

2. **Kombinasikan dan deduplikasi** hasil:
   ```bash
   cat ct_subdomains.txt subfinder_subdomains.txt bruteforce_subdomains.txt | \
       sort -u > all_subdomains.txt
   echo "Total unique subdomains: $(wc -l < all_subdomains.txt)"
   ```

3. **Verifikasi subdomain yang aktif** (jika diizinkan):
   ```bash
   cat all_subdomains.txt | httpx -silent -status-code -title -o live_subdomains.txt
   ```

4. **Deliverable:** Daftar subdomain lengkap beserta analisis mana yang berpotensi menjadi attack surface (staging, dev, old, admin, api, dll).

---

### Task A4 — OSINT & Technology Fingerprinting (20 menit)

**Instruksi:**

1. **Google Dorking** — jalankan minimal 5 dork query terhadap target:
   ```
   site:<target_domain> intitle:"login" OR intitle:"admin"
   site:<target_domain> filetype:pdf OR filetype:xlsx OR filetype:docx
   site:<target_domain> filetype:env OR filetype:config OR filetype:yml
   site:<target_domain> "powered by" OR "running on"
   site:<target_domain> intitle:"index of" "parent directory"
   ```

2. **Shodan lookup** (jika IP diketahui):
   ```bash
   shodan host <target_IP>
   ```

3. **Wayback Machine** — cari perubahan historis:
   ```bash
   waybackurls <target_domain> > wayback_urls.txt
   cat wayback_urls.txt | grep -iE "admin|login|config|backup|api|debug" | sort -u
   ```

4. **Dokumentasikan** temuan OSINT dalam format:

   | Sumber | Temuan | Relevansi |
   |--------|--------|----------|
   | Google Dork | | |
   | Shodan | | |
   | Wayback Machine | | |

---

## Bagian B: Active Reconnaissance (90 menit)

### Task B1 — Host Discovery (20 menit)

**Target:** Segmen jaringan lab 10.10.2.0/24

**Instruksi:**

1. Lakukan host discovery menggunakan **3 metode berbeda**:

   ```bash
   # Method 1: ARP Discovery (paling reliable di local network)
   sudo nmap -sn -PR 10.10.2.0/24 -oG discovery_arp.txt

   # Method 2: Multi-method discovery
   sudo nmap -sn -PE -PS80,443,22 -PA80,443 -PU53 10.10.2.0/24 -oA discovery_multi

   # Method 3: Ping sweep
   sudo nmap -sn 10.10.2.0/24 -oG discovery_ping.txt
   ```

2. **Ekstrak live hosts:**
   ```bash
   grep "Status: Up" discovery_arp.txt | awk '{print $2}' > live_hosts.txt
   echo "Live hosts found: $(wc -l < live_hosts.txt)"
   cat live_hosts.txt
   ```

3. **Jawab Saya:**
   - Berapa host yang ditemukan aktif?
   - Metode mana yang menemukan host paling banyak? Mengapa?
   - Adakah host yang hanya terdeteksi oleh satu metode saja?

---

### Task B2 — Port Scanning (30 menit)

**Target:** Ubuntu Server lab (10.10.2.x)

**Instruksi:**

1. **Quick scan** — top 1000 ports:
   ```bash
   sudo nmap -sS -T4 --top-ports 1000 <target_IP> -oA scan_quick
   ```

2. **Full TCP scan** — semua 65535 ports:
   ```bash
   sudo nmap -sS -p- -T4 <target_IP> -oA scan_full_tcp
   ```

3. **UDP scan** — top 100 ports:
   ```bash
   sudo nmap -sU --top-ports 100 <target_IP> -oA scan_udp
   ```

4. **Version detection** pada open ports:
   ```bash
   OPEN_PORTS=$(grep "open" scan_full_tcp.gnmap | grep -oP '\d+/open' | \
       cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')
   sudo nmap -sV -sC -p$OPEN_PORTS <target_IP> -oA scan_versions
   ```

5. **OS Detection:**
   ```bash
   sudo nmap -O --osscan-guess <target_IP> -oA scan_os
   ```

6. **Dokumentasikan** hasil dalam tabel:

   | Port | State | Service | Version | Catatan |
   |------|-------|---------|---------|---------|
   | | | | | |

7. **Jawab Saya:**
   - Port mana yang paling menarik untuk exploitation? Mengapa?
   - Apakah ada perbedaan antara quick scan dan full scan? Service apa yang terlewat?
   - Apa OS yang teridentifikasi? Bagaimana confidence level-nya?

---

### Task B3 — IDS/Firewall Evasion Techniques (20 menit)

**Instruksi:**

Praktikkan minimal **3 teknik evasion** dan bandingkan hasilnya:

1. **Fragmentasi paket:**
   ```bash
   sudo nmap -f <target_IP> -p 22,80,443 -oN evasion_fragment.txt
   sudo nmap --mtu 16 <target_IP> -p 22,80,443 -oN evasion_mtu.txt
   ```

2. **Decoys:**
   ```bash
   sudo nmap -D RND:10 <target_IP> -p 22,80,443 -oN evasion_decoy.txt
   ```

3. **Timing manipulation:**
   ```bash
   sudo nmap -T2 -sS <target_IP> -p 22,80,443 --scan-delay 500ms -oN evasion_timing.txt
   ```

4. **Source port manipulation:**
   ```bash
   sudo nmap -g 53 <target_IP> -p 22,80,443 -oN evasion_srcport.txt
   ```

5. **Jawab Saya:**
   - Apakah hasil scan berbeda antar teknik? Jika ya, mengapa?
   - Teknik mana yang paling efektif untuk menghindari deteksi?
   - Dalam skenario real-world, timing template berapa yang sesuai untuk engagement yang memerlukan stealth?

---

### Task B4 — Network Topology Mapping (20 menit)

**Instruksi:**

1. **Traceroute:**
   ```bash
   traceroute <target_IP>
   sudo nmap -sS --traceroute <target_IP> -oA trace_results
   ```

2. **Kompilasi semua hasil scan** menjadi network map:
   ```bash
   cat scan_quick.nmap scan_full_tcp.nmap scan_udp.nmap scan_versions.nmap
   ```

3. **Buat network topology diagram** (format teks atau gambar) yang mencakup:
   - Semua live hosts yang ditemukan
   - Open ports dan services per host
   - Hubungan antar host (gateway, routing)
   - Potential entry points yang diidentifikasi

4. **Format diagram:**
   ```
   [Kali Linux]                    [Ubuntu Server]
   10.10.2.x                       10.10.2.x
   (Attacker)                      (Target)
       |                               |
       |--- Port 22 (SSH vX.X) --------|
       |--- Port 80 (HTTP/Nginx) ------|
       |--- Port XX (Service) ---------|
       |                               |
       └──────── 10.10.2.0/24 ─────────┘
   ```

---

## Bagian C: Deliverable & Laporan (60 menit)

### Instruksi Penulisan Laporan

Buat **Reconnaissance Report** dalam format markdown dengan struktur berikut:

```markdown
# RECONNAISSANCE REPORT
## Target: [nama/IP target]
## Tanggal: [tanggal pengerjaan]
## Operator: [nama peserta]

---

## 1. Executive Summary
- Ringkasan temuan utama (3-5 bullet points)
- Overall attack surface assessment

## 2. Methodology
- Tools yang digunakan
- Teknik passive vs active
- OPSEC considerations yang diterapkan

## 3. Passive Reconnaissance Findings
### 3.1 WHOIS Intelligence
### 3.2 DNS Intelligence
### 3.3 Subdomain Discovery
### 3.4 OSINT Findings

## 4. Active Reconnaissance Findings
### 4.1 Host Discovery Results
### 4.2 Port Scan Results
### 4.3 Service & Version Detection
### 4.4 OS Fingerprinting
### 4.5 Evasion Technique Results

## 5. Network Topology Map

## 6. Identified Entry Points (Prioritized)

| # | Entry Point | Service | Priority | Reasoning |
|---|------------|---------|----------|-----------|
| 1 | | | HIGH | |
| 2 | | | MEDIUM | |
| 3 | | | LOW | |

## 7. Hipotesis Serangan
- Berdasarkan temuan, vektor serangan apa yang paling memungkinkan?
- Service mana yang menjadi prioritas untuk enumeration lanjutan?

## 8. Rekomendasi untuk Fase Berikutnya
```

---

## Rubrik Penilaian

| Kriteria | Bobot | Deskripsi |
|----------|-------|-----------|
| **Kelengkapan Passive Recon** | 20% | Semua task A1-A4 dikerjakan dengan output lengkap |
| **Kelengkapan Active Recon** | 25% | Semua task B1-B4 dikerjakan, semua scan types dilakukan |
| **Analisis & Interpretasi** | 25% | Jawab Saya dijawab dengan pemahaman mendalam |
| **Network Topology Map** | 10% | Diagram akurat dan informatif |
| **Kualitas Laporan** | 15% | Struktur profesional, temuan terdokumentasi dengan bukti |
| **OPSEC Awareness** | 5% | Menunjukkan kesadaran tentang operational security |
| **Total** | **100%** | **70+ = Pass** |

---

## Catatan Penting

1. **Hanya lakukan scanning terhadap target lab yang diizinkan** (10.10.2.0/24)
2. **Passive reconnaissance** terhadap domain publik harus menggunakan domain yang diperuntukkan untuk testing
3. **Simpan semua output** scan dalam direktori terorganisir: `~/recon/<target>/`
4. **Screenshot** setiap langkah penting sebagai bukti
5. Terapkan prinsip **OPSEC** yang dipelajari di materi (VPN, rate limiting, timing)

---

*Referensi: Man Behind the Hat — (Reconnaissance Basic), Section 2.1-2.3*
