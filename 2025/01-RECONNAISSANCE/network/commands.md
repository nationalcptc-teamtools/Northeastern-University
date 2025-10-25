# Network Reconnaissance

## Network Discovery

### Find Live Hosts

```bash
# Ping sweep (fast)
nmap -sn 10.10.10.0/24 -oG live_hosts.txt

# Extract IPs
grep "Up" live_hosts.txt | cut -d' ' -f2 > targets.txt

# Verify count
wc -l targets.txt
```

### Port Scanning

**Quick scan (top 1000 ports):**
```bash
nmap -iL targets.txt -oA quick_scan
```

**Comprehensive scan (all ports):**
```bash
# Start in background
nmap -p- -sV -sC -iL targets.txt -oA full_scan 

# Check progress
tail -f full_scan.nmap
```

**UDP scan (important but slow):**
```bash
# Top 100 UDP ports
sudo nmap -sU --top-ports 100 -iL targets.txt -oA udp_scan

# Specific UDP services
sudo nmap -sU -p 53,67,68,69,123,135,137,138,139,161,162,445,500,514,520,631,1434,1900,4500,49152 -iL targets.txt
```

---

## Service-Specific Enumeration

### SMB/NetBIOS (Ports 139, 445)

```bash
# Quick SMB scan
netexec smb 10.10.10.0/24

# Check for signing
netexec smb 10.10.10.0/24 --gen-relay-list relay_targets.txt

# Null session enumeration
netexec smb 10.10.10.0/24 -u '' -p '' --shares

# Nmap SMB scripts
nmap -p445 --script smb-protocols,smb-security-mode,smb-os-discovery,smb-enum-shares TARGET
```

### SNMP (Port 161/UDP)

```bash
# Find SNMP hosts
sudo nmap -sU -p 161 --open 10.10.10.0/24 -oG snmp_hosts.txt

# Test default community strings
for ip in $(grep open snmp_hosts.txt | cut -d' ' -f2); do
    echo "[*] Testing $ip"
    snmpwalk -v2c -c public $ip | head -20
done

# Full enumeration
snmpwalk -v2c -c public TARGET > snmp_full.txt

# Search for credentials
grep -i "password\|credential\|secret" snmp_full.txt
```

### DNS (Port 53)

```bash
# DNS enumeration
nmap -p53 --script dns-nsid,dns-recursion TARGET

# Try zone transfer
dig axfr @TARGET DOMAIN.LOCAL

# Using dnsrecon
dnsrecon -d DOMAIN.LOCAL -n TARGET -t axfr
```

### NFS (Port 2049)

```bash
# Find NFS servers
nmap -p 111,2049 --open 10.10.10.0/24

# Show exports
showmount -e TARGET

# Nmap NFS scripts
nmap -p 111 --script nfs-ls,nfs-statfs,nfs-showmount TARGET
```

### RDP (Port 3389)

```bash
# Check RDP
nmap -p3389 --script rdp-enum-encryption,rdp-vuln-ms12-020 TARGET

# Test for NLA (Network Level Authentication)
netexec rdp TARGET
```

---

## Vulnerability Scanning

### Nmap Vulnerability Scripts

```bash
# Safe vulnerability scripts
nmap -p- --script vuln-safe TARGET

# Specific checks
nmap -p445 --script smb-vuln-ms17-010 TARGET  # EternalBlue
nmap -p22 --script ssh-auth-methods TARGET
nmap -p80,443 --script http-vuln* TARGET

# All vuln scripts (use carefully)
nmap --script vuln TARGET
```

### Network-Wide Vulnerability Assessment

```bash
# Quick vulnerability baseline
nmap -iL targets.txt --script vuln-safe -oA vuln_scan

# Check for common Windows vulns
nmap -p445 --script smb-vuln* 10.10.10.0/24

# Check for common web vulns  
nmap -p80,443,8080,8443 --script http-vuln* 10.10.10.0/24
```

---

## Network Mapping

### Identify Network Segments

```bash
# From compromised host, discover other networks
ip route
route print  # Windows

# ARP table shows local network neighbors
arp -a
ip neighbor  # Linux

# Look for dual-homed systems (2+ interfaces)
# These are pivot points
```

### Network Topology Discovery

```bash
# Traceroute to understand routing
traceroute TARGET

# TCP traceroute (if ICMP blocked)
tcptraceroute TARGET

# Identify firewalls/filtering
hping3 -S -p 80 TARGET
```

---

## Credential Discovery

### Default Credentials Testing

**Common defaults by service:**
```bash
# SMB/Windows
administrator:administrator
admin:admin
guest:(blank)

# MySQL
root:(blank)
root:root
root:password
root:toor

# MSSQL
sa:(blank)
sa:sa
sa:password

# PostgreSQL
postgres:postgres
postgres:password

# SSH
root:root
root:toor
admin:admin

# Web apps
admin:admin
admin:password
administrator:administrator
```

**Automated testing:**
```bash
# Test across network
netexec smb 10.10.10.0/24 -u admin -p admin
netexec mssql 10.10.10.0/24 -u sa -p sa
```

### Passive Credential Harvesting

```bash
# Responder (captures authentication attempts)
sudo responder -I eth0 -wv

# Wait for:
# - LLMNR/NBT-NS broadcasts
# - SMB authentication attempts
# - HTTP basic auth

# Captured hashes go to:
/usr/share/responder/logs/
```

---

## Network Service Enumeration

### Port-to-Tool Mapping

```bash
# Port 21 (FTP)
nmap -p21 --script ftp-anon,ftp-bounce,ftp-libopie TARGET

# Port 22 (SSH)
ssh-audit TARGET
nc TARGET 22  # Banner grab

# Port 23 (Telnet)
telnet TARGET

# Port 25 (SMTP)
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -t TARGET

# Port 53 (DNS)
dig axfr @TARGET DOMAIN.LOCAL
dnsrecon -d DOMAIN.LOCAL -n TARGET

# Port 80/443 (HTTP/HTTPS)
whatweb http://TARGET
nikto -h http://TARGET
gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt

# Port 88 (Kerberos)
# Indicates Domain Controller
netexec smb TARGET  # Verify domain

# Port 110 (POP3)
nc TARGET 110

# Port 111 (RPCBind)
rpcinfo -p TARGET

# Port 135 (MSRPC)
rpcdump.py TARGET

# Port 139/445 (SMB)
netexec smb TARGET
enum4linux-ng TARGET
smbclient -L //TARGET -N

# Port 161 (SNMP)
snmpwalk -v2c -c public TARGET

# Port 389/636 (LDAP/LDAPS)
ldapsearch -x -H ldap://TARGET -b "dc=domain,dc=local"

# Port 1433 (MSSQL)
netexec mssql TARGET
impacket-mssqlclient sa@TARGET

# Port 2049 (NFS)
showmount -e TARGET

# Port 3306 (MySQL)
mysql -h TARGET -u root

# Port 3389 (RDP)
netexec rdp TARGET
nmap -p3389 --script rdp-enum-encryption TARGET

# Port 5432 (PostgreSQL)
psql -h TARGET -U postgres

# Port 5985/5986 (WinRM)
netexec winrm TARGET
evil-winrm -i TARGET -u USERNAME -p 'PASSWORD'

# Port 6379 (Redis)
redis-cli -h TARGET ping

# Port 8080 (HTTP-Proxy)
# Same as port 80/443
```

---

## Documentation During Reconnaissance

### What to Document

**For GhostWriter, create findings for:**

**Informational (document baseline):**
- Open ports per system
- Service versions
- Operating systems
- Network topology

**Low severity:**
- Banner disclosure
- Directory listing
- Information disclosure

**Medium severity:**
- Unencrypted protocols (HTTP vs HTTPS, Telnet vs SSH)
- Weak SSL/TLS
- Default installations (Tomcat examples, IIS defaults)

**High/Critical:**
- Default credentials
- Anonymous access (FTP, SMB, LDAP)
- Missing authentication (Redis, MongoDB)
- SMB signing disabled

### Evidence to Collect

**During reconnaissance, capture:**
- nmap output showing versions
- Service banners
- Directory listing screenshots
- Default page screenshots
- Configuration disclosure
- Error messages

---

## Time-Saving Tips

### Background Tasks

```bash
# Long-running tasks in background
nmap -p- 10.10.10.0/24 -oA full_scan 
autorecon -t targets.txt 
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt 

# Check what's running
jobs
```
---

