# Linux Service Reconnaissance - Pure Enumeration

---

## Network Service Discovery

### Port Scanning
```bash
# Quick TCP scan
nmap -p- --min-rate=1000 -T4 TARGET -oN tcp_scan.txt

# Service version detection
nmap -p- -sV -sC TARGET -oA detailed_scan

# UDP scan (slower but important)
sudo nmap -sU --top-ports 100 TARGET -oN udp_scan.txt
```

### Service Banner Grabbing
```bash
# Manual banner grab
nc -nv TARGET 22  # SSH
nc -nv TARGET 21  # FTP
nc -nv TARGET 25  # SMTP
nc -nv TARGET 80  # HTTP

# Automated
nmap -sV --script=banner TARGET
```

---

## SSH Enumeration

### Version and Configuration
```bash
# Get SSH version
ssh TARGET
nc TARGET 22

# Detailed SSH enumeration
nmap -p22 --script ssh-hostkey,ssh-auth-methods TARGET

# Check for user enumeration vulnerability
ssh-audit TARGET
```

---

## NFS Enumeration

### Discover NFS Exports
```bash
# Check if NFS is running
nmap -p 111,2049 TARGET

# Show exported shares
showmount -e TARGET

# Detailed NFS enumeration
nmap -p 111 --script nfs-ls,nfs-statfs,nfs-showmount TARGET
```

### What to Look For
- `/home` exports (SSH keys!)
- `/root` exports (everything!)
- `no_root_squash` option (privilege escalation opportunity)
- World-readable exports (`*` in client list)

---

## SNMP Enumeration

### Discovery
```bash
# Find SNMP hosts
sudo nmap -sU -p 161 --open 10.10.10.0/24 -oG snmp_hosts.txt

# Extract IPs
grep open snmp_hosts.txt | cut -d' ' -f2 > snmp_targets.txt
```

### Information Gathering
```bash
# Try default community string
snmpwalk -v1 -c public TARGET | tee snmp_v1.txt
snmpwalk -v2c -c public TARGET | tee snmp_v2c.txt

# Try other common community strings
for community in public private manager; do
    echo "[*] Trying community: $community"
    snmpwalk -v2c -c $community TARGET | head -20
done
```

### High-Value Information (Save All Output)
```bash
# System information
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.1 > snmp_system.txt

# Running processes
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.25.4.2.1.5 > snmp_processes.txt

# Installed software
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.25.6.3.1.2 > snmp_software.txt

# User accounts
snmpwalk -v2c -c public TARGET 1.3.6.1.4.1.77.1.2.25 > snmp_users.txt

# Network interfaces
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.4.20.1.1 > snmp_network.txt

# Storage devices
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.25.2.3.1.3 > snmp_storage.txt

# Save everything
snmpwalk -v2c -c public TARGET > snmp_full.txt
```

### Analysis (What to Note)
```bash
# Search for sensitive information in output
grep -i "password\|passwd\|pwd\|credential\|secret\|key" snmp_full.txt

# Look for script names
grep -i "\.sh\|\.py\|\.pl\|backup\|reset\|admin" snmp_full.txt

# Process command lines often contain passwords
grep -i "ssh\|mysql\|psql\|ftp\|--password\|-p\s" snmp_processes.txt
```

**Document findings, note for exploitation phase.**

---

## Database Service Enumeration

### MySQL/MariaDB
```bash
# Check if MySQL is accessible
nmap -p3306 --script mysql-info TARGET

# Attempt connection (no password)
mysql -h TARGET -u root 2>&1

# Check for anonymous access
mysql -h TARGET 2>&1

# Note the error messages - they reveal information
```

### PostgreSQL
```bash
# Check PostgreSQL
nmap -p5432 --script pgsql-brute TARGET

# Attempt connection
psql -h TARGET -U postgres 2>&1

# List databases (if accessible)
psql -h TARGET -U postgres -l
```

### Redis
```bash
# Check Redis
nmap -p6379 --script redis-info TARGET

# Test for authentication
redis-cli -h TARGET ping 2>&1
# "PONG" = no authentication!
# Error = authentication required

# If no auth, enumerate (but don't exploit)
redis-cli -h TARGET INFO
redis-cli -h TARGET CONFIG GET dir
```

### MongoDB
```bash
# Check MongoDB
nmap -p27017 --script mongodb-info,mongodb-databases TARGET

# Connect without authentication
mongosh --host TARGET --eval "db.adminCommand('listDatabases')"
```

---

## SMB/Samba Enumeration

### Anonymous/Null Session Enumeration
```bash
# Check for null sessions
netexec smb TARGET -u '' -p ''

# Guest account
netexec smb TARGET -u 'guest' -p ''

# Enum4linux (comprehensive)
enum4linux-ng TARGET -A

# SMB shares without authentication
smbclient -L //TARGET -N
smbmap -H TARGET -u null
```

### SMB Enumeration (With Credentials)
```bash
# List shares
netexec smb TARGET -u USERNAME -p 'PASSWORD' --shares

# Detailed share permissions
smbmap -H TARGET -u USERNAME -p 'PASSWORD' -r

# Connect to specific share
smbclient //TARGET/SHARE -U "USERNAME%PASSWORD"
```

**List what shares exist, what permissions they have**

---

## FTP Enumeration

### Check for Anonymous Access
```bash
# Nmap script
nmap -p21 --script ftp-anon,ftp-bounce TARGET

# Manual check
ftp TARGET
# Username: anonymous
# Password: (blank or email)

# List files if anonymous works
ftp TARGET
anonymous
ls -la
pwd
bye
```

**Note if anonymous access exists, what files are visible**

---

## Web Service Enumeration

### Technology Identification
```bash
# WhatWeb
whatweb http://TARGET -a 3

# Curl headers
curl -I http://TARGET

# Nmap HTTP scripts
nmap -p80,443 --script http-methods,http-headers,http-title,http-server-header TARGET
```

### Check for Information Disclosure
```bash
# Common files (just check if they exist)
curl -s http://TARGET/robots.txt | head -20
curl -s http://TARGET/.git/config | head -20
curl -s http://TARGET/.env | head -10
curl -s http://TARGET/phpinfo.php | head -20

# Directory listing
curl -s http://TARGET/ | grep -i "index of"
```

---

## SMTP Enumeration

### User Enumeration
```bash
# VRFY method
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -t TARGET

# RCPT TO method  
smtp-user-enum -M RCPT -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -t TARGET

# EXPN method
smtp-user-enum -M EXPN -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -t TARGET
```

**Save discovered usernames for later password attacks.**

---

## RPC Enumeration

### RPC Service Discovery
```bash
# Show all RPC services
rpcinfo -p TARGET

# Check for NFS via RPC
rpcinfo -p TARGET | grep nfs

# RPC dump
rpcdump.py TARGET
```

---

## LDAP Enumeration (If Present)

### Anonymous LDAP Queries
```bash
# Anonymous bind
ldapsearch -x -H ldap://TARGET -b "" -s base

# Try to enumerate domain
ldapsearch -x -H ldap://TARGET -b "dc=domain,dc=local"
```

**Document if anonymous access works. Authenticated enumeration comes later**

---

## OS Fingerprinting

### Identify Linux Distribution
```bash
# Nmap OS detection
sudo nmap -O TARGET

# SSH banner analysis
nc TARGET 22

# HTTP server headers
curl -I http://TARGET | grep "Server:"

# Service banner patterns
# Ubuntu: OpenSSH 7.6p1 Ubuntu-4ubuntu0.3
# CentOS: OpenSSH 7.4
# Debian: OpenSSH 7.9p1 Debian-10+deb10u2
```

---

## Complete Linux Enumeration Workflow

### Step-by-Step 

**Port Discovery**
```bash
nmap -p- --min-rate=1000 TARGET -oN ports.txt
```

**Service Enumeration**
```bash
# For each discovered service, run appropriate enumeration
# SSH: ssh-audit
# HTTP: whatweb, curl for common files
# SMB: enum4linux-ng
# NFS: showmount
# SNMP: snmpwalk
# Databases: connection attempts to check auth
```

**Information Analysis**
```bash
# Review all output
# Note:
# - Services with no authentication
# - Default credentials possibilities
# - Information disclosure
# - Version numbers (for exploit research)
```

**Documentation**
```bash
# Create findings for:
# - Open ports (informational)
# - Services without authentication
# - Information disclosure
# - Weak configurations

# Note for exploitation phase:
# - Which services to target first
# - Potential quick wins
# - Areas needing manual testing
```

---

## Output Organization

### Save All Enumeration Results
```bash
# Create directory structure per host
mkdir -p ~/pentest/recon/TARGET/{nmap,services,web,smb,snmp}

# Save results organized
nmap output → ~/pentest/recon/TARGET/nmap/
enum4linux → ~/pentest/recon/TARGET/smb/
snmpwalk → ~/pentest/recon/TARGET/snmp/
gobuster → ~/pentest/recon/TARGET/web/
```
---