# AutoRecon Setup & Usage Guide

**AutoRecon by Tiberius - Automated multi-threaded reconnaissance**

---

## What AutoRecon Does

AutoRecon automatically performs comprehensive enumeration on discovered hosts:

**For EACH service found:**
- Runs appropriate enumeration tools automatically
- Organizes output into logical folders
- Captures screenshots of web services
- Suggests manual follow-up commands
- Runs in parallel across multiple hosts

---

## Installation

### Method 1: pip (Recommended)

```bash
# Install dependencies
sudo apt update
sudo apt install -y python3 python3-pip seclists curl enum4linux gobuster nbtscan nikto nmap onesixtyone oscanner smbclient smbmap smtp-user-enum snmp sslscan tnscmd10g whatweb wkhtmltopdf

# Install AutoRecon
sudo python3 -m pip install git+https://github.com/Tib3rius/AutoRecon.git

# Verify installation
autorecon --version
```

### Method 2: Manual Install

```bash
# Clone repository
git clone https://github.com/Tib3rius/AutoRecon.git
cd AutoRecon

# Install Python dependencies
pip3 install -r requirements.txt

# Run from directory
python3 autorecon.py --help
```

---

## Basic Usage

### Scan Single Target

```bash
# Basic scan
autorecon 10.10.10.50

# Specify output directory
autorecon 10.10.10.50 -o ~/pentest/results/

# Verbose output
autorecon 10.10.10.50 -v
```

### Scan Multiple Targets

```bash
# Multiple IPs
autorecon 10.10.10.50 10.10.10.51 10.10.10.52

# From file
autorecon -t targets.txt

# Subnet
autorecon 10.10.10.0/24
```

### Competition Mode (Fast & Efficient)

```bash
# Quick scan with custom profile
autorecon 10.10.10.0/24 \
  -o ~/results/ \
  --profile profiles/cptc-competition.toml \
  -v
```

---

## Understanding AutoRecon Output

### Directory Structure

After running AutoRecon on `10.10.10.50`, you'll get:

```
results/
└── 10.10.10.50/
    ├── exploit/        # Space for your exploit code
    ├── loot/           # Captured data (credentials, files)
    ├── report/         
    │   ├── local.txt           # Important findings
    │   ├── notes.txt           # General notes
    │   ├── proof.txt           # Proof of compromise
    │   └── screenshots/        # Auto-captured screenshots
    └── scans/
        ├── _commands.log       # Every command run
        ├── _manual_commands.txt # Suggested manual follow-up
        ├── xml/                # Raw nmap XML
        └── [service-specific results]
```

### Critical Files to Review

**1. `scans/_manual_commands.txt`**
```
Contains commands that require human intervention:
- Authentication-dependent tests
- Potentially disruptive scans
- Context-specific enumeration
```

**2. `scans/_commands.log`**
```
Every command AutoRecon ran with timestamps
Perfect for:
- Understanding what was tested
- Reproducing findings
- Including in reports
```

**3. `report/local.txt` and `report/proof.txt`**
```
Where YOU add your findings
Local.txt: Initial access findings
Proof.txt: Privilege escalation proof
```

**4. Service-specific directories:**
```
scans/tcp80/        # All HTTP enumeration
scans/tcp445/       # All SMB enumeration  
scans/tcp22/        # All SSH enumeration
```

---

## Custom Profiles for Different Scenarios

### Using Custom Profiles

```bash
autorecon TARGET --profile path/to/profile.toml
```

---

### Parsing AutoRecon Results

**Quick review process:**

1. **Check _manual_commands.txt** 
   - Contains suggested follow-up
   - Usually authentication-dependent commands

2. **Review service scans** 
   ```bash
   # HTTP results
   cat scans/tcp80/tcp80_whatweb.txt
   ls scans/tcp80/tcp80_gobuster*.txt
   
   # SMB results  
   cat scans/tcp445/tcp445_enum4linux*.txt
   
   # Check for interesting findings
   grep -i "password\|credential\|admin" scans/tcp*/*.txt
   ```

3. **Look at screenshots** 
   ```bash
   ls report/screenshots/
   # Open in browser for quick visual review
   ```
---

## Advanced AutoRecon Usage

### Scan Specific Ports Only

```bash
# Only scan ports 80,443,445
autorecon TARGET --ports 80,443,445
```

### Exclude Certain Hosts

```bash
# Scan subnet but exclude ICS/SCADA systems
autorecon 10.10.10.0/24 --exclude 10.10.10.200-210
```

### Resume Interrupted Scans

```bash
# AutoRecon tracks progress
# If interrupted, just re-run same command
# It will skip completed hosts
autorecon -t targets.txt -o results/
```

### Service-Specific Enumeration

```bash
# Force specific service detection
autorecon TARGET --services http,smb

# Disable certain scans
autorecon TARGET --disable-reports screenshots
```

---

## Quick Reference

### Essential Commands

```bash
# Basic scan
autorecon TARGET

# Multiple targets
autorecon TARGET1 TARGET2 TARGET3

# From file
autorecon -t targets.txt

# Custom output directory
autorecon TARGET -o /path/to/results/

# Verbose mode
autorecon TARGET -v

# Specific ports
autorecon TARGET --ports 80,443,445,3389

# Resume scans
autorecon -t targets.txt -o results/
# (skips completed hosts)
```

### File Locations to Check

```bash
# For each scanned host:
results/TARGET/scans/_manual_commands.txt  # Manual follow-up suggestions
results/TARGET/scans/_commands.log         # All commands run
results/TARGET/report/screenshots/         # Web screenshots
results/TARGET/scans/tcp80/                # HTTP enumeration
results/TARGET/scans/tcp445/               # SMB enumeration
results/TARGET/scans/tcp3389/              # RDP enumeration
```

---