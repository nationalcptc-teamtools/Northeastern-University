# SAFETY IMPACT GUIDE

---

## CPTC-SPECIFIC WARNINGS

### ICS/SCADA Systems - EXTREME CAUTION REQUIRED

**From CPTC 2020 Historical Incident:**
Teams ran OpenVAS and aggressive nmap scans against ICS/SCADA systems controlling a dam's operations. This caused:
- PLC (Programmable Logic Controller) crashes
- Each restart took progressively longer
- Potential catastrophic infrastructure damage

**IF YOU ENCOUNTER ICS/SCADA:**
```
DO NOT use automated vulnerability scanners
DO NOT use aggressive nmap timing (-T4, -T5)
DO NOT attempt exploits without explicit permission
DO NOT test during production hours
```

**SAFE APPROACH FOR ICS/SCADA:**
```
Read documentation FIRST
Use passive reconnaissance only (traffic sniffing, tcpdump)
Use gentle enumeration (-T2 or slower)
Ask client before ANY active testing
Test during approved maintenance windows ONLY
Have rollback plan ready
```

**How to Identify ICS/SCADA:**
```
Indicators:
- Ports: 502 (Modbus), 102 (S7), 44818 (EtherNet/IP), 20000 (DNP3)
- Keywords: PLC, HMI, RTU, SCADA, ICS, OT (Operational Technology)
- Devices: Siemens, Allen-Bradley, Schneider, GE
- Network names: OT, control, SCADA, operations
- Documentation mentions: plant, facility, production

If ANY of these appear:
1. STOP all automated scanning
2. Notify team immediately
3. Contact client for guidance
4. Use ONLY approved testing methods
```

---

## ACCOUNT LOCKOUT RISKS

### Password Spraying - Critical Safety

**The Problem:**
Aggressive password attempts lock out accounts, disrupting business operations and triggering alarms.

**ALWAYS Check Policy First:**
```bash
# Windows/AD
crackmapexec smb DC_IP -u '' -p '' --pass-pol

# Look for:
Account lockout threshold: 5 attempts
Lockout duration: 30 minutes

SAFE LIMITS:
- Threshold 0 or None: Safe to spray freely
- Threshold 3-4: ONLY 1-2 password attempts
- Threshold 5+: Safe to spray 3-4 passwords maximum
- Unknown: DO NOT SPRAY

WAIT TIME:
- Minimum 30 minutes between spray attempts
- Better: 60+ minutes
```

**What Happens If You Lock Out Accounts:**
- Users can't log in
- IT gets alerted immediately
- You look unprofessional
- Client loses confidence
- May result in disqualification or penalties
- "Educational opportunity" (penalty points)

**Safe Password Spray Process:**
```bash
# Step 1: Get password policy
crackmapexec smb DC_IP -u '' -p '' --pass-pol

# Step 2: Verify threshold is safe (≥5)
# If not, SKIP password spraying

# Step 3: ONE password at a time
./ad_password_spray.sh DC_IP DOMAIN users.txt 'Welcome2024!'

# Step 4: WAIT 30+ minutes

# Step 5: Try next password
./ad_password_spray.sh DC_IP DOMAIN users.txt 'Fall2024!'

# Step 6: Maximum 3-4 total passwords in entire competition
```

---

## SERVICE DISRUPTION RISKS

### Nmap Timing - Can Crash Services

**Aggressive Scans Can:**
- Crash vulnerable services
- Overwhelm network devices
- Trigger IDS/IPS blocks
- Cause service restarts
- Disrupt legitimate traffic

**SAFE SCANNING:**
```bash
NEVER USE:
nmap -T5 --max-rate 10000 (TOO AGGRESSIVE)
nmap --script vuln (may crash services)

SAFE:
nmap -T4 --min-rate 1000 (balanced)
nmap -sV -sC (safe scripts only)
rustscan with default settings
```

**Vulnerable Service Types:**
```
High Risk (scan gently):
- ICS/SCADA (use -T2 maximum)
- Legacy systems (Windows Server 2003, old Linux)
- Embedded devices (printers, IoT, cameras)
- Database servers (production databases)

Medium Risk (use -T4):
- Modern Windows servers
- Modern Linux servers
- Web servers

Low Risk (-T4 fine):
- Test/development systems
- Already compromised systems
- Modern, patched systems
```

### SQLMap - Database Performance Impact

**What SQLMap Does:**
- Sends hundreds/thousands of requests
- Can slow database significantly
- May fill logs rapidly
- Can trigger alarms

**SAFE USAGE:**
```bash
# Start with low intensity
sqlmap -u "URL" --level=1 --risk=1 --batch

# Increase only if needed
sqlmap -u "URL" --level=2 --risk=2 --batch

AVOID in production:
sqlmap --level=5 --risk=3 (extremely aggressive)

ALWAYS use --batch to avoid prompts during testing
```

### Brute Force Attacks - Multiple Risks

**Services That Lock Out:**
- SSH: May ban IP after failed attempts
- RDP: Account lockout after failures
- Web logins: Account lockout or IP ban
- FTP: IP ban common
- SMB: Account lockout (covered above)

**SAFE APPROACH:**
```bash
# Use SMALL wordlists only
hydra -L users.txt -P top100passwords.txt ssh://target -t 4

NEVER:
hydra with rockyou.txt (14 million passwords - will lock everything)

SAFE:
- Top 100 passwords maximum
- 4 threads maximum (-t 4)
- Test one account first
- Stop after 3-5 failures
```

---

## EXPLOIT RISKS

### Metasploit Exploits - May Crash Systems

**Understanding Exploit Stability:**
```
Excellent: Reliable, won't crash
Great: Very stable
Good: Usually works, rarely crashes
Normal: Sometimes crashes
Average: Unstable, may crash
Low: Often crashes
Manual: Requires careful execution
```

**BEFORE USING METASPLOIT EXPLOIT:**
```bash
# Check exploit ranking
msf> info exploit/path/to/exploit

# Look for "Reliability: Good" or better
# Avoid "Reliability: Average" or "Low" in production

# ALWAYS have backup plan if exploit crashes service
```
---

## PRE-TESTING SAFETY CHECKLIST

### Before ANY Active Testing:

**1. Verify Scope**
```
This IP/hostname is in approved scope
This service is approved for testing
Current time is within testing window
No restricted actions on this target
```

**2. Understand Target**
```
Identified operating system
Identified service versions
Checked if ICS/SCADA
Know criticality level
```

**3. Choose Appropriate Tools**
```
Tool appropriate for target type
Using safe timing/intensity
Have tested tool before
Know what tool does
```

**4. Have Backup Plan**
```
Can restart service if needed
Know who to contact if issues
Have tested recovery process
Documented what you're about to do
```

---

## TOOL IMPACT REFERENCE

### Low Impact (Generally Safe)
```
nmap -sV -sC -T4 (service detection)
enum4linux-ng (SMB enumeration)
gobuster/ffuf (directory fuzzing)
Manual web testing
AS-REP roasting (one request per user)
Passive tools (Responder, tcpdump)
```

### Medium Impact (Use Carefully)
```
nmap --script vuln (vulnerability scripts)
sqlmap --level=1-2 (database queries)
hydra with small lists (authentication attempts)
Kerberoasting (service ticket requests)
Password spraying (3-4 attempts max)
```

### High Impact (Extreme Caution)
```
Metasploit exploits (may crash)
sqlmap --level=5 (very aggressive)
nmap -T5 (can crash services)
Buffer overflow exploits
Kernel exploits
```

### NEVER Use Without Explicit Permission
```
Greenbone or other auto-scanners on ICS/SCADA
Aggressive timing on legacy systems
Any "destructive" exploits
DoS/stress testing (Out of Scope anyways)
Social engineering (unless explicitly scoped)
```

---

## INCIDENT RESPONSE PROTOCOL

### If You Crash Something:

**Step 1: STOP**
```
Immediately stop all testing on that system
Do NOT try to "fix" it yourself
Do NOT continue testing other systems without reporting
```

**Step 2: NOTIFY**
```
Tell your team captain IMMEDIATELY
Contact client IT staff ON-SITE
Document exactly what you did:
- Command run
- Time executed
- What happened
- Current system state
```

**Step 3: DOCUMENT**
```
This becomes a finding:
- Title: "Service Disruption During Testing"
- Describe what happened
- Document impact
- Recommend: Better change control, testing in dev first
- This shows professionalism!
```

**Step 4: COMMUNICATE**
```
Professional communication:
"During testing of [system] at [time], we executed [command] 
which resulted in [impact]. We immediately ceased testing and 
are available to assist with recovery. We recommend [remediation]."

NOT:
"Oops, we broke it" or hiding the incident
```

---

## TESTING BEST PRACTICES

### Start Gentle, Escalate Carefully
```
Phase 1: Passive (no impact)
- Port scanning with -T3
- Service banner grabbing
- Web browsing
- Traffic sniffing

Phase 2: Active but Safe (minimal impact)
- Service version detection
- Directory enumeration
- Manual web testing
- Null session checks

Phase 3: Authentication Attempts (may lock out)
- Default credentials (safe - just one attempt per)
- Password spraying (3-4 attempts with policy check)
- Brute force (small lists only)

Phase 4: Exploitation (may crash)
- Only on approved targets
- After testing in lab if possible
- With client awareness
- During approved windows
```

### Communication is Key
```
BEFORE risky testing:
"We've identified potential SQL injection. Testing may generate 
significant database queries. Is now an appropriate time?"

DURING testing:
"Currently testing AD authentication. Being cautious of lockout 
thresholds. Will report any access obtained."

AFTER finding issues:
"Discovered critical vulnerability. Demonstrated exploitability 
without causing impact. Ready to discuss findings."
```

---

## COMPETITION-SPECIFIC SAFETY

### CPTC Scoring Penalties

**You LOSE Points For:**
- Locking out accounts
- Crashing services  
- Testing out of scope
- Not communicating issues
- Unprofessional conduct

**You GAIN Points For:**
- Professional communication
- Safe testing practices
- Reporting issues immediately
- Understanding business impact
- Proposing remediations

### "Educational Opportunities"

CPTC uses this term for mistakes that teach professionalism:
- Account lockouts
- Service crashes
- Scope violations

**How to Handle:**
1. Acknowledge immediately
2. Document thoroughly
3. Communicate professionally
4. Turn into a finding
5. Show you learned from it

---