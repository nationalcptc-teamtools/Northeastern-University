# Web Application Reconnaissance

## Initial Discovery

### Basic Directory Enumeration
```bash
# Gobuster
gobuster dir -u http://TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,html,txt,pdf

# Feroxbuster - Recursive with auto-filtering
feroxbuster -u http://TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php html txt -t 50

# Quick common files check
gobuster dir -u http://TARGET -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,html,txt,bak,old
```

### Technology Fingerprinting
```bash
# WhatWeb - Identify technologies
whatweb http://TARGET -a 3

# Wappalyzer
wappalyzer http://TARGET

# Manual header inspection
curl -I http://TARGET

# Nikto scan (noisy)
nikto -h http://TARGET -C all
```

### Subdomain Enumeration
```bash
# If you have a domain name
# Sublist3r
python3 /opt/Sublist3r/sublist3r.py -d TARGET.com

# Amass
amass enum -passive -d TARGET.com

# DNSrecon
dnsrecon -d TARGET.com -t std
```

### Content Discovery
```bash
# Find backup files
gobuster dir -u http://TARGET -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -x bak,old,backup,zip,tar.gz

# Find hidden parameters
ffuf -u http://TARGET/page?FUZZ=test -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

# JavaScript file analysis
# First, find all JS files
gospider -s http://TARGET -c 10 -d 2 --js

# Then analyze for endpoints/secrets
python3 /opt/LinkFinder/linkfinder.py -i http://TARGET/app.js -o cli
```

## Vulnerability Scanning

### Quick Wins
```bash
# Check for common vulns
nuclei -u http://TARGET -t /root/nuclei-templates/

# Git exposure
wget -r http://TARGET/.git/
git-dumper http://TARGET/.git/ ./output

# Environment files
curl http://TARGET/.env
curl http://TARGET/.env.local
curl http://TARGET/.env.production

# Common sensitive files
robots.txt
sitemap.xml
crossdomain.xml
phpinfo.php
info.php
```

### Authentication Testing
```bash
# Test for default credentials first
# admin:admin, admin:password, root:root, etc.

# Password spraying (if you have usernames, use carefully)
hydra -L users.txt -p Welcome2024! http-post-form "//login.php:username=^USER^&password=^PASS^:F=incorrect" -t 10

# Test for username enumeration
# Watch response differences
curl -X POST http://TARGET/login -d "username=admin&password=wrong" -v
curl -X POST http://TARGET/login -d "username=nonexistent&password=wrong" -v
```

## API Enumeration

### REST API Discovery
```bash
# Common API endpoints
gobuster dir -u http://TARGET -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt

# API fuzzing
ffuf -u http://TARGET/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt

# Check for API documentation
curl http://TARGET/api/docs
curl http://TARGET/swagger.json
curl http://TARGET/api/swagger.json
curl http://TARGET/openapi.json
```

### GraphQL Testing
```bash
# Introspection query
curl http://TARGET/graphql -X POST -H "Content-Type: application/json" -d '{"query":"{ __schema { types { name } } }"}'

# Common GraphQL endpoints
graphql
api/graphql
grahiql
api/graphiql
v1/graphql
```

## WordPress Specific

### WPScan
```bash
# Basic enumeration
wpscan --url http://TARGET --enumerate u,ap,at

# With API token for vulnerability data
wpscan --url http://TARGET --enumerate vp,vt --api-token YOUR_TOKEN

# Aggressive user enumeration
wpscan --url http://TARGET --enumerate u1-100

# Password attack
wpscan --url http://TARGET -U admin -P /usr/share/wordlists/rockyou.txt
```

### WordPress Manual Checks
```bash
# Check xmlrpc.php (brute force vector)
curl http://TARGET/xmlrpc.php -X POST -d '<methodCall><methodName>system.listMethods</methodName></methodCall>'

# Check wp-json
curl http://TARGET/wp-json/wp/v2/users

# Check wp-content uploads
gobuster dir -u http://TARGET/wp-content/uploads/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
```

## Screenshot & Visual Recon

### Automated Screenshots
```bash
# EyeWitness
eyewitness --web -f urls.txt --delay 5

# Aquatone
cat urls.txt | aquatone

# GoWitness
gowitness file -f urls.txt
```

## Proxy Setup (Burp/ZAP)

### Configure Proxy
```bash
# Set browser to use proxy (127.0.0.1:8080 for Burp)
# Or use FoxyProxy extension (preferred)

# For command-line tools
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080

# Spider with Burp running
gospider -s http://TARGET -p http://127.0.0.1:8080
```

## Quick Security Tests

### Test for Common Issues
```bash
# SQL injection quick test
sqlmap -u "http://TARGET/page.php?id=1" --batch --level=1 --risk=1 --threads=5

# XSS quick test
dalfox url http://TARGET/search?q=test

# Command injection test
commix -u "http://TARGET/page.php?cmd=test"

# XXE test
# Create xxe.xml with payload, then:
curl -X POST http://TARGET/upload -H "Content-Type: application/xml" -d @xxe.xml
```

## One-Liners

### Extract All URLs from Page
```bash
# Get all links
curl -s http://TARGET | grep -oP 'href="\K[^"]+' | sort -u

# Get all JavaScript files
curl -s http://TARGET | grep -oP 'src="\K[^"]+\.js' | sort -u
```