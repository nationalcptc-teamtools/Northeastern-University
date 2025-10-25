#!/bin/bash
# CPTC Complete Tool Installation 

echo "========================================="
echo "CPTC Tool Installation"
echo "========================================="
echo ""

# Update
echo "[*] Updating package lists..."
sudo apt update

# ALL essential tools from apt
echo "[*] Installing tools from apt..."
sudo apt install -y \
    nmap masscan netcat-traditional curl wget git \
    python3 python3-pip python3-venv \
    seclists gobuster feroxbuster nikto sqlmap \
    enum4linux smbclient smbmap \
    hydra john hashcat \
    tmux vim jq rlwrap proxychains4 \
    responder bloodhound neo4j \
    unzip ruby-full dnsrecon \
    netexec \
    autorecon \
    theharvester \
    s3scanner \
    impacket-scripts

# evil-winrm
echo "[*] Installing evil-winrm..."
sudo gem install evil-winrm

# enum4linux-ng
echo "[*] Installing enum4linux-ng..."
if [ ! -d /opt/enum4linux-ng ]; then
    sudo git clone https://github.com/cddmp/enum4linux-ng.git /opt/enum4linux-ng
fi
sudo chmod +x /opt/enum4linux-ng/enum4linux-ng.py
sudo ln -sf /opt/enum4linux-ng/enum4linux-ng.py /usr/local/bin/enum4linux-ng

# Create directories
echo "[*] Creating directory structure..."
mkdir -p ~/tools/{privesc,windows-tools,ad-attacks,pivoting,monitoring,cloud}
mkdir -p ~/pentest/{scans,exploits,loot,screenshots,notes}
mkdir -p ~/evidence

# LinPEAS/WinPEAS
echo "[*] Downloading LinPEAS/WinPEAS..."
cd ~/tools/privesc
wget -q https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
wget -q https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe
chmod +x linpeas.sh

# Mimikatz
echo "[*] Downloading Mimikatz..."
cd ~/tools/windows-tools
wget -q https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip
unzip -q mimikatz_trunk.zip -d mimikatz
rm mimikatz_trunk.zip

# Rubeus
echo "[*] Downloading Rubeus..."
wget -q https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe

# SharpHound
echo "[*] Downloading SharpHound..."
wget -q https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe

# PrintSpoofer
echo "[*] Downloading PrintSpoofer..."
wget -q https://github.com/itm4n/PrintSpoofer/releases/latest/download/PrintSpoofer64.exe

# GodPotato
echo "[*] Downloading GodPotato..."
wget -q https://github.com/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET4.exe

# PowerUp
echo "[*] Downloading PowerUp..."
wget -q https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1

# kerbrute
echo "[*] Installing kerbrute..."
cd ~/tools/ad-attacks
wget -q https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64
mv kerbrute_linux_amd64 kerbrute
chmod +x kerbrute
sudo ln -sf ~/tools/ad-attacks/kerbrute /usr/local/bin/kerbrute

# PetitPotam
echo "[*] Cloning PetitPotam..."
if [ ! -d ~/tools/ad-attacks/PetitPotam ]; then
    git clone https://github.com/topotam/PetitPotam.git ~/tools/ad-attacks/PetitPotam 2>/dev/null || true
fi

# DFSCoerce  
echo "[*] Cloning DFSCoerce..."
if [ ! -d ~/tools/ad-attacks/DFSCoerce ]; then
    git clone https://github.com/Wh04m1001/DFSCoerce.git ~/tools/ad-attacks/DFSCoerce 2>/dev/null || true
fi

# Ligolo-ng
echo "[*] Downloading Ligolo-ng..."
cd ~/tools/pivoting
LIGOLO_PROXY=$(curl -s https://api.github.com/repos/nicocha30/ligolo-ng/releases/latest | grep "browser_download_url.*proxy.*linux_amd64.tar.gz" | cut -d '"' -f 4)
LIGOLO_AGENT_LINUX=$(curl -s https://api.github.com/repos/nicocha30/ligolo-ng/releases/latest | grep "browser_download_url.*agent.*linux_amd64.tar.gz" | cut -d '"' -f 4)
LIGOLO_AGENT_WIN=$(curl -s https://api.github.com/repos/nicocha30/ligolo-ng/releases/latest | grep "browser_download_url.*agent.*windows_amd64.zip" | cut -d '"' -f 4)

wget -q "$LIGOLO_PROXY" -O ligolo-proxy.tar.gz
wget -q "$LIGOLO_AGENT_LINUX" -O ligolo-agent-linux.tar.gz
wget -q "$LIGOLO_AGENT_WIN" -O ligolo-agent-windows.zip

tar -xzf ligolo-proxy.tar.gz
tar -xzf ligolo-agent-linux.tar.gz
unzip -q ligolo-agent-windows.zip
chmod +x proxy agent 2>/dev/null
rm -f *.tar.gz *.zip

# Chisel
echo "[*] Downloading Chisel..."
CHISEL_URL=$(curl -s https://api.github.com/repos/jpillora/chisel/releases/latest | grep "browser_download_url.*linux_amd64.gz" | cut -d '"' -f 4)
wget -q "$CHISEL_URL" -O chisel.gz
gunzip chisel.gz
chmod +x chisel

# pspy
echo "[*] Downloading pspy..."
cd ~/tools/monitoring
wget -q https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64
chmod +x pspy64

# Ligolo setup 
echo "[*] Setting up Ligolo interface..."
cd ~
sudo ip tuntap add user $(whoami) mode tun ligolo 2>/dev/null || true
sudo ip link set ligolo up 2>/dev/null || true

# Wordlists
echo "[*] Setting up wordlists..."
mkdir -p ~/wordlists
ln -sf /usr/share/wordlists/rockyou.txt ~/wordlists/rockyou.txt 2>/dev/null || true
ln -sf /usr/share/seclists ~/wordlists/seclists 2>/dev/null || true

echo ""
echo "========================================="
echo "Installation Complete!"
echo "========================================="
echo ""
echo "Verification:"
echo "----------------------------------------"
command -v netexec >/dev/null 2>&1 && echo "✓ netexec" || echo "✗ netexec"
command -v impacket-GetUserSPNs >/dev/null 2>&1 && echo "✓ impacket" || echo "✗ impacket"
command -v autorecon >/dev/null 2>&1 && echo "✓ autorecon" || echo "✗ autorecon"
command -v kerbrute >/dev/null 2>&1 && echo "✓ kerbrute" || echo "✗ kerbrute"
command -v evil-winrm >/dev/null 2>&1 && echo "✓ evil-winrm" || echo "✗ evil-winrm"
command -v theHarvester >/dev/null 2>&1 && echo "✓ theHarvester" || echo "✗ theHarvester"
command -v sublist3r >/dev/null 2>&1 && echo "✓ sublist3r" || echo "✗ sublist3r"
command -v dnsrecon >/dev/null 2>&1 && echo "✓ dnsrecon" || echo "✗ dnsrecon"
command -v s3scanner >/dev/null 2>&1 && echo "✓ s3scanner" || echo "✗ s3scanner"
[ -f ~/tools/windows-tools/mimikatz/x64/mimikatz.exe ] && echo "✓ Mimikatz" || echo "✗ Mimikatz"
[ -f ~/tools/windows-tools/Rubeus.exe ] && echo "✓ Rubeus" || echo "✗ Rubeus"
[ -f ~/tools/windows-tools/PrintSpoofer64.exe ] && echo "✓ PrintSpoofer" || echo "✗ PrintSpoofer"
[ -f ~/tools/windows-tools/GodPotato-NET4.exe ] && echo "✓ GodPotato" || echo "✗ GodPotato"
[ -f ~/tools/pivoting/proxy ] && echo "✓ Ligolo-ng proxy" || echo "✗ Ligolo-ng"
[ -f ~/tools/pivoting/chisel ] && echo "✓ Chisel" || echo "✗ Chisel"

echo ""
echo "Tools at: ~/tools/"
echo "Workspace: ~/pentest/"
echo "Evidence: ~/evidence/"
echo ""
echo "Install manually"
echo "  AWS CLI: curl https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o aws.zip && unzip aws.zip && sudo ./aws/install"
echo "  Azure CLI: sudo apt install azure-cli"
echo "  GCP CLI: sudo apt install google-cloud-cli"
echo ""
