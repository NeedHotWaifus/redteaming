"""
RedTeam Toolkit Configuration Module
Centralized configuration management for all toolkit components
"""

import os
from pathlib import Path
from typing import Dict, Any

# Base Configuration
BASE_DIR = Path(__file__).parent
INSTALL_DIR = Path.home() / "redteam-toolkit"
TOOLS_DIR = INSTALL_DIR / "tools"
RESULTS_DIR = INSTALL_DIR / "results"
LOGS_DIR = INSTALL_DIR / "logs"
CONFIG_DIR = INSTALL_DIR / "config"

# General Settings
LOG_LEVEL = "INFO"
LOG_RETENTION_DAYS = 7
MAX_CONCURRENT_PROCESSES = 3
SESSION_TIMEOUT_MINUTES = 60

# OPSEC Configuration
USE_TOR = True
USE_PROXYCHAINS = True
RANDOMIZE_USER_AGENTS = True
SCAN_DELAY_MIN = 30
SCAN_DELAY_MAX = 180
ANTI_FORENSICS_ENABLED = True

# Anonymity Settings
PROTONMAIL_EMAIL = "your-email@protonmail.com"
VPN_REQUIRED = False
TRAFFIC_OBFUSCATION = True

# Default Target Configuration
DEFAULT_TARGET = "example.com"
DEFAULT_LHOST = "127.0.0.1"
DEFAULT_LPORT = 4444

# Tool Paths Configuration
TOOL_PATHS = {
    # Reconnaissance Tools
    "amass": TOOLS_DIR / "amass",
    "subfinder": TOOLS_DIR / "subfinder", 
    "naabu": TOOLS_DIR / "naabu",
    "rustscan": TOOLS_DIR / "rustscan",
    "httpx": TOOLS_DIR / "httpx",
    "theharvester": TOOLS_DIR / "theHarvester",
    "nuclei": TOOLS_DIR / "nuclei",
    
    # Payload Generation
    "metasploit": "/opt/metasploit-framework",
    "msfconsole": "/opt/metasploit-framework/msfconsole",
    "msfvenom": "/opt/metasploit-framework/msfvenom",
    "sliver": "/opt/sliver",
    "sliver_server": "/opt/sliver/sliver-server",
    "sliver_client": "/opt/sliver/sliver-client",
    "havoc": TOOLS_DIR / "Havoc",
    "scarecrow": TOOLS_DIR / "ScareCrow" / "ScareCrow",
    "donut": TOOLS_DIR / "donut" / "donut",
    "greatsct": TOOLS_DIR / "GreatSCT",
    
    # Privilege Escalation
    "winpeas": TOOLS_DIR / "PEASS-ng" / "winPEAS" / "winPEAS.exe",
    "linpeas": TOOLS_DIR / "PEASS-ng" / "linPEAS" / "linpeas.sh",
    "beroot": TOOLS_DIR / "BeRoot",
    "seatbelt": TOOLS_DIR / "Seatbelt" / "Seatbelt.exe",
    
    # Credential Access
    "mimikatz": TOOLS_DIR / "mimikatz" / "mimikatz.exe",
    "rubeus": TOOLS_DIR / "Rubeus" / "Rubeus.exe",
    "crackmapexec": "/usr/local/bin/crackmapexec",
    "impacket": "/usr/local/lib/python3/dist-packages/impacket",
    "bloodhound": TOOLS_DIR / "BloodHound",
    "sharphound": TOOLS_DIR / "SharpHound.exe",
    
    # C2 Frameworks
    "mythic": TOOLS_DIR / "Mythic",
    "chisel": "/usr/local/bin/chisel",
    "dnscat2": TOOLS_DIR / "dnscat2",
    
    # Evasion Tools
    "nimcrypt2": TOOLS_DIR / "Nimcrypt2",
    "pezor": TOOLS_DIR / "PEzor",
    "invoke_obfuscation": TOOLS_DIR / "Invoke-Obfuscation",
    
    # Persistence Tools
    "sharpersist": TOOLS_DIR / "SharPersist",
    "setmace": TOOLS_DIR / "SetMace.exe",
    "sdelete": TOOLS_DIR / "sdelete64.exe"
}

# Network Configuration
PROXY_CONFIG = {
    "tor_proxy": "socks5://127.0.0.1:9050",
    "http_proxy": None,
    "https_proxy": None,
    "backup_proxies": [
        "socks5://127.0.0.1:9051",
        "socks5://127.0.0.1:9052"
    ]
}

# C2 Configuration
C2_CONFIG = {
    "preferred_protocols": ["https", "dns", "icmp"],
    "beacon_interval_range": [3600, 7200],
    "jitter_range": [10, 30],
    "domain_fronting": True,
    "tor_hidden_service": True,
    "auto_migration": True,
    "killswitch_enabled": True
}

# Evasion Configuration
EVASION_CONFIG = {
    "target_av_engines": ["defender", "crowdstrike", "sentinelone", "carbonblack"],
    "obfuscation_level": "high",
    "encryption_method": "aes_256_gcm",
    "packing_enabled": True,
    "sandbox_evasion": True,
    "vm_detection": True,
    "sleep_timers": True
}

# Installation Configuration
INSTALL_CONFIG = {
    "auto_update": True,
    "verify_checksums": True,
    "install_timeout": 3600,
    "retry_attempts": 3,
    "cleanup_temp_files": True,
    "create_shortcuts": False
}

# Color Configuration for CLI
COLORS = {
    "RED": r"\033[31m",
    "GREEN": r"\033[32m", 
    "YELLOW": r"\033[33m",
    "BLUE": r"\033[34m",
    "MAGENTA": r"\033[35m",
    "CYAN": r"\033[36m",
    "WHITE": r"\033[37m",
    "BOLD": r"\033[1m",
    "RESET": r"\033[0m"
}

# Configuration Validation
def validate_config():
    """Validate current configuration settings"""
    errors = []
    
    # Check if base directories exist or can be created
    try:
        INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        TOOLS_DIR.mkdir(parents=True, exist_ok=True)
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        errors.append("Insufficient permissions to create directories")
    
    # Validate email format
    if "@" not in PROTONMAIL_EMAIL or "." not in PROTONMAIL_EMAIL:
        errors.append("Invalid email format")
    
    # Validate port ranges
    if not (1 <= DEFAULT_LPORT <= 65535):
        errors.append("Invalid default port number")
    
    return errors

def save_config():
    """Save current configuration to file"""
    config_file = CONFIG_DIR / "toolkit_config.json"
    config_data = {
        "general": {
            "log_level": LOG_LEVEL,
            "max_concurrent_processes": MAX_CONCURRENT_PROCESSES,
            "session_timeout_minutes": SESSION_TIMEOUT_MINUTES
        },
        "opsec": {
            "use_tor": USE_TOR,
            "use_proxychains": USE_PROXYCHAINS,
            "randomize_user_agents": RANDOMIZE_USER_AGENTS,
            "anti_forensics_enabled": ANTI_FORENSICS_ENABLED
        },
        "anonymity": {
            "protonmail_email": PROTONMAIL_EMAIL,
            "vpn_required": VPN_REQUIRED,
            "traffic_obfuscation": TRAFFIC_OBFUSCATION
        },
        "targets": {
            "default_target": DEFAULT_TARGET,
            "default_lhost": DEFAULT_LHOST,
            "default_lport": DEFAULT_LPORT
        }
    }
    
    import json
    with open(config_file, 'w') as f:
        json.dump(config_data, f, indent=2)

def load_config():
    """Load configuration from file"""
    config_file = CONFIG_DIR / "toolkit_config.json"
    if not config_file.exists():
        return
    
    try:
        import json
        with open(config_file, 'r') as f:
            config_data = json.load(f)
        
        # Update global variables
        global LOG_LEVEL, MAX_CONCURRENT_PROCESSES, SESSION_TIMEOUT_MINUTES
        global USE_TOR, USE_PROXYCHAINS, RANDOMIZE_USER_AGENTS, ANTI_FORENSICS_ENABLED
        global PROTONMAIL_EMAIL, VPN_REQUIRED, TRAFFIC_OBFUSCATION
        global DEFAULT_TARGET, DEFAULT_LHOST, DEFAULT_LPORT
        
        # General settings
        general = config_data.get("general", {})
        LOG_LEVEL = general.get("log_level", LOG_LEVEL)
        MAX_CONCURRENT_PROCESSES = general.get("max_concurrent_processes", MAX_CONCURRENT_PROCESSES)
        SESSION_TIMEOUT_MINUTES = general.get("session_timeout_minutes", SESSION_TIMEOUT_MINUTES)
        
        # OPSEC settings
        opsec = config_data.get("opsec", {})
        USE_TOR = opsec.get("use_tor", USE_TOR)
        USE_PROXYCHAINS = opsec.get("use_proxychains", USE_PROXYCHAINS)
        RANDOMIZE_USER_AGENTS = opsec.get("randomize_user_agents", RANDOMIZE_USER_AGENTS)
        ANTI_FORENSICS_ENABLED = opsec.get("anti_forensics_enabled", ANTI_FORENSICS_ENABLED)
        
        # Anonymity settings
        anonymity = config_data.get("anonymity", {})
        PROTONMAIL_EMAIL = anonymity.get("protonmail_email", PROTONMAIL_EMAIL)
        VPN_REQUIRED = anonymity.get("vpn_required", VPN_REQUIRED)
        TRAFFIC_OBFUSCATION = anonymity.get("traffic_obfuscation", TRAFFIC_OBFUSCATION)
        
        # Target settings
        targets = config_data.get("targets", {})
        DEFAULT_TARGET = targets.get("default_target", DEFAULT_TARGET)
        DEFAULT_LHOST = targets.get("default_lhost", DEFAULT_LHOST)
        DEFAULT_LPORT = targets.get("default_lport", DEFAULT_LPORT)
        
    except Exception as e:
        print(f"Error loading configuration: {e}")

# Helper functions
def get_tool_path(tool_name: str) -> Path:
    """Get the full path to a specific tool"""
    return TOOL_PATHS.get(tool_name, Path())

def is_tool_installed(tool_name: str) -> bool:
    """Check if a tool is installed"""
    tool_path = get_tool_path(tool_name)
    return tool_path.exists() and tool_path.is_file()

def get_proxy_url() -> str:
    """Get the current proxy URL based on configuration"""
    if USE_TOR:
        return PROXY_CONFIG["tor_proxy"]
    elif PROXY_CONFIG["http_proxy"]:
        return PROXY_CONFIG["http_proxy"]
    return ""

# Initialize configuration on import
load_config()
