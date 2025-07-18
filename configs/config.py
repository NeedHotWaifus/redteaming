"""
RedTeam Toolkit Configuration
"""

import sys
import os
from pathlib import Path

# Import keys module for secure key management
try:
    from configs.keys import get_ssh_public_key, DEFAULT_SSH_KEY
except ImportError:
    # Fallback if keys module not available
    def get_ssh_public_key():
        return "ssh-rsa AAAAB3... Generate your own key and add it here"
    DEFAULT_SSH_KEY = ""

# Base directory - will be set by CLI
BASE_DIR = None

# Target settings
DEFAULT_TARGET = "example.local"  # Default target (change as needed)
DEFAULT_LHOST = "0.0.0.0"  # Local host IP (set via config)
DEFAULT_LPORT = 4444

# User credentials for lateral movement and exploitation
DEFAULT_USERNAME = "user"
DEFAULT_DOMAIN = "domain"
DEFAULT_PASSWORD = ""  # Set via CLI or config
SSH_PUBLIC_KEY = get_ssh_public_key()

# Attacker infrastructure
ATTACKER_DOMAIN = "attacker.local"  # Set via config
C2_SERVER_URL = f"http://{ATTACKER_DOMAIN}"  # Set via config
C2_LISTENER_PORT = 8443
TOR_ENABLED = False
TOR_HIDDEN_SERVICE_PORT = 80
TOR_HIDDEN_SERVICE = ""

# File paths and directories
PAYLOAD_OUTPUT_DIR = "loot/payloads/"
SCRIPT_OUTPUT_DIR = "loot/scripts/"
RECON_OUTPUT_DIR = "loot/recon/"

# Tool installation options
AUTO_INSTALL_TOOLS = True
USE_MIRRORS = True

# Operational security settings
USE_TOR = False
USE_PROXYCHAINS = False
RANDOMIZE_USER_AGENTS = True
ANTI_FORENSICS_ENABLED = True
VPN_REQUIRED = True
PROTONMAIL_EMAIL = "user@example.com"

# User agent for web requests
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# UI Configuration
UI_PADDING_X = 10
UI_PADDING_Y = 5
HEADER_FONT = ("TkDefaultFont", 16, "bold")
TEXT_FONT = ("TkDefaultFont", 10)

def save_config():
    """Save current configuration to file"""
    import json
    import os
    
    # Only save values that should persist
    save_values = {
        "DEFAULT_TARGET": DEFAULT_TARGET,
        "DEFAULT_LHOST": DEFAULT_LHOST,
        "DEFAULT_LPORT": DEFAULT_LPORT,
        "ATTACKER_DOMAIN": ATTACKER_DOMAIN,
        "C2_SERVER_URL": C2_SERVER_URL,
        "SSH_PUBLIC_KEY": SSH_PUBLIC_KEY,
        "USE_TOR": USE_TOR,
        "USE_PROXYCHAINS": USE_PROXYCHAINS,
        "RANDOMIZE_USER_AGENTS": RANDOMIZE_USER_AGENTS,
        "ANTI_FORENSICS_ENABLED": ANTI_FORENSICS_ENABLED,
        "VPN_REQUIRED": VPN_REQUIRED,
        "PROTONMAIL_EMAIL": PROTONMAIL_EMAIL
    }
    
    # Create configs directory if it doesn't exist
    if BASE_DIR:
        config_dir = BASE_DIR / "configs"
        os.makedirs(config_dir, exist_ok=True)
        
        # Save to user_config.json
        with open(config_dir / "user_config.json", "w") as f:
            json.dump(save_values, f, indent=4)
        
        return True
    return False

def load_config():
    """Load configuration from file"""
    import json
    
    if BASE_DIR:
        config_path = BASE_DIR / "configs" / "user_config.json"
        if config_path.exists():
            try:
                with open(config_path, "r") as f:
                    saved_config = json.load(f)
                
                # Update global variables with saved values
                for key, value in saved_config.items():
                    if key in globals():
                        globals()[key] = value
                
                return True
            except Exception as e:
                print(f"Error loading config: {e}")
    
    return False

def collect_target_settings():
    """Interactively collect target settings"""
    global DEFAULT_TARGET, DEFAULT_LHOST, DEFAULT_LPORT
    
    print("\n=== Target Settings ===")
    target = input(f"Default Target [{DEFAULT_TARGET}]: ").strip()
    if target:
        DEFAULT_TARGET = target
        
    lhost = input(f"Default LHOST (Your IP) [{DEFAULT_LHOST}]: ").strip()
    if lhost:
        DEFAULT_LHOST = lhost
        
    lport = input(f"Default LPORT [{DEFAULT_LPORT}]: ").strip()
    if lport and lport.isdigit() and 1 <= int(lport) <= 65535:
        DEFAULT_LPORT = int(lport)

def collect_user_credentials():
    """Interactively collect user credential settings"""
    global DEFAULT_USERNAME, DEFAULT_DOMAIN, DEFAULT_PASSWORD
    
    print("\n=== User Credentials ===")
    username = input(f"Default Username [{DEFAULT_USERNAME}]: ").strip()
    if username:
        DEFAULT_USERNAME = username
        
    domain = input(f"Default Domain [{DEFAULT_DOMAIN}]: ").strip()
    if domain:
        DEFAULT_DOMAIN = domain
        
    # Password input with optional masking
    try:
        import getpass
        password = getpass.getpass(f"Default Password (leave empty for security): ")
    except ImportError:
        password = input(f"Default Password (leave empty for security): ")
    
    if password:
        DEFAULT_PASSWORD = password

def collect_infrastructure_settings():
    """Interactively collect infrastructure settings"""
    global ATTACKER_DOMAIN, C2_SERVER_URL, C2_LISTENER_PORT
    
    print("\n=== Attacker Infrastructure ===")
    domain = input(f"Attacker Domain [{ATTACKER_DOMAIN}]: ").strip()
    if domain:
        ATTACKER_DOMAIN = domain
        # Update C2 server URL
        C2_SERVER_URL = f"http://{ATTACKER_DOMAIN}"
        
    c2_url = input(f"C2 Server URL [{C2_SERVER_URL}]: ").strip()
    if c2_url:
        C2_SERVER_URL = c2_url
        
    c2_port = input(f"C2 Listener Port [{C2_LISTENER_PORT}]: ").strip()
    if c2_port and c2_port.isdigit() and 1 <= int(c2_port) <= 65535:
        C2_LISTENER_PORT = int(c2_port)

def collect_opsec_settings():
    """Interactively collect OPSEC settings"""
    global USE_TOR, USE_PROXYCHAINS, RANDOMIZE_USER_AGENTS, ANTI_FORENSICS_ENABLED, VPN_REQUIRED, PROTONMAIL_EMAIL
    
    print("\n=== Operational Security ===")
    use_tor = input(f"Use Tor (y/n) [{'y' if USE_TOR else 'n'}]: ").strip().lower()
    if use_tor in ('y', 'n'):
        USE_TOR = (use_tor == 'y')
        
    use_proxy = input(f"Use ProxyChains (y/n) [{'y' if USE_PROXYCHAINS else 'n'}]: ").strip().lower()
    if use_proxy in ('y', 'n'):
        USE_PROXYCHAINS = (use_proxy == 'y')
        
    random_ua = input(f"Randomize User Agents (y/n) [{'y' if RANDOMIZE_USER_AGENTS else 'n'}]: ").strip().lower()
    if random_ua in ('y', 'n'):
        RANDOMIZE_USER_AGENTS = (random_ua == 'y')
        
    anti_forensics = input(f"Enable Anti-Forensics (y/n) [{'y' if ANTI_FORENSICS_ENABLED else 'n'}]: ").strip().lower()
    if anti_forensics in ('y', 'n'):
        ANTI_FORENSICS_ENABLED = (anti_forensics == 'y')
        
    vpn_required = input(f"VPN Required (y/n) [{'y' if VPN_REQUIRED else 'n'}]: ").strip().lower()
    if vpn_required in ('y', 'n'):
        VPN_REQUIRED = (vpn_required == 'y')
        
    email = input(f"ProtonMail Email [{PROTONMAIL_EMAIL}]: ").strip()
    if email:
        PROTONMAIL_EMAIL = email

def setup_interactive_config():
    """Interactive setup of all configuration values"""
    print("\n=== RedTeam Toolkit Interactive Configuration ===")
    print("Press Enter to keep current values")
    
    collect_target_settings()
    collect_user_credentials()
    collect_infrastructure_settings()
    collect_opsec_settings()
    
    # Save configuration
    save = input("\nSave configuration? (y/n) [y]: ").strip().lower()
    if save != 'n':
        if save_config():
            print("Configuration saved successfully")
        else:
            print("Failed to save configuration")
    
    return True

# Command-line interface for config if run directly
if __name__ == "__main__":
    setup_interactive_config()

# Try to load saved configuration
try:
    load_config()
except:
    pass
