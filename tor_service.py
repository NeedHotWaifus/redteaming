"""
Tor Service Handler
Manages Tor configuration, proxy chains, and anonymity infrastructure for red team operations
"""

import os
import subprocess
import logging
import traceback
import shutil
from pathlib import Path
from typing import Dict, Optional

class TorService:
    """Handles Tor configuration, proxychains, and anonymity-related operations"""
    
    def __init__(self, loot_dir: Path, logger: Optional[logging.Logger] = None):
        self.loot_dir = loot_dir
        self.logger = logger
        self.tor_running = False
        
        # Ensure loot directory exists
        os.makedirs(self.loot_dir, exist_ok=True)
        
        # Tor config file path
        self.tor_config_path = self.loot_dir / "torrc"
        self.proxychains_config_path = self.loot_dir / "proxychains.conf"
        self.iptables_script_path = self.loot_dir / "stealth_iptables.sh"
        
    def configure_tor(self) -> bool:
        """Configure Tor for anonymity and return success status"""
        config_content = """# Tor configuration for red team operations
SocksPort 9050
ControlPort 9051
CookieAuthentication 1
ExitPolicy reject *:*

# Additional relays for better anonymity
UseBridges 1
ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy

# Disable features that could leak info
DisableDebuggerAttachment 1
SafeLogging 1
HardwareAccel 0

# Directory authorities
DirReqStatistics 0
EntryStatistics 0
ExtraInfoStatistics 0
"""
        
        try:
            with open(self.tor_config_path, 'w') as f:
                f.write(config_content)
            self._log_info(f"Tor configuration written to {self.tor_config_path}")
            return True
        except Exception as e:
            self._log_error(f"Failed to write Tor config: {e}")
            return False
            
    def start_tor_service(self) -> Dict:
        """Start the Tor service using the generated configuration"""
        if not self.check_tor_installed():
            return {
                "success": False,
                "error": "Tor is not installed. Install with 'apt-get install tor' or equivalent."
            }
            
        if not self.tor_config_path.exists():
            if not self.configure_tor():
                return {
                    "success": False,
                    "error": "Could not configure Tor"
                }
                
        try:
            result = subprocess.run(
                ["tor", "-f", str(self.tor_config_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                self.tor_running = True
                self._log_info("Tor service started successfully")
                return {
                    "success": True,
                    "output": result.stdout
                }
            else:
                self._log_error(f"Tor service failed to start: {result.stderr}")
                return {
                    "success": False,
                    "error": result.stderr
                }
        except subprocess.TimeoutExpired:
            self._log_error("Tor service startup timed out")
            return {
                "success": False,
                "error": "Tor service startup timed out after 30 seconds"
            }
        except Exception as e:
            self._log_error(f"Error starting Tor service: {e}")
            return {
                "success": False,
                "error": str(e)
            }
            
    def configure_proxychains(self) -> bool:
        """Configure proxychains for Tor routing"""
        config_content = """# ProxyChains configuration for Tor
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 9050
"""
        
        try:
            with open(self.proxychains_config_path, 'w') as f:
                f.write(config_content)
            self._log_info(f"ProxyChains config written to {self.proxychains_config_path}")
            return True
        except Exception as e:
            self._log_error(f"Failed to write proxychains config: {e}")
            return False
            
    def configure_stealth_iptables(self) -> bool:
        """Configure iptables for stealth operations"""
        script_content = """#!/bin/bash
# Stealth iptables configuration

# Drop ICMP ping responses
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# Rate limit connections
iptables -A INPUT -p tcp --dport 22 -m limit --limit 3/min -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j DROP

# Log and drop port scans
iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP
iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP

# Route traffic through Tor
iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 9040
iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 9040

echo "Stealth iptables rules applied"
"""
        
        try:
            with open(self.iptables_script_path, 'w') as f:
                f.write(script_content)
            
            # Make script executable
            try:
                self.iptables_script_path.chmod(0o755)
            except Exception as e:
                self._log_error(f"Could not set executable permissions: {e}")
                
            self._log_info(f"Stealth iptables script written to {self.iptables_script_path}")
            return True
        except Exception as e:
            self._log_error(f"Failed to write iptables script: {e}")
            return False
    
    def apply_iptables_rules(self) -> Dict:
        """Apply the stealth iptables rules"""
        if not self.iptables_script_path.exists():
            if not self.configure_stealth_iptables():
                return {
                    "success": False,
                    "error": "Could not configure iptables script"
                }
                
        try:
            result = subprocess.run(
                ["bash", str(self.iptables_script_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                self._log_info("Stealth iptables rules applied successfully")
                return {
                    "success": True,
                    "output": result.stdout
                }
            else:
                self._log_error(f"Failed to apply iptables rules: {result.stderr}")
                return {
                    "success": False,
                    "error": result.stderr
                }
        except subprocess.TimeoutExpired:
            self._log_error("Iptables configuration timed out")
            return {
                "success": False,
                "error": "Iptables configuration timed out"
            }
        except Exception as e:
            self._log_error(f"Error applying iptables rules: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def check_tor_installed(self) -> bool:
        """Check if Tor is installed on the system"""
        return shutil.which("tor") is not None
        
    def check_public_ip(self) -> Dict:
        """Check the current public IP address"""
        try:
            result = subprocess.run(
                ["curl", "-s", "ifconfig.me"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                ip = result.stdout.strip()
                self._log_info(f"Public IP detected: {ip}")
                return {
                    "success": True,
                    "ip": ip
                }
            else:
                self._log_error("Failed to check public IP")
                return {
                    "success": False,
                    "error": "curl command failed"
                }
        except Exception as e:
            self._log_error(f"Error checking public IP: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def generate_opsec_checklist(self) -> str:
        """Generate OPSEC checklist file and return the path"""
        checklist_file = self.loot_dir / "opsec_checklist.md"
        
        checklist_content = """# OPSEC Checklist

## Pre-Engagement
- [ ] VPN connection active
- [ ] Tor service running
- [ ] ProxyChains configured
- [ ] Burner email configured
- [ ] VM/Container environment

## During Engagement
- [ ] All traffic routed through proxies
- [ ] No direct IP connections to target
- [ ] User agent randomization
- [ ] Rate limiting on scans
- [ ] Encrypted C2 channels

## Post-Engagement
- [ ] Clear command history
- [ ] Remove temporary files
- [ ] Clear system logs
- [ ] Secure delete sensitive data
- [ ] Verify no persistence left behind

## Continuous
- [ ] Monitor for blue team activity
- [ ] Rotate infrastructure regularly
- [ ] Use domain fronting
- [ ] Implement kill switches
"""
        
        try:
            with open(checklist_file, 'w') as f:
                f.write(checklist_content)
            self._log_info(f"OPSEC checklist written to {checklist_file}")
            return str(checklist_file)
        except Exception as e:
            self._log_error(f"Failed to write OPSEC checklist: {e}")
            return ""
            
    def _log_info(self, message: str) -> None:
        """Log info message if logger is available"""
        if self.logger:
            self.logger.info(message)
            
    def _log_error(self, message: str) -> None:
        """Log error message if logger is available"""
        if self.logger:
            self.logger.error(message)
