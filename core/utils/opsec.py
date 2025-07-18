"""
OPSEC and Anonymity Module
Handles operational security and anonymity setup
"""

import socket
import requests
from pathlib import Path
import os
import subprocess
import platform
from typing import Dict, Optional, List, Tuple
from core.utils.output import print_colored

def run_opsec_anonymity(tool_executor):
    """
    Execute OPSEC and anonymity infrastructure setup
    
    Args:
        tool_executor: ToolExecutor instance
        
    Returns:
        Dictionary with OPSEC check results
    """
    target = tool_executor.target
    
    print_colored(f"🔒 Running OPSEC & Anonymity Infrastructure for: {target}", "GREEN", True)
    print()
    
    results = {}
    
    # Check current IP and VPN status
    results["ip_check"] = check_vpn_status(tool_executor)
    
    # Configure Tor
    results["tor"] = configure_tor_setup(tool_executor)
    
    # Configure ProxyChains
    results["proxychains"] = configure_proxychains(tool_executor)
    
    # Setup stealth iptables rules
    if platform.system() != "Windows":
        results["iptables"] = configure_stealth_iptables(tool_executor)
    
    # Generate OPSEC checklist
    results["checklist"] = generate_opsec_checklist(tool_executor)
    
    return results

def get_print_colored_function():
    """Get the print_colored function dynamically to avoid circular imports"""
    try:
        from core.utils.output import print_colored
        return print_colored
    except ImportError:
        # Fallback if import fails
        return lambda text, color="WHITE", bold=False, end="\n", colors=None: print(text, end=end)

def check_vpn_status(tool_executor):
    """
    Check VPN connection status
    
    Args:
        tool_executor: ToolExecutor instance
        
    Returns:
        Dictionary with check results
    """
    print_colored = get_print_colored_function()
    print_colored("🔍 Checking VPN status...", "BLUE")
    
    results = {
        "public_ip": None,
        "ip_details": {},
        "dns_leak": None,
        "status": "unknown"
    }
    
    # Check public IP using multiple services for reliability
    ip_services = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com"
    ]
    
    for service in ip_services:
        try:
            ip_result = tool_executor.execute_tool(
                "curl",
                ["curl", "-s", service],
                timeout=10
            )
            
            if ip_result["success"] and ip_result["output"].strip():
                results["public_ip"] = ip_result["output"].strip()
                break
        except:
            continue
    
    # If we got an IP, try to get more details
    if results["public_ip"]:
        print_colored(f"📍 Public IP: {results['public_ip']}", "CYAN")
        
        # Try to get IP details
        try:
            ip_details = tool_executor.execute_tool(
                "curl",
                ["curl", "-s", f"https://ipinfo.io/{results['public_ip']}/json"],
                timeout=10
            )
            
            if ip_details["success"]:
                import json
                try:
                    results["ip_details"] = json.loads(ip_details["output"])
                    print_colored(f"📍 Location: {results['ip_details'].get('city', 'Unknown')}, {results['ip_details'].get('country', 'Unknown')}", "CYAN")
                    print_colored(f"📍 ISP: {results['ip_details'].get('org', 'Unknown')}", "CYAN")
                except:
                    pass
        except:
            pass
        
        # Determine if likely using VPN based on hostname or organization
        vpn_indicators = ["vpn", "proxy", "tor", "exit", "node", "relay", "hosting"]
        hostname = results["ip_details"].get("hostname", "").lower()
        org = results["ip_details"].get("org", "").lower()
        
        vpn_detected = any(indicator in hostname or indicator in org for indicator in vpn_indicators)
        if vpn_detected:
            print_colored("✅ VPN/Proxy detected", "GREEN")
            results["status"] = "vpn_detected"
        else:
            print_colored("⚠️ No VPN/Proxy detected", "YELLOW")
            results["status"] = "no_vpn_detected"
    else:
        print_colored("❌ Failed to check public IP", "RED")
        results["status"] = "check_failed"
    
    return results

def configure_tor_setup(tool_executor):
    """
    Configure Tor for anonymity
    
    Args:
        tool_executor: ToolExecutor instance
        
    Returns:
        Dictionary with setup results
    """
    print_colored = get_print_colored_function()
    tor_config = tool_executor.loot_dir / "torrc"
    
    results = {
        "config_path": str(tor_config),
        "tor_available": tool_executor.check_tool("tor"),
        "status": "not_configured"
    }
    
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
        with open(tor_config, 'w') as f:
            f.write(config_content)
        
        print_colored(f"📁 Tor config: {tor_config}", "CYAN")
        results["config_written"] = True
        
        # Start Tor service
        if results["tor_available"]:
            print_colored("🔧 Starting Tor service...", "BLUE")
            result = tool_executor.execute_tool(
                "tor",
                ["tor", "-f", str(tor_config)],
                timeout=30
            )
            
            results["service_result"] = result
            
            if result["success"]:
                print_colored("✅ Tor service started", "GREEN")
                results["status"] = "running"
            else:
                print_colored("❌ Failed to start Tor", "RED")
                results["status"] = "start_failed"
        else:
            print_colored("❌ Tor not available. Install with: apt install tor", "RED")
            results["status"] = "not_installed"
    except Exception as e:
        print_colored(f"❌ Error configuring Tor: {str(e)}", "RED")
        results["error"] = str(e)
        results["status"] = "config_failed"
    
    return results

def configure_proxychains(tool_executor):
    """
    Configure proxychains for Tor
    
    Args:
        tool_executor: ToolExecutor instance
        
    Returns:
        Dictionary with setup results
    """
    print_colored = get_print_colored_function()
    proxychains_config = tool_executor.loot_dir / "proxychains.conf"
    
    results = {
        "config_path": str(proxychains_config),
        "proxychains_available": tool_executor.check_tool("proxychains") or tool_executor.check_tool("proxychains4"),
        "status": "not_configured"
    }
    
    config_content = """# ProxyChains configuration for Tor
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 9050
"""
    
    try:
        with open(proxychains_config, 'w') as f:
            f.write(config_content)
        
        print_colored(f"📁 ProxyChains config: {proxychains_config}", "CYAN")
        results["config_written"] = True
        results["status"] = "configured"
        
        if not results["proxychains_available"]:
            print_colored("⚠️ ProxyChains not found. Install with: apt install proxychains4", "YELLOW")
            results["status"] = "not_installed"
    except Exception as e:
        print_colored(f"❌ Error configuring ProxyChains: {str(e)}", "RED")
        results["error"] = str(e)
        results["status"] = "config_failed"
    
    return results

def configure_stealth_iptables(tool_executor):
    """
    Configure iptables for stealth
    
    Args:
        tool_executor: ToolExecutor instance
        
    Returns:
        Dictionary with setup results
    """
    print_colored = get_print_colored_function()
    iptables_script = tool_executor.loot_dir / "stealth_iptables.sh"
    
    results = {
        "script_path": str(iptables_script),
        "iptables_available": tool_executor.check_tool("iptables"),
        "status": "not_configured"
    }
    
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
        with open(iptables_script, 'w') as f:
            f.write(script_content)
        
        # Make executable
        iptables_script.chmod(0o755)
        results["script_written"] = True
        
        print_colored(f"📁 Stealth iptables script: {iptables_script}", "CYAN")
        
        if results["iptables_available"]:
            print_colored("ℹ️ Run the script as root to apply stealth rules", "BLUE")
            results["status"] = "script_ready"
        else:
            print_colored("⚠️ iptables not found. This is normal on non-Linux systems.", "YELLOW")
            results["status"] = "not_applicable"
    except Exception as e:
        print_colored(f"❌ Error creating iptables script: {str(e)}", "RED")
        results["error"] = str(e)
        results["status"] = "script_failed"
    
    return results

def generate_opsec_checklist(tool_executor):
    """
    Generate OPSEC checklist
    
    Args:
        tool_executor: ToolExecutor instance
        
    Returns:
        Dictionary with checklist results
    """
    print_colored = get_print_colored_function()
    checklist_file = tool_executor.loot_dir / "opsec_checklist.md"
    
    results = {
        "checklist_path": str(checklist_file),
        "status": "not_generated"
    }
    
    checklist_content = """# OPSEC Checklist

## Pre-Engagement
- [ ] VPN connection active
- [ ] Tor service running
- [ ] ProxyChains configured
- [ ] Burner email configured
- [ ] VM/Container environment
- [ ] Host firewall rules reviewed
- [ ] Time zone and locale settings modified
- [ ] System clock synchronized
- [ ] DNS leak protection active

## During Engagement
- [ ] All traffic routed through proxies
- [ ] No direct IP connections to target
- [ ] User agent randomization
- [ ] Rate limiting on scans
- [ ] Encrypted C2 channels
- [ ] Unique infrastructure per target
- [ ] Regular command history clearing
- [ ] Session timeout limits enforced
- [ ] Egress filtering verification
- [ ] Network activity monitoring
- [ ] Document all actions for reporting

## Post-Engagement
- [ ] Clear command history
- [ ] Remove temporary files
- [ ] Clear system logs
- [ ] Secure delete sensitive data
- [ ] Verify no persistence left behind
- [ ] Close all connections
- [ ] Document findings
- [ ] Sanitize report metadata
- [ ] Destroy ephemeral infrastructure
- [ ] Change credentials

## Continuous
- [ ] Monitor for blue team activity
- [ ] Rotate infrastructure regularly
- [ ] Use domain fronting
- [ ] Implement kill switches
- [ ] Regular OPSEC process review
- [ ] Update tools and techniques
- [ ] Review latest threat intelligence
"""
    
    try:
        with open(checklist_file, 'w') as f:
            f.write(checklist_content)
        
        print_colored(f"📁 OPSEC checklist: {checklist_file}", "CYAN")
        results["status"] = "generated"
    except Exception as e:
        print_colored(f"❌ Error generating OPSEC checklist: {str(e)}", "RED")
        results["error"] = str(e)
        results["status"] = "generation_failed"
    
    return results