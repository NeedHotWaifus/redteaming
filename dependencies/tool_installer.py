"""
RedTeam Toolkit Tool Installer
Handles automatic installation of required tools for both Windows and Linux platforms
"""

import os
import sys
import subprocess
import platform
import shutil
import logging
import time
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Union, Callable

# Set up logging
logger = logging.getLogger("tool_installer")
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Root directory
ROOT_DIR = Path(__file__).parent.parent.absolute()
TOOLS_DIR = ROOT_DIR / "tools"

# Tool definitions - name, description, and installation methods for different platforms
TOOLS = {
    # Reconnaissance Tools
    "nmap": {
        "description": "Network mapper and port scanner",
        "category": "recon",
        "windows": {
            "choco": "nmap",
            "winget": "Insecure.Nmap",
            "scoop": "nmap",
        },
        "linux": {
            "apt": "nmap",
            "yum": "nmap",
            "dnf": "nmap",
            "pacman": "nmap",
        },
        "check_command": "nmap --version"
    },
    "amass": {
        "description": "Network mapping of attack surfaces and external asset discovery",
        "category": "recon",
        "windows": {
            "choco": "amass",
            "scoop": "amass",
        },
        "linux": {
            "apt": "amass",
            "snap": "amass",
            "go": "github.com/OWASP/Amass/v3/...",
        },
        "check_command": "amass -version"
    },
    "subfinder": {
        "description": "Subdomain discovery tool",
        "category": "recon",
        "windows": {
            "go": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        },
        "linux": {
            "go": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "apt": "subfinder",
        },
        "check_command": "subfinder -version"
    },
    "gobuster": {
        "description": "Directory/file, DNS and VHost busting tool",
        "category": "recon",
        "windows": {
            "go": "github.com/OJ/gobuster/v3@latest",
        },
        "linux": {
            "apt": "gobuster",
            "go": "github.com/OJ/gobuster/v3@latest",
        },
        "check_command": "gobuster --version"
    },
    
    # Additional Reconnaissance Tools
    "masscan": {
        "description": "TCP port scanner, faster than nmap",
        "category": "recon",
        "windows": {
            "choco": "masscan",
        },
        "linux": {
            "apt": "masscan",
            "yum": "masscan",
            "dnf": "masscan",
            "pacman": "masscan",
        },
        "check_command": "masscan --version"
    },
    "whatweb": {
        "description": "Web scanner to identify web technologies",
        "category": "recon",
        "windows": {
            "gem": "whatweb",
        },
        "linux": {
            "apt": "whatweb",
            "gem": "whatweb",
        },
        "check_command": "whatweb --version"
    },
    "fierce": {
        "description": "DNS reconnaissance tool",
        "category": "recon",
        "windows": {
            "pip": "fierce",
        },
        "linux": {
            "apt": "fierce",
            "pip": "fierce",
        },
        "check_command": "fierce --version"
    },
    "theharvester": {
        "description": "E-mail, subdomain and people gathering",
        "category": "recon",
        "windows": {
            "pip": "theharvester",
        },
        "linux": {
            "apt": "theharvester",
            "pip": "theharvester",
        },
        "check_command": "theHarvester -h"
    },
    "httpx": {
        "description": "Fast HTTP probing",
        "category": "recon",
        "windows": {
            "go": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        },
        "linux": {
            "go": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        },
        "check_command": "httpx -version"
    },
    
    # Vulnerability Scanning Tools
    "nuclei": {
        "description": "Template-based vulnerability scanner",
        "category": "vuln_scan",
        "windows": {
            "go": "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
        },
        "linux": {
            "go": "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
        },
        "check_command": "nuclei -version"
    },
    "nikto": {
        "description": "Web server scanner",
        "category": "vuln_scan",
        "windows": {
            "choco": "nikto",
        },
        "linux": {
            "apt": "nikto",
            "yum": "nikto",
            "dnf": "nikto",
        },
        "check_command": "nikto -Version"
    },
    "wpscan": {
        "description": "WordPress vulnerability scanner",
        "category": "vuln_scan",
        "windows": {
            "gem": "wpscan",
        },
        "linux": {
            "apt": "wpscan",
            "gem": "wpscan",
        },
        "check_command": "wpscan --version"
    },
    
    # Web Application Testing Tools
    "burpsuite": {
        "description": "Web vulnerability scanner and proxy",
        "category": "web",
        "windows": {
            "choco": "burp-suite-free-edition",
        },
        "linux": {
            "apt": "burpsuite",
            "snap": "burpsuite-free",
        },
        "check_command": "burpsuite --version"
    },
    "sqlmap": {
        "description": "Automatic SQL injection tool",
        "category": "web",
        "windows": {
            "choco": "sqlmap",
            "pip": "sqlmap",
        },
        "linux": {
            "apt": "sqlmap",
            "pip": "sqlmap",
        },
        "check_command": "sqlmap --version"
    },
    "ffuf": {
        "description": "Fast web fuzzer",
        "category": "web",
        "windows": {
            "go": "github.com/ffuf/ffuf@latest",
        },
        "linux": {
            "go": "github.com/ffuf/ffuf@latest",
        },
        "check_command": "ffuf -V"
    },
    "zap": {
        "description": "OWASP Zed Attack Proxy",
        "category": "web",
        "windows": {
            "choco": "owasp-zap",
        },
        "linux": {
            "snap": "zaproxy",
        },
        "check_command": "zap.sh -version"
    },
    
    # Exploitation Frameworks
    "metasploit": {
        "description": "Penetration testing framework",
        "category": "exploit",
        "windows": {
            "choco": "metasploit",
            "manual": "https://windows.metasploit.com/metasploitframework-latest.msi"
        },
        "linux": {
            "apt": "metasploit-framework",
            "installer": "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall",
        },
        "check_command": "msfconsole --version"
    },
    "searchsploit": {
        "description": "Exploit-DB search tool",
        "category": "exploit",
        "windows": {
            "manual": "git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb",
        },
        "linux": {
            "apt": "exploitdb",
            "yum": "exploitdb",
            "dnf": "exploitdb",
        },
        "check_command": "searchsploit --version"
    },
    "beef": {
        "description": "Browser Exploitation Framework",
        "category": "exploit",
        "windows": {
            "manual": "git clone https://github.com/beefproject/beef.git",
        },
        "linux": {
            "apt": "beef-xss",
            "gem": "beef",
        },
        "check_command": "beef --version"
    },
    
    # Post-Exploitation Tools
    "impacket": {
        "description": "Collection of Python classes for working with network protocols",
        "category": "post-exploit",
        "windows": {
            "pip": "impacket",
        },
        "linux": {
            "pip": "impacket",
            "apt": "python3-impacket",
        },
        "check_command": "GetADUsers.py --help"
    },
    "empire": {
        "description": "PowerShell post-exploitation framework",
        "category": "post-exploit",
        "windows": {
            "manual": "git clone https://github.com/BC-SECURITY/Empire.git",
        },
        "linux": {
            "manual": "git clone https://github.com/BC-SECURITY/Empire.git",
        },
        "check_command": "empire --version"
    },
    "mimikatz": {
        "description": "Windows credential dumping tool",
        "category": "post-exploit",
        "windows": {
            "manual": "https://github.com/gentilkiwi/mimikatz/releases/latest",
        },
        "linux": {
            "manual": "https://github.com/gentilkiwi/mimikatz/releases/latest",
        },
        "check_command": "mimikatz.exe --version"
    },
    "bloodhound": {
        "description": "Active Directory visualization tool",
        "category": "post-exploit",
        "windows": {
            "choco": "bloodhound",
        },
        "linux": {
            "apt": "bloodhound",
            "npm": "bloodhound",
        },
        "check_command": "bloodhound --version"
    },
    "chisel": {
        "description": "Fast TCP/UDP tunnel",
        "category": "post-exploit",
        "windows": {
            "go": "github.com/jpillora/chisel@latest",
        },
        "linux": {
            "go": "github.com/jpillora/chisel@latest",
        },
        "check_command": "chisel --version"
    },
    
    # Password Tools
    "hashcat": {
        "description": "Advanced password recovery utility",
        "category": "password",
        "windows": {
            "choco": "hashcat",
        },
        "linux": {
            "apt": "hashcat",
            "yum": "hashcat",
            "dnf": "hashcat",
        },
        "check_command": "hashcat --version"
    },
    "john": {
        "description": "John the Ripper password cracker",
        "category": "password",
        "windows": {
            "choco": "john",
        },
        "linux": {
            "apt": "john",
            "yum": "john",
            "dnf": "john",
        },
        "check_command": "john --version"
    },
    "hydra": {
        "description": "Online password cracking tool",
        "category": "password",
        "windows": {
            "choco": "hydra",
        },
        "linux": {
            "apt": "hydra",
            "yum": "hydra",
            "dnf": "hydra",
        },
        "check_command": "hydra -h"
    },
    "crackmapexec": {
        "description": "Post-exploitation tool",
        "category": "password",
        "windows": {
            "pip": "crackmapexec",
        },
        "linux": {
            "apt": "crackmapexec",
            "pip": "crackmapexec",
        },
        "check_command": "crackmapexec --version"
    },
    
    # Social Engineering Tools
    "gophish": {
        "description": "Phishing framework",
        "category": "social",
        "windows": {
            "manual": "https://github.com/gophish/gophish/releases/latest",
        },
        "linux": {
            "manual": "https://github.com/gophish/gophish/releases/latest",
        },
        "check_command": "gophish --version"
    },
    "social-engineer-toolkit": {
        "description": "Social Engineering Toolkit",
        "category": "social",
        "windows": {
            "manual": "git clone https://github.com/trustedsec/social-engineer-toolkit.git",
        },
        "linux": {
            "apt": "set",
            "manual": "git clone https://github.com/trustedsec/social-engineer-toolkit.git",
        },
        "check_command": "setoolkit --version"
    },
    
    # Wireless Testing Tools
    "aircrack-ng": {
        "description": "WiFi security auditing tools suite",
        "category": "wireless",
        "windows": {
            "choco": "aircrack-ng",
        },
        "linux": {
            "apt": "aircrack-ng",
            "yum": "aircrack-ng",
            "dnf": "aircrack-ng",
        },
        "check_command": "aircrack-ng --version"
    },
    "wifite": {
        "description": "Automated wireless attack tool",
        "category": "wireless",
        "windows": {
            "manual": "git clone https://github.com/derv82/wifite2.git",
        },
        "linux": {
            "apt": "wifite",
            "pip": "wifite",
        },
        "check_command": "wifite --version"
    },
    
    # Command & Control Frameworks
    "sliver": {
        "description": "Modern cross-platform C2 framework",
        "category": "c2",
        "windows": {
            "manual": "https://github.com/BishopFox/sliver/releases/latest",
        },
        "linux": {
            "manual": "https://github.com/BishopFox/sliver/releases/latest",
        },
        "check_command": "sliver-server --version"
    },
    "cobaltstrike": {
        "description": "Commercial adversary simulation software",
        "category": "c2",
        "windows": {
            "manual": "https://www.cobaltstrike.com/download",
        },
        "linux": {
            "manual": "https://www.cobaltstrike.com/download",
        },
        "check_command": "cobaltstrike --version"
    },
    "covenant": {
        "description": ".NET command and control framework",
        "category": "c2",
        "windows": {
            "manual": "git clone --recurse-submodules https://github.com/cobbr/Covenant",
        },
        "linux": {
            "manual": "git clone --recurse-submodules https://github.com/cobbr/Covenant",
        },
        "check_command": "Covenant --version"
    },
    
    # Evasion & OPSEC Tools
    "veil": {
        "description": "Payload generator to bypass anti-virus",
        "category": "evasion",
        "windows": {
            "manual": "git clone https://github.com/Veil-Framework/Veil.git",
        },
        "linux": {
            "manual": "git clone https://github.com/Veil-Framework/Veil.git",
        },
        "check_command": "veil --version"
    },
    "shellter": {
        "description": "Dynamic shellcode injection tool",
        "category": "evasion",
        "windows": {
            "manual": "https://www.shellterproject.com/download/",
        },
        "linux": {
            "manual": "https://www.shellterproject.com/download/",
        },
        "check_command": "shellter --version"
    },
    "proxychains": {
        "description": "Proxy chains for anonymity",
        "category": "evasion",
        "windows": {
            "manual": "git clone https://github.com/haad/proxychains-ng.git",
        },
        "linux": {
            "apt": "proxychains4",
            "yum": "proxychains-ng",
            "dnf": "proxychains-ng",
        },
        "check_command": "proxychains4 --version"
    },
    
    # OSINT Tools
    "spiderfoot": {
        "description": "Open source intelligence automation tool",
        "category": "osint",
        "windows": {
            "pip": "spiderfoot",
        },
        "linux": {
            "pip": "spiderfoot",
        },
        "check_command": "spiderfoot --version"
    },
    "maltego": {
        "description": "Interactive data mining tool",
        "category": "osint",
        "windows": {
            "manual": "https://www.maltego.com/downloads/",
        },
        "linux": {
            "manual": "https://www.maltego.com/downloads/",
        },
        "check_command": "maltego --version"
    },
    
    # Utility Tools
    "python3": {
        "description": "Python programming language",
        "category": "utility",
        "windows": {
            "choco": "python3",
            "winget": "Python.Python.3",
        },
        "linux": {
            "apt": "python3 python3-pip python3-dev",
            "yum": "python3 python3-pip python3-devel",
            "dnf": "python3 python3-pip python3-devel",
        },
        "check_command": "python3 --version"
    },
    "git": {
        "description": "Version control system",
        "category": "utility",
        "windows": {
            "choco": "git",
            "winget": "Git.Git",
        },
        "linux": {
            "apt": "git",
            "yum": "git",
            "dnf": "git",
        },
        "check_command": "git --version"
    },
    "curl": {
        "description": "Command line tool for transferring data with URL syntax",
        "category": "utility",
        "windows": {
            "choco": "curl",
            "winget": "cURL.cURL",
        },
        "linux": {
            "apt": "curl",
            "yum": "curl",
            "dnf": "curl",
        },
        "check_command": "curl --version"
    },
    "wget": {
        "description": "Internet file retriever",
        "category": "utility",
        "windows": {
            "choco": "wget",
            "winget": "GnuWin32.Wget",
        },
        "linux": {
            "apt": "wget",
            "yum": "wget",
            "dnf": "wget",
        },
        "check_command": "wget --version"
    }
}

class ToolInstaller:
    def __init__(self, tools_dir: Path = TOOLS_DIR, interactive: bool = True, log_level: int = logging.INFO):
        """
        Initialize the tool installer.
        
        Args:
            tools_dir: Directory to install tools to
            interactive: Whether to prompt for confirmation
            log_level: Logging level
        """
        self.tools_dir = tools_dir
        self.interactive = interactive
        self.os_type = platform.system().lower()
        self.package_managers = self._detect_package_managers()
        self.tools_installed = 0
        self.tools_failed = 0
        
        # Set up logging
        self.logger = logging.getLogger("ToolInstaller")
        self.logger.setLevel(log_level)
        
        # Create tools directory if it doesn't exist
        os.makedirs(self.tools_dir, exist_ok=True)

    def _detect_package_managers(self) -> Dict[str, bool]:
        """
        Detect which package managers are available on the system.
        
        Returns:
            Dictionary of package managers and whether they're available
        """
        managers = {}
        
        if self.os_type == "windows":
            managers["choco"] = self._check_command("choco")
            managers["winget"] = self._check_command("winget")
            managers["scoop"] = self._check_command("scoop")
            managers["pip"] = self._check_command("pip") or self._check_command("pip3")
            managers["go"] = self._check_command("go")
        else:  # Linux or other Unix-like
            managers["apt"] = self._check_command("apt-get")
            managers["yum"] = self._check_command("yum")
            managers["dnf"] = self._check_command("dnf")
            managers["pacman"] = self._check_command("pacman")
            managers["snap"] = self._check_command("snap")
            managers["pip"] = self._check_command("pip") or self._check_command("pip3")
            managers["go"] = self._check_command("go")
        
        return managers

    def _check_command(self, command: str) -> bool:
        """Check if a command is available in the PATH"""
        return shutil.which(command) is not None
    
    def _run_command(self, command: Union[str, List[str]], shell: bool = False, timeout: int = 300) -> Tuple[bool, str]:
        """
        Run a command and return success status and output.
        
        Args:
            command: Command to run, either as a string or list of arguments
            shell: Whether to run through shell
            timeout: Command timeout in seconds
            
        Returns:
            Tuple of (success boolean, command output/error)
        """
        try:
            if isinstance(command, str) and not shell:
                command = command.split()
                
            result = subprocess.run(
                command, 
                shell=shell, 
                capture_output=True, 
                text=True, 
                timeout=timeout
            )
            
            output = (result.stdout or "") + (result.stderr or "")
            return result.returncode == 0, output
        except subprocess.TimeoutExpired:
            return False, f"Command timed out after {timeout} seconds"
        except Exception as e:
            return False, f"Error running command: {str(e)}"

    def check_tool(self, tool_name: str) -> bool:
        """
        Check if a tool is already installed.
        
        Args:
            tool_name: Name of the tool to check
            
        Returns:
            True if tool is installed, False otherwise
        """
        if tool_name not in TOOLS:
            self.logger.warning(f"Unknown tool: {tool_name}")
            return False
            
        check_command = TOOLS[tool_name].get("check_command")
        if not check_command:
            return self._check_command(tool_name)
        
        success, _ = self._run_command(check_command)
        return success

    def install_tool(self, tool_name: str) -> bool:
        """
        Install a specific tool.
        
        Args:
            tool_name: Name of the tool to install
            
        Returns:
            True if installation succeeded, False otherwise
        """
        if tool_name not in TOOLS:
            self.logger.error(f"Unknown tool: {tool_name}")
            return False
            
        # Check if already installed
        if self.check_tool(tool_name):
            self.logger.info(f"✅ {tool_name} is already installed")
            return True
            
        tool_info = TOOLS[tool_name]
        
        # Get OS-specific installation methods
        if self.os_type == "windows":
            install_methods = tool_info.get("windows", {})
        else:
            install_methods = tool_info.get("linux", {})
            
        if not install_methods:
            self.logger.error(f"No installation methods available for {tool_name} on {self.os_type}")
            return False
            
        # Try each available package manager in order of preference
        for manager, package in install_methods.items():
            if manager in self.package_managers and self.package_managers[manager]:
                self.logger.info(f"📦 Installing {tool_name} using {manager}...")
                
                if manager == "choco":
                    success, output = self._run_command(f"choco install {package} -y")
                elif manager == "winget":
                    success, output = self._run_command(f"winget install {package} --accept-package-agreements --accept-source-agreements")
                elif manager == "scoop":
                    success, output = self._run_command(f"scoop install {package}")
                elif manager == "apt":
                    success, output = self._run_command(f"sudo apt-get install -y {package}")
                elif manager == "yum":
                    success, output = self._run_command(f"sudo yum install -y {package}")
                elif manager == "dnf":
                    success, output = self._run_command(f"sudo dnf install -y {package}")
                elif manager == "pacman":
                    success, output = self._run_command(f"sudo pacman -S --noconfirm {package}")
                elif manager == "snap":
                    success, output = self._run_command(f"sudo snap install {package}")
                elif manager == "pip":
                    success, output = self._run_command(f"pip install {package}")
                elif manager == "go":
                    success, output = self._run_command(f"go install {package}")
                elif manager == "installer":
                    success, output = self._run_command(package, shell=True)
                elif manager == "manual":
                    self.logger.info(f"Manual installation required: {package}")
                    return False
                else:
                    self.logger.error(f"Unknown package manager: {manager}")
                    continue
                    
                if success:
                    self.logger.info(f"✅ Successfully installed {tool_name}")
                    self.tools_installed += 1
                    return True
                else:
                    self.logger.error(f"❌ Failed to install {tool_name} using {manager}: {output}")
        
        self.tools_failed += 1
        return False

    def install_tools(self, tool_names: List[str] = None, category: str = None) -> Dict[str, bool]:
        """
        Install multiple tools, either by name or category.
        
        Args:
            tool_names: List of specific tools to install, or None to use category
            category: Category of tools to install, or None to install all
            
        Returns:
            Dictionary of tool names and installation success status
        """
        results = {}
        
        if tool_names:
            tools_to_install = [t for t in tool_names if t in TOOLS]
        elif category:
            tools_to_install = [t for t, info in TOOLS.items() if info.get("category") == category]
        else:
            tools_to_install = list(TOOLS.keys())
            
        total_tools = len(tools_to_install)
        self.logger.info(f"🔍 Installing {total_tools} tools...")
        
        for i, tool in enumerate(tools_to_install, 1):
            self.logger.info(f"[{i}/{total_tools}] Installing {tool}: {TOOLS[tool]['description']}")
            success = self.install_tool(tool)
            results[tool] = success
            
        self.logger.info(f"📊 Installation Summary:")
        self.logger.info(f"✅ Successfully installed: {self.tools_installed}")
        if self.tools_failed > 0:
            self.logger.warning(f"❌ Failed installations: {self.tools_failed}")
        
        return results

    def install_all_tools(self) -> Dict[str, bool]:
        """Install all tools defined in the TOOLS dictionary"""
        return self.install_tools()

    def install_essential_tools(self) -> Dict[str, bool]:
        """Install only the essential tools needed for basic functionality"""
        essential_tools = ["python3", "git", "curl", "wget", "nmap"]
        return self.install_tools(tool_names=essential_tools)

    def install_recon_tools(self) -> Dict[str, bool]:
        """Install reconnaissance tools"""
        return self.install_tools(category="recon")

    def install_exploitation_tools(self) -> Dict[str, bool]:
        """Install exploitation tools"""
        return self.install_tools(category="exploit")

    def install_post_exploitation_tools(self) -> Dict[str, bool]:
        """Install post-exploitation tools"""
        return self.install_tools(category="post-exploit")

    def update_package_managers(self) -> None:
        """Update package managers to ensure latest packages are available"""
        if self.os_type == "windows":
            if self.package_managers.get("choco"):
                self.logger.info("📦 Updating Chocolatey...")
                self._run_command("choco upgrade chocolatey -y")
                
            if self.package_managers.get("scoop"):
                self.logger.info("📦 Updating Scoop...")
                self._run_command("scoop update")
        else:
            if self.package_managers.get("apt"):
                self.logger.info("📦 Updating APT package lists...")
                self._run_command("sudo apt-get update")
                
            if self.package_managers.get("snap"):
                self.logger.info("📦 Refreshing Snap...")
                self._run_command("sudo snap refresh")

def main():
    """Main function when script is run directly"""
    import argparse
    
    parser = argparse.ArgumentParser(description="RedTeam Toolkit Tool Installer")
    parser.add_argument("--all", action="store_true", help="Install all tools")
    parser.add_argument("--essential", action="store_true", help="Install only essential tools")
    parser.add_argument("--recon", action="store_true", help="Install reconnaissance tools")
    parser.add_argument("--exploit", action="store_true", help="Install exploitation tools")
    parser.add_argument("--post-exploit", action="store_true", help="Install post-exploitation tools")
    parser.add_argument("--tools", nargs="+", help="Install specific tools by name")
    parser.add_argument("--non-interactive", action="store_true", help="Run without prompting")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    log_level = logging.DEBUG if args.verbose else logging.INFO
    installer = ToolInstaller(interactive=not args.non_interactive, log_level=log_level)
    
    # Update package managers first
    installer.update_package_managers()
    
    if args.all:
        installer.install_all_tools()
    elif args.essential:
        installer.install_essential_tools()
    elif args.recon:
        installer.install_recon_tools()
    elif args.exploit:
        installer.install_exploitation_tools()
    elif args.post_exploit:
        installer.install_post_exploitation_tools()
    elif args.tools:
        installer.install_tools(tool_names=args.tools)
    else:
        # If no specific option is given, prompt user
        print("Please select an installation option:")
        print("1) Install all tools")
        print("2) Install essential tools only")
        print("3) Install reconnaissance tools")
        print("4) Install exploitation tools")
        print("5) Install post-exploitation tools")
        print("0) Exit")
        
        try:
            choice = input("Enter your choice [0-5]: ").strip()
            
            if choice == "1":
                installer.install_all_tools()
            elif choice == "2":
                installer.install_essential_tools()
            elif choice == "3":
                installer.install_recon_tools()
            elif choice == "4":
                installer.install_exploitation_tools()
            elif choice == "5":
                installer.install_post_exploitation_tools()
            elif choice == "0":
                print("Exiting...")
            else:
                print("Invalid choice.")
        except KeyboardInterrupt:
            print("\nInstallation cancelled.")

if __name__ == "__main__":
    main()
