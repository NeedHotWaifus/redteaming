"""
Reconnaissance Module
Handles target information gathering and scanning
"""

from pathlib import Path
from datetime import datetime
import sys
import re  # Add missing import for regex operations
import logging
from typing import Dict, Optional, List, Tuple

# Add configs directory to path for config import
TOOLKIT_DIR = Path(__file__).parent.parent.parent.absolute()
sys.path.insert(0, str(TOOLKIT_DIR / "configs"))

try:
    import config
except ImportError:
    # Fallback config values if import fails
    class config:
        RECON_OUTPUT_DIR = "loot/recon/"
        USER_AGENT = "Mozilla/5.0"

from core.utils.output import print_colored

def run_recon(target: str, tool_executor, session_id: str, toolkit_dir: Path):
    """
    Execute comprehensive reconnaissance phase
    
    Args:
        target: Target domain or IP
        tool_executor: ToolExecutor instance
        session_id: Current session ID
        toolkit_dir: Base toolkit directory
        
    Returns:
        Dictionary with reconnaissance results
    """
    # Import here to avoid circular imports
    from core.utils.output import print_colored
    
    print_colored(f"🔍 Running Reconnaissance on target: {target}", "GREEN", True)
    print()
    
    # Update tool executor target
    if tool_executor:
        tool_executor.target = target
        # Use config for output directory if available
        output_dir = getattr(config, 'RECON_OUTPUT_DIR', "loot")
        tool_executor.loot_dir = toolkit_dir / output_dir / target
        try:
            tool_executor.loot_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print_colored(f"⚠️ Warning: Cannot create loot directory: {e}", "YELLOW")
    
    # Use user agent from config for web tools
    user_agent = getattr(config, 'USER_AGENT', "Mozilla/5.0")
    
    # Define reconnaissance tools with proper file paths
    recon_tools = {
        "nmap": {
            "command": ["nmap", "-sV", "-sC", "-O", "--script", "vuln", 
                       "-oA", str(tool_executor.loot_dir / "nmap_scan"), target],
            "output_file": "nmap_results.txt",
            "description": "Comprehensive port scan with service detection"
        },
        "amass": {
            "command": ["amass", "enum", "-d", target, "-o", 
                       str(tool_executor.loot_dir / "amass_subdomains.txt")],
            "output_file": "amass_subdomains.txt",
            "description": "Subdomain enumeration"
        },
        "subfinder": {
            "command": ["subfinder", "-d", target, "-o", 
                       str(tool_executor.loot_dir / "subfinder_results.txt")],
            "output_file": "subfinder_results.txt", 
            "description": "Fast subdomain discovery"
        },
        "whatweb": {
            "command": ["whatweb", "-a", "3", "--log-brief", 
                       str(tool_executor.loot_dir / "whatweb_results.txt"), 
                       "--user-agent", user_agent, target],
            "output_file": "whatweb_results.txt",
            "description": "Web technology fingerprinting"
        },
        "httpx": {
            "command": ["httpx", "-u", target, "-title", "-tech-detect", "-status-code",
                       "-o", str(tool_executor.loot_dir / "httpx_results.txt")],
            "output_file": "httpx_results.txt",
            "description": "HTTP service probing"
        }
    }
    
    # Check if wordlist exists before using gobuster
    wordlist_path = Path("/usr/share/wordlists/dirb/common.txt")
    if wordlist_path.exists():
        recon_tools["gobuster"] = {
            "command": ["gobuster", "dir", "-u", f"http://{target}", "-w", 
                       str(wordlist_path), "-o",
                       str(tool_executor.loot_dir / "gobuster_dirs.txt")],
            "output_file": "gobuster_dirs.txt",
            "description": "Directory and file bruteforcing"
        }
    
    results = {}
    
    for tool_name, tool_config in recon_tools.items():
        print_colored(f"🔧 Running {tool_name}: {tool_config['description']}", "BLUE")
        
        if tool_executor:
            # Check if tool is available before running
            if not tool_executor.check_tool(tool_name):
                print_colored(f"❌ {tool_name} is not installed or not in PATH", "RED")
                results[tool_name] = {
                    "success": False,
                    "error": f"{tool_name} not found in PATH",
                    "command": " ".join(tool_config["command"])
                }
                print()
                continue
                
            result = tool_executor.execute_tool(
                tool_name, 
                tool_config["command"],
                tool_config.get("output_file"),
                timeout=600  # 10 minutes for recon tools
            )
            
            results[tool_name] = result
            
            if result["success"]:
                print_colored(f"✅ {tool_name} completed successfully", "GREEN")
                if result.get("output_file"):
                    print_colored(f"📁 Output saved to: loot/{target}/{result['output_file']}", "CYAN")
            else:
                print_colored(f"❌ {tool_name} failed: {result.get('error', 'Unknown error')}", "RED")
        else:
            print_colored(f"❌ Tool executor not available", "RED")
        
        print()
    
    # Generate reconnaissance summary
    generate_recon_summary(target, results, tool_executor, session_id)
    
    return results

def generate_recon_summary(target: str, results: Dict, tool_executor, session_id: str):
    """
    Compile available recon tool outputs into a comprehensive summary file.
    
    Args:
        target: Target domain or IP
        results: Dictionary with tool results
        tool_executor: ToolExecutor instance
        session_id: Current session ID
    """
    if not tool_executor:
        return
    
    # Import here to avoid circular imports
    from core.utils.output import print_colored
        
    summary_path = tool_executor.loot_dir / "recon_summary.md"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        with open(summary_path, "w", encoding="utf-8") as f:
            # Header
            f.write(f"# Reconnaissance Summary for {target}\n\n")
            f.write(f"**Generated:** {timestamp}  \n")
            f.write(f"**Session ID:** {session_id}  \n")
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
            
            # Key Findings First
            f.write("## Key Findings\n\n")
            
            # Extract key findings from tool output
            findings = extract_key_findings(results, target, tool_executor.loot_dir)
            
            if findings:
                for finding in findings:
                    f.write(f"- {finding}\n")
            else:
                f.write("- No significant findings detected in automated analysis\n")
            
            f.write("\n")
            
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
                        output_path = tool_executor.loot_dir / output_file
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
            
            # Next Steps
            f.write("## Recommended Next Steps\n\n")
            
            # Generate recommendations based on findings
            recommendations = generate_recommendations(findings, results)
            
            for rec in recommendations:
                f.write(f"- {rec}\n")
                
            f.write("\n")
            
            # File Locations
            f.write("## Output Files\n\n")
            for tool_name, result in results.items():
                if result.get("success") and result.get("output_file"):
                    f.write(f"- **{tool_name}:** `loot/{target}/{result['output_file']}`\n")
            
            f.write(f"\n**Summary Location:** `loot/{target}/recon_summary.md`\n")
            
        print_colored(f"📄 Comprehensive recon summary generated: {summary_path}", "CYAN")
        
    except Exception as e:
        print_colored(f"❌ Failed to generate recon summary: {str(e)}", "RED")

def extract_key_findings(results: Dict, target: str, loot_dir: Path) -> List[str]:
    """
    Extract key findings from tool outputs
    
    Args:
        results: Dictionary with tool results
        target: Target domain or IP
        loot_dir: Directory with output files
        
    Returns:
        List of key findings
    """
    findings = []
    
    # Check nmap results for open ports and services
    if "nmap" in results and results["nmap"].get("success"):
        findings.append("Port scan completed - check nmap output for open services")
        
        # Try to extract open ports from nmap output
        try:
            nmap_file = loot_dir / "nmap_results.txt"
            if nmap_file.exists():
                with open(nmap_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    # Extract open ports
                    open_ports = re.findall(r'(\d+)/tcp\s+open\s+(\w+)', content)
                    if open_ports:
                        ports_str = ", ".join([f"{port} ({service})" for port, service in open_ports[:5]])
                        if len(open_ports) > 5:
                            ports_str += f" and {len(open_ports) - 5} more"
                        findings.append(f"Found {len(open_ports)} open ports: {ports_str}")
                    
                    # Extract vulnerabilities
                    vulns = re.findall(r'VULNERABLE:(.*?)(\n\||\n[^\|])', content, re.DOTALL)
                    if vulns:
                        findings.append(f"Detected {len(vulns)} potential vulnerabilities in nmap scan")
        except Exception as e:
            # Improved error handling with logging
            logging.debug(f"Error parsing nmap results: {str(e)}")
    
    # Check subdomain enumeration
    subdomain_tools = ["amass", "subfinder"]
    for tool in subdomain_tools:
        if tool in results and results[tool].get("success"):
            try:
                if tool == "amass":
                    subdomains_file = loot_dir / "amass_subdomains.txt"
                else:
                    subdomains_file = loot_dir / "subfinder_results.txt"
                    
                if subdomains_file.exists():
                    with open(subdomains_file, 'r', encoding='utf-8', errors='ignore') as f:
                        subdomains = [line.strip() for line in f if line.strip()]
                        if subdomains:
                            findings.append(f"Found {len(subdomains)} subdomains with {tool}")
            except Exception as e:
                # Improved error handling
                logging.debug(f"Error parsing {tool} results: {str(e)}")
                findings.append(f"Subdomain enumeration completed with {tool}")
    
    # Check web technology detection
    if "whatweb" in results and results["whatweb"].get("success"):
        findings.append("Web technology fingerprinting completed")
        
        # Try to extract technologies
        try:
            whatweb_file = loot_dir / "whatweb_results.txt"
            if whatweb_file.exists():
                with open(whatweb_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    # Extract technologies
                    if "[" in content and "]" in content:
                        techs = re.findall(r'\[(.*?)\]', content)
                        if techs:
                            unique_techs = set()
                            for tech in techs:
                                parts = tech.split(',')
                                for part in parts:
                                    if ':' in part:
                                        name = part.split(':')[0].strip()
                                        if name and name.lower() not in ['http', 'ip', 'country', 'title']:
                                            unique_techs.add(name)
                            
                            if unique_techs:
                                tech_str = ", ".join(list(unique_techs)[:5])
                                if len(unique_techs) > 5:
                                    tech_str += f" and {len(unique_techs) - 5} more"
                                findings.append(f"Detected technologies: {tech_str}")
        except Exception as e:
            # Improved error handling
            logging.debug(f"Error parsing whatweb results: {str(e)}")
    
    # Check directory bruteforcing
    if "gobuster" in results and results["gobuster"].get("success"):
        try:
            gobuster_file = loot_dir / "gobuster_dirs.txt"
            if gobuster_file.exists():
                with open(gobuster_file, 'r', encoding='utf-8', errors='ignore') as f:
                    dirs = [line.strip() for line in f if line.strip() and ' (Status:' in line]
                    if dirs:
                        findings.append(f"Found {len(dirs)} directories/files with gobuster")
        except Exception as e:
            # Improved error handling
            logging.debug(f"Error parsing gobuster results: {str(e)}")
            findings.append("Directory bruteforcing completed")
    
    return findings

def generate_recommendations(findings: List[str], results: Dict) -> List[str]:
    """
    Generate recommendations based on findings
    
    Args:
        findings: List of key findings
        results: Dictionary with tool results
        
    Returns:
        List of recommendations
    """
    recommendations = [
        "Manually review all tool outputs for detailed findings",
        "Investigate open ports and services from nmap scan",
        "Analyze web application technologies for known CVEs"
    ]
    
    # Add recommendations based on findings
    if any("subdomain" in finding.lower() for finding in findings):
        recommendations.append("Test discovered subdomains for vulnerabilities")
        
    if any("directories" in finding.lower() for finding in findings):
        recommendations.append("Explore discovered directories and endpoints")
        
    if any("vulnerability" in finding.lower() for finding in findings):
        recommendations.append("Prioritize investigation of potential vulnerabilities identified by scanners")
        
    if "nmap" in results and results["nmap"].get("success"):
        recommendations.append("Consider targeted vulnerability scanning for detected services")
        
    if any("web" in finding.lower() for finding in findings):
        recommendations.append("Perform web application testing (SQLi, XSS, CSRF, etc.)")
    
    return recommendations