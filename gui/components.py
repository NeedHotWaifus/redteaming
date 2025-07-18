"""
GUI Components for RedTeam Toolkit
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import sys
import importlib
from pathlib import Path
import threading
import os
import logging

# Setup logger
logger = logging.getLogger(__name__)

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import config with fallback
try:
    import config
except ImportError as e:
    logger.warning(f"Error importing config: {e}")
    # Create a fallback config class
    class config:
        DEFAULT_TARGET = "example.com"
        DEFAULT_LHOST = "127.0.0.1"
        DEFAULT_LPORT = 4444
        ATTACKER_DOMAIN = "localhost"
        C2_SERVER_URL = "http://localhost"
        USE_TOR = False
        USE_PROXYCHAINS = False
        VPN_REQUIRED = True

# Safe import function for core modules
def safe_import(module_path):
    """Safely import a module, returning None if import fails"""
    try:
        module_parts = module_path.split('.')
        if len(module_parts) > 1:
            # For functions in modules
            module_name = '.'.join(module_parts[:-1])
            func_name = module_parts[-1]
            module = importlib.import_module(module_name)
            return getattr(module, func_name)
        else:
            # For direct module imports
            return importlib.import_module(module_path)
    except (ImportError, AttributeError) as e:
        logger.warning(f"Failed to import {module_path}: {e}")
        return None

# Import core modules with fallbacks
def dummy_function(*args, **kwargs):
    """Dummy function that returns a failure result"""
    return {
        "success": False, 
        "error": "Module not available or not implemented"
    }

# Import core modules with fallbacks
run_recon = safe_import('core.scanners.reconnaissance.run_recon') or dummy_function
run_initial_access = safe_import('core.payloads.generator.run_initial_access') or dummy_function
run_privilege_escalation = safe_import('core.exploits.privilege_escalation.run_privilege_escalation') or dummy_function
run_credential_access = safe_import('core.exploits.credential_access.run_credential_access') or dummy_function
run_post_exploitation = safe_import('core.c2.post_exploitation.run_post_exploitation') or dummy_function
run_av_edr_evasion = safe_import('core.payloads.evasion.run_av_edr_evasion') or dummy_function
run_persistence = safe_import('core.persistence.persistence.run_persistence') or dummy_function
run_opsec_anonymity = safe_import('core.utils.opsec.run_opsec_anonymity') or dummy_function


class BaseFrame(ttk.Frame):
    """Base frame for all module frames"""
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.parent = parent
        self._create_widgets()
        
    def _create_widgets(self):
        """Create widgets - to be implemented by subclasses"""
        pass
    
    def run_module(self, module_func, *args, **kwargs):
        """Run a module function in a separate thread"""
        self.controller.run_in_thread(module_func, *args, **kwargs)


class DashboardFrame(BaseFrame):
    """Dashboard/Home page frame"""
    def _create_widgets(self):
        # Get UI configuration values
        padding_x = getattr(config, 'UI_PADDING_X', 10)
        padding_y = getattr(config, 'UI_PADDING_Y', 5)
        header_font = getattr(config, 'HEADER_FONT', ("TkDefaultFont", 16, "bold"))
        
        # Header
        header_frame = ttk.Frame(self)
        header_frame.pack(fill=tk.X, padx=padding_x, pady=padding_y)
        
        ttk.Label(header_frame, text="RedTeam Toolkit Dashboard", 
                 font=header_font).pack(side=tk.LEFT)
        
        # Main dashboard content
        content_frame = ttk.Frame(self)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=padding_x, pady=padding_y)
        
        # Status overview
        status_frame = ttk.LabelFrame(content_frame, text="Status Overview")
        status_frame.pack(fill=tk.X, expand=False, padx=padding_y, pady=padding_y)
        
        # Grid for status items
        ttk.Label(status_frame, text="Current Target:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(status_frame, text=self.controller.target.get()).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(status_frame, text="Session ID:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(status_frame, text=self.controller.session_id).grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(status_frame, text="Toolkit Location:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(status_frame, text=str(self.controller.toolkit_dir)).grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Quick actions
        actions_frame = ttk.LabelFrame(content_frame, text="Quick Actions")
        actions_frame.pack(fill=tk.X, expand=False, padx=5, pady=5)
        
        ttk.Button(actions_frame, text="🔍 Run Reconnaissance", 
                  command=lambda: self.controller._show_recon()).grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        
        ttk.Button(actions_frame, text="💥 Generate Payloads", 
                  command=lambda: self.controller._show_payloads()).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Button(actions_frame, text="⚙️ Open Configuration", 
                  command=lambda: self.controller._show_config()).grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Information
        info_frame = ttk.LabelFrame(content_frame, text="Information")
        info_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Use a Text widget to display information
        info_text = tk.Text(info_frame, wrap=tk.WORD, height=15)
        info_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        welcome_text = """
Welcome to the RedTeam Toolkit GUI!

This toolkit provides a suite of tools for offensive security testing, organized around the stages of the attack lifecycle:

🔍 Reconnaissance - Gather information about the target
💥 Initial Access - Generate payloads and establish initial access
🔓 Privilege Escalation - Elevate privileges on compromised systems
🧠 Credential Access - Extract and use credentials
📡 Post-Exploitation - Maintain access and explore the network
🦠 AV/EDR Evasion - Bypass security controls
👻 Persistence - Establish persistence mechanisms
🔒 OPSEC - Maintain operational security

Use the navigation panel on the left to access each module.

⚠️ For authorized penetration testing use only ⚠️
"""
        info_text.insert(tk.END, welcome_text)
        info_text.config(state=tk.DISABLED)


class ReconFrame(BaseFrame):
    """Reconnaissance module frame"""
    def _create_widgets(self):
        # Header
        header_frame = ttk.Frame(self)
        header_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(header_frame, text="Reconnaissance", 
                 font=("TkDefaultFont", 16, "bold")).pack(side=tk.LEFT)
        
        # Target and options
        target_frame = ttk.LabelFrame(self, text="Target Settings")
        target_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(target_frame, text="Target:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.target_var = tk.StringVar(value=self.controller.target.get())
        ttk.Entry(target_frame, textvariable=self.target_var, width=40).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Recon tools options
        tools_frame = ttk.LabelFrame(self, text="Recon Tools")
        tools_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.tool_vars = {}
        recon_tools = ["nmap", "amass", "subfinder", "whatweb", "httpx", "gobuster"]
        
        for i, tool in enumerate(recon_tools):
            self.tool_vars[tool] = tk.BooleanVar(value=True)
            ttk.Checkbutton(tools_frame, text=tool, variable=self.tool_vars[tool]).grid(
                row=i // 3, column=i % 3, sticky=tk.W, padx=5, pady=2)
        
        # Action buttons
        action_frame = ttk.Frame(self)
        action_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(action_frame, text="Run Reconnaissance", 
                  command=self.run_reconnaissance).pack(side=tk.LEFT, padx=5, pady=5)
        
        ttk.Button(action_frame, text="View Results Directory", 
                  command=self.open_results_dir).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Results area
        results_frame = ttk.LabelFrame(self, text="Results")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD)
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.results_text.config(state=tk.DISABLED)
    
    def run_reconnaissance(self):
        """Run reconnaissance module"""
        target = self.target_var.get()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        self.controller.target.set(target)
        self.controller.update_status(f"Running reconnaissance on {target}...")
        
        # Update results area
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Starting reconnaissance on {target}...\n\n")
        self.results_text.config(state=tk.DISABLED)
        
        def run_and_update():
            try:
                results = run_recon(target, self.controller.tool_executor, 
                                   self.controller.session_id, self.controller.toolkit_dir)
                
                # Update results in GUI thread
                self.after(100, lambda: self.update_results(results))
            except Exception as e:
                self.after(100, lambda: self.show_error(str(e)))
        
        # Run in thread
        threading.Thread(target=run_and_update, daemon=True).start()
    
    def update_results(self, results):
        """Update results text widget with recon results"""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.insert(tk.END, f"Reconnaissance completed.\n\n")
        
        # Show summary of tools run
        self.results_text.insert(tk.END, "Tools executed:\n")
        for tool, result in results.items():
            status = "✓ Success" if result.get("success") else "✗ Failed"
            self.results_text.insert(tk.END, f"- {tool}: {status}\n")
        
        self.results_text.insert(tk.END, "\nSee the console output for detailed information.\n")
        self.results_text.insert(tk.END, f"Full results available in loot/{self.controller.target.get()}/\n")
        self.results_text.config(state=tk.DISABLED)
        
        self.controller.update_status("Reconnaissance completed")
    
    def show_error(self, error_msg):
        """Show error in results area"""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.insert(tk.END, f"Error: {error_msg}\n")
        self.results_text.config(state=tk.DISABLED)
        messagebox.showerror("Error", f"Reconnaissance failed: {error_msg}")
        self.controller.update_status("Reconnaissance failed")
    
    def open_results_dir(self):
        """Open the results directory"""
        target = self.controller.target.get()
        results_dir = self.controller.toolkit_dir / "loot" / target
        
        if not results_dir.exists():
            messagebox.showinfo("Info", "Results directory does not exist yet")
            return
            
        # Open directory using OS-specific method
        try:
            if sys.platform == 'win32':
                os.startfile(results_dir)
            elif sys.platform == 'darwin':  # macOS
                import subprocess
                subprocess.Popen(['open', results_dir])
            else:  # Linux
                import subprocess
                subprocess.Popen(['xdg-open', results_dir])
        except Exception as e:
            messagebox.showerror("Error", f"Could not open directory: {e}")


class PayloadFrame(BaseFrame):
    """Payload generation module frame"""
    def _create_widgets(self):
        # Header
        ttk.Label(self, text="Payload Generation", 
                 font=("TkDefaultFont", 16, "bold")).pack(fill=tk.X, padx=10, pady=5)
        
        # Main content frame with columns
        content_frame = ttk.Frame(self)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Left side - payload options
        options_frame = ttk.LabelFrame(content_frame, text="Payload Options")
        options_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5), pady=5)
        
        # Target settings
        ttk.Label(options_frame, text="Target:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.target_var = tk.StringVar(value=self.controller.target.get())
        ttk.Entry(options_frame, textvariable=self.target_var, width=20).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # LHOST/LPORT settings
        ttk.Label(options_frame, text="LHOST:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.lhost_var = tk.StringVar(value=getattr(config, 'DEFAULT_LHOST', '127.0.0.1'))
        ttk.Entry(options_frame, textvariable=self.lhost_var, width=20).grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(options_frame, text="LPORT:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.lport_var = tk.StringVar(value=getattr(config, 'DEFAULT_LPORT', '4444'))
        ttk.Entry(options_frame, textvariable=self.lport_var, width=20).grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Payload type
        ttk.Label(options_frame, text="Payload Type:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        self.payload_type = tk.StringVar(value="windows")
        payload_types = [
            ("Windows Reverse Shell", "windows"),
            ("Linux Reverse Shell", "linux"),
            ("Web Shell", "web"),
            ("Macro Document", "macro"),
            ("HTA Application", "hta")
        ]
        
        type_frame = ttk.Frame(options_frame)
        type_frame.grid(row=3, column=1, sticky=tk.W, padx=5, pady=5)
        
        for i, (text, value) in enumerate(payload_types):
            ttk.Radiobutton(type_frame, text=text, value=value, 
                           variable=self.payload_type).grid(row=i, column=0, sticky=tk.W)
        
        # Right side - generated payloads
        payloads_frame = ttk.LabelFrame(content_frame, text="Generated Payloads")
        payloads_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0), pady=5)
        
        # Listbox for payloads
        self.payload_listbox = tk.Listbox(payloads_frame, height=10)
        self.payload_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Buttons
        buttons_frame = ttk.Frame(self)
        buttons_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(buttons_frame, text="Generate Payload", 
                  command=self.generate_payload).pack(side=tk.LEFT, padx=5, pady=5)
        
        ttk.Button(buttons_frame, text="View Payload", 
                  command=self.view_payload).pack(side=tk.LEFT, padx=5, pady=5)
        
        ttk.Button(buttons_frame, text="Open Payloads Directory", 
                  command=self.open_payloads_dir).pack(side=tk.LEFT, padx=5, pady=5)
    
    def generate_payload(self):
        """Generate payload based on selected options"""
        target = self.target_var.get()
        lhost = self.lhost_var.get()
        lport = self.lport_var.get()
        payload_type = self.payload_type.get()
        
        if not target or not lhost or not lport:
            messagebox.showerror("Error", "Please fill in all required fields")
            return
        
        self.controller.target.set(target)
        self.controller.update_status(f"Generating {payload_type} payload...")
        
        # Clear previous payloads
        self.payload_listbox.delete(0, tk.END)
        
        def run_and_update():
            try:
                # Need a better way to map payload types
                if payload_type == "windows":
                    results = run_initial_access(target, self.controller.tool_executor, 
                                              self.controller.script_gen, self.controller.logger)
                    
                    # Update listbox in GUI thread
                    self.after(100, lambda: self.update_payload_list(results))
                # Add other payload types...
                
            except Exception as e:
                self.after(100, lambda: messagebox.showerror("Error", f"Payload generation failed: {e}"))
                self.controller.update_status("Payload generation failed")
        
        # Run in thread
        threading.Thread(target=run_and_update, daemon=True).start()
    
    def update_payload_list(self, results):
        """Update the payload listbox with generated payloads"""
        if not results.get("success", False):
            messagebox.showerror("Error", f"Payload generation failed: {results.get('error', 'Unknown error')}")
            self.controller.update_status("Payload generation failed")
            return
            
        # Add payloads to listbox
        payloads = results.get("payloads", {})
        if not payloads:
            self.payload_listbox.insert(tk.END, "No payloads generated")
            return
            
        for name, path in payloads.items():
            if path:
                self.payload_listbox.insert(tk.END, f"{name}: {Path(path).name}")
        
        self.controller.update_status("Payload generation completed")
    
    def view_payload(self):
        """View the selected payload"""
        selection = self.payload_listbox.curselection()
        if not selection:
            messagebox.showinfo("Info", "Please select a payload to view")
            return
            
        payload_info = self.payload_listbox.get(selection[0])
        if not payload_info or ":" not in payload_info:
            return
            
        payload_name = payload_info.split(":")[1].strip()
        target = self.controller.target.get()
        payload_dir = self.controller.toolkit_dir / "loot" / target
        
        # Try to find the payload file
        for file in payload_dir.glob("*"):
            if file.name == payload_name:
                self.show_file_content(file)
                return
        
        messagebox.showinfo("Info", f"Could not find payload file: {payload_name}")
    
    def show_file_content(self, file_path):
        """Show file content in a new window"""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                
            # Create new window
            view_window = tk.Toplevel(self)
            view_window.title(f"Payload: {file_path.name}")
            view_window.geometry("800x600")
            
            # Add text widget
            text = scrolledtext.ScrolledText(view_window, wrap=tk.NONE)
            text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            # Insert content
            text.insert(tk.END, content)
            
            # Add copy button
            ttk.Button(view_window, text="Copy to Clipboard", 
                      command=lambda: self.copy_to_clipboard(content)).pack(pady=5)
            
        except Exception as e:
            messagebox.showerror("Error", f"Could not read file: {e}")
    
    def copy_to_clipboard(self, text):
        """Copy text to clipboard"""
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Info", "Content copied to clipboard")
    
    def open_payloads_dir(self):
        """Open the payloads directory"""
        target = self.controller.target.get()
        payloads_dir = self.controller.toolkit_dir / "loot" / target
        
        if not payloads_dir.exists():
            messagebox.showinfo("Info", "Payloads directory does not exist yet")
            return
            
        # Open directory using OS-specific method
        try:
            if sys.platform == 'win32':
                os.startfile(payloads_dir)
            elif sys.platform == 'darwin':  # macOS
                import subprocess
                subprocess.Popen(['open', payloads_dir])
            else:  # Linux
                import subprocess
                subprocess.Popen(['xdg-open', payloads_dir])
        except Exception as e:
            messagebox.showerror("Error", f"Could not open directory: {e}")


# Define placeholder classes for other modules
# These would be fully implemented similar to ReconFrame and PayloadFrame
class PrivEscFrame(BaseFrame):
    def _create_widgets(self):
        ttk.Label(self, text="Privilege Escalation Module", font=("TkDefaultFont", 16, "bold")).pack()
        ttk.Label(self, text="This module will be implemented in the next version.").pack()

class CredAccessFrame(BaseFrame):
    def _create_widgets(self):
        ttk.Label(self, text="Credential Access Module", font=("TkDefaultFont", 16, "bold")).pack()
        ttk.Label(self, text="This module will be implemented in the next version.").pack()

class PostExploitFrame(BaseFrame):
    def _create_widgets(self):
        ttk.Label(self, text="Post Exploitation Module", font=("TkDefaultFont", 16, "bold")).pack()
        ttk.Label(self, text="This module will be implemented in the next version.").pack()

class EvasionFrame(BaseFrame):
    def _create_widgets(self):
        ttk.Label(self, text="AV/EDR Evasion Module", font=("TkDefaultFont", 16, "bold")).pack()
        ttk.Label(self, text="This module will be implemented in the next version.").pack()

class PersistenceFrame(BaseFrame):
    def _create_widgets(self):
        ttk.Label(self, text="Persistence Module", font=("TkDefaultFont", 16, "bold")).pack()
        ttk.Label(self, text="This module will be implemented in the next version.").pack()

class OpsecFrame(BaseFrame):
    def _create_widgets(self):
        ttk.Label(self, text="OPSEC Module", font=("TkDefaultFont", 16, "bold")).pack()
        ttk.Label(self, text="This module will be implemented in the next version.").pack()

class ConfigFrame(BaseFrame):
    """Configuration module frame"""
    def _create_widgets(self):
        # Header
        ttk.Label(self, text="Configuration", 
                 font=("TkDefaultFont", 16, "bold")).pack(fill=tk.X, padx=10, pady=5)
        
        # Create notebook for config categories
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # General settings
        general_frame = ttk.Frame(notebook)
        notebook.add(general_frame, text="General")
        
        # Target settings
        targets_frame = ttk.Frame(notebook)
        notebook.add(targets_frame, text="Targets")
        
        # Attacker settings
        attacker_frame = ttk.Frame(notebook)
        notebook.add(attacker_frame, text="Attacker")
        
        # Security settings
        security_frame = ttk.Frame(notebook)
        notebook.add(security_frame, text="Security")
        
        # General settings
        row = 0
        ttk.Label(general_frame, text="Default Target:").grid(row=row, column=0, sticky=tk.W, padx=10, pady=5)
        self.default_target_var = tk.StringVar(value=getattr(config, 'DEFAULT_TARGET', 'example.com'))
        ttk.Entry(general_frame, textvariable=self.default_target_var, width=30).grid(row=row, column=1, sticky=tk.W, padx=10, pady=5)
        row += 1
        
        ttk.Label(general_frame, text="Default LHOST:").grid(row=row, column=0, sticky=tk.W, padx=10, pady=5)
        self.default_lhost_var = tk.StringVar(value=getattr(config, 'DEFAULT_LHOST', '127.0.0.1'))
        ttk.Entry(general_frame, textvariable=self.default_lhost_var, width=30).grid(row=row, column=1, sticky=tk.W, padx=10, pady=5)
        row += 1
        
        ttk.Label(general_frame, text="Default LPORT:").grid(row=row, column=0, sticky=tk.W, padx=10, pady=5)
        self.default_lport_var = tk.StringVar(value=getattr(config, 'DEFAULT_LPORT', '4444'))
        ttk.Entry(general_frame, textvariable=self.default_lport_var, width=30).grid(row=row, column=1, sticky=tk.W, padx=10, pady=5)
        row += 1
        
        # Attacker settings
        row = 0
        ttk.Label(attacker_frame, text="Attacker Domain:").grid(row=row, column=0, sticky=tk.W, padx=10, pady=5)
        self.attacker_domain_var = tk.StringVar(value=getattr(config, 'ATTACKER_DOMAIN', 'localhost'))
        ttk.Entry(attacker_frame, textvariable=self.attacker_domain_var, width=30).grid(row=row, column=1, sticky=tk.W, padx=10, pady=5)
        row += 1
        
        ttk.Label(attacker_frame, text="C2 Server URL:").grid(row=row, column=0, sticky=tk.W, padx=10, pady=5)
        self.c2_server_url_var = tk.StringVar(value=getattr(config, 'C2_SERVER_URL', 'http://localhost'))
        ttk.Entry(attacker_frame, textvariable=self.c2_server_url_var, width=30).grid(row=row, column=1, sticky=tk.W, padx=10, pady=5)
        row += 1
        
        # Security settings
        row = 0
        self.use_tor_var = tk.BooleanVar(value=getattr(config, 'USE_TOR', False))
        ttk.Checkbutton(security_frame, text="Use Tor", variable=self.use_tor_var).grid(row=row, column=0, sticky=tk.W, padx=10, pady=5)
        row += 1
        
        self.use_proxychains_var = tk.BooleanVar(value=getattr(config, 'USE_PROXYCHAINS', False))
        ttk.Checkbutton(security_frame, text="Use ProxyChains", variable=self.use_proxychains_var).grid(row=row, column=0, sticky=tk.W, padx=10, pady=5)
        row += 1
        
        self.vpn_required_var = tk.BooleanVar(value=getattr(config, 'VPN_REQUIRED', True))
        ttk.Checkbutton(security_frame, text="VPN Required", variable=self.vpn_required_var).grid(row=row, column=0, sticky=tk.W, padx=10, pady=5)
        row += 1
        
        # Buttons
        buttons_frame = ttk.Frame(self)
        buttons_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(buttons_frame, text="Save Configuration", 
                  command=self.save_configuration).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(buttons_frame, text="Generate SSH Keys", 
                  command=self.generate_ssh_keys).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(buttons_frame, text="Reset to Defaults", 
                  command=self.reset_defaults).pack(side=tk.LEFT, padx=5)
    
    def save_configuration(self):
        """Save configuration to config module"""
        try:
            # Update config module
            config.DEFAULT_TARGET = self.default_target_var.get()
            config.DEFAULT_LHOST = self.default_lhost_var.get()
            config.DEFAULT_LPORT = int(self.default_lport_var.get())
            config.ATTACKER_DOMAIN = self.attacker_domain_var.get()
            config.C2_SERVER_URL = self.c2_server_url_var.get()
            config.USE_TOR = self.use_tor_var.get()
            config.USE_PROXYCHAINS = self.use_proxychains_var.get()
            config.VPN_REQUIRED = self.vpn_required_var.get()
            
            # Save to file if method exists
            if hasattr(config, 'save_config'):
                config.save_config()
                messagebox.showinfo("Success", "Configuration saved successfully")
                self.controller.update_status("Configuration saved")
            else:
                messagebox.showwarning("Warning", "Configuration saved in memory only (save_config method not found)")
                self.controller.update_status("Configuration saved in memory only")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save configuration: {e}")
            self.controller.update_status("Configuration save failed")
    
    def generate_ssh_keys(self):
        """Generate new SSH key pair"""
        try:
            from configs.keys import generate_ssh_key_pair
            
            if messagebox.askyesno("Confirm", "Generate new SSH key pair? This will overwrite existing keys."):
                key_pair = generate_ssh_key_pair()
                if key_pair:
                    config.SSH_PUBLIC_KEY = key_pair["public_key"]
                    messagebox.showinfo("Success", "SSH key pair generated successfully")
                    self.controller.update_status("SSH keys generated")
                else:
                    messagebox.showerror("Error", "Failed to generate SSH key pair")
        except ImportError:
            messagebox.showerror("Error", "Keys module not found")
    
    def reset_defaults(self):
        """Reset configuration to defaults"""
        if messagebox.askyesno("Confirm", "Reset all settings to defaults?"):
            self.default_target_var.set("example.com")
            self.default_lhost_var.set("127.0.0.1")
            self.default_lport_var.set("4444")
            self.attacker_domain_var.set("localhost")
            self.c2_server_url_var.set("http://localhost")
            self.use_tor_var.set(False)
            self.use_proxychains_var.set(False)
            self.vpn_required_var.set(True)
            
            messagebox.showinfo("Success", "Settings reset to defaults")
            self.controller.update_status("Configuration reset to defaults")
