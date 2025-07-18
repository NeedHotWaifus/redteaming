"""
Main GUI Window for RedTeam Toolkit
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import sys
import os
from pathlib import Path
import logging
import importlib
import traceback  # Add missing traceback import

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Setup basic configuration to avoid circular imports
TOOLKIT_DIR = Path(__file__).parent.parent.absolute()
CONFIG_IMPORTED = False

# Import config first
try:
    import config
    # Set the base directory in config
    config.BASE_DIR = TOOLKIT_DIR
    
    # Try to load existing configuration
    if hasattr(config, 'load_config'):
        config.load_config()
    CONFIG_IMPORTED = True
except ImportError as e:
    print(f"Warning: Config module not found: {e}")
    # Create fallback config
    class config:
        DEFAULT_TARGET = "example.com"
        DEFAULT_LHOST = "127.0.0.1"
        DEFAULT_LPORT = 4444
        BASE_DIR = TOOLKIT_DIR

# Now import the rest of the components with better error handling
try:
    from core.utils.executor import ToolExecutor
    from core.utils.script_generator import ScriptGenerator
    from core.utils.output import print_colored
except ImportError as e:
    print(f"Error importing core utilities: {e}")
    # Define fallback function for print_colored
    def print_colored(text, color=None, bold=False, end="\n"):
        print(text, end=end)
    
    # Define fallback classes
    class ToolExecutor:
        def __init__(self, session_id, target, toolkit_dir):
            self.session_id = session_id
            self.target = target
            self.toolkit_dir = toolkit_dir
            self.loot_dir = toolkit_dir / "loot" / target
            os.makedirs(self.loot_dir, exist_ok=True)
            
    class ScriptGenerator:
        def __init__(self, loot_dir):
            self.loot_dir = loot_dir

# Import core modules with fallbacks
def import_or_dummy(module_path, fallback_func=None):
    """Import a module or return a dummy function if import fails"""
    try:
        module_parts = module_path.split('.')
        module_name = '.'.join(module_parts[:-1])
        func_name = module_parts[-1]
        
        module = importlib.import_module(module_name)
        return getattr(module, func_name)
    except (ImportError, AttributeError) as e:
        print(f"Warning: Could not import {module_path}: {e}")
        return fallback_func or (lambda *args, **kwargs: {"success": False, "error": f"{module_path} not available"})

# Import core functionality with fallbacks
run_recon = import_or_dummy("core.scanners.reconnaissance.run_recon")
run_initial_access = import_or_dummy("core.payloads.generator.run_initial_access")
run_privilege_escalation = import_or_dummy("core.exploits.privilege_escalation.run_privilege_escalation")
run_credential_access = import_or_dummy("core.exploits.credential_access.run_credential_access")
run_post_exploitation = import_or_dummy("core.c2.post_exploitation.run_post_exploitation")
run_av_edr_evasion = import_or_dummy("core.payloads.evasion.run_av_edr_evasion")
run_persistence = import_or_dummy("core.persistence.persistence.run_persistence")
run_opsec_anonymity = import_or_dummy("core.utils.opsec.run_opsec_anonymity")

# Try to import theme, create fallback if not found
try:
    from gui.theme import apply_theme
except ImportError:
    # Fallback theme function
    def apply_theme(root, theme_name="default"):
        pass

# Import GUI components with placeholder implementation if missing
# Will create components module if needed
COMPONENTS_CREATED = False
# Simplify component imports with a more robust approach
try:
    from gui.components import (DashboardFrame, ReconFrame, PayloadFrame, 
                              PrivEscFrame, CredAccessFrame, PostExploitFrame,
                              EvasionFrame, PersistenceFrame, OpsecFrame, ConfigFrame)
except ImportError as e:
    print(f"Warning: GUI components not found: {e}")
    
    # Create a more minimal base frame
    class BaseFrame(ttk.Frame):
        """Base frame for all module frames"""
        def __init__(self, parent, controller):
            super().__init__(parent)
            self.controller = controller
            self.parent = parent
            self._create_widgets()
            
        def _create_widgets(self):
            frame = ttk.Frame(self, padding=20)
            frame.pack(expand=True, fill=tk.BOTH)
            
            ttk.Label(frame, text="Module Not Available", 
                     font=("TkDefaultFont", 14, "bold")).pack(pady=(0, 10))
            
            ttk.Label(frame, text="This module could not be loaded. Check your installation.",
                     wraplength=400).pack(pady=5)
            
            ttk.Button(frame, text="Check Installation", 
                      command=lambda: messagebox.showinfo(
                          "Installation", 
                          "Please verify that all required modules are installed and available.")
                      ).pack(pady=10)
    
    # Create all placeholder frames with a single factory function
    def create_placeholder(name):
        return type(name, (BaseFrame,), {"__doc__": f"{name} placeholder"})
    
    # Create all required frame classes
    DashboardFrame = create_placeholder("DashboardFrame")
    ReconFrame = create_placeholder("ReconFrame")
    PayloadFrame = create_placeholder("PayloadFrame")
    PrivEscFrame = create_placeholder("PrivEscFrame")
    CredAccessFrame = create_placeholder("CredAccessFrame")
    PostExploitFrame = create_placeholder("PostExploitFrame")
    EvasionFrame = create_placeholder("EvasionFrame")
    PersistenceFrame = create_placeholder("PersistenceFrame")
    OpsecFrame = create_placeholder("OpsecFrame")
    ConfigFrame = create_placeholder("ConfigFrame")

# Create components_dir variable before use
components_dir = TOOLKIT_DIR / "gui"

# Create components.py if it doesn't exist
components_file = components_dir / "components.py"
if not components_file.exists():
    with open(components_file, 'w') as f:
        f.write("""
# filepath: gui/components.py
\"\"\"
GUI Components for RedTeam Toolkit
\"\"\"

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import sys
from pathlib import Path

# Base class for all module frames
class BaseFrame(ttk.Frame):
    \"\"\"Base frame for all module frames\"\"\"
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.parent = parent
        self._create_widgets()
        
    def _create_widgets(self):
        \"\"\"Create widgets - to be implemented by subclasses\"\"\"
        ttk.Label(self, text="Module placeholder. Implementation coming soon!").pack(padx=20, pady=20)

# Module frame implementations
class DashboardFrame(BaseFrame):
    \"\"\"Dashboard/Home page frame\"\"\"
    pass

class ReconFrame(BaseFrame):
    \"\"\"Reconnaissance module frame\"\"\""
    pass

class PayloadFrame(BaseFrame):
    \"\"\"Payload generation module frame\"\"\""
    pass

class PrivEscFrame(BaseFrame):
    \"\"\"Privilege escalation module frame\"\"\""
    pass

class CredAccessFrame(BaseFrame):
    \"\"\"Credential access module frame\"\"\""
    pass

class PostExploitFrame(BaseFrame):
    \"\"\"Post-exploitation module frame\"\"\""
    pass

class EvasionFrame(BaseFrame):
    \"\"\"AV/EDR evasion module frame\"\"\""
    pass

class PersistenceFrame(BaseFrame):
    \"\"\"Persistence module frame\"\"\""
    pass

class OpsecFrame(BaseFrame):
    \"\"\"OPSEC module frame\"\"\""
    pass

class ConfigFrame(BaseFrame):
    \"\"\"Configuration module frame\"\"\""
    pass
""")
    
# Create __init__.py in gui directory if missing
init_file = components_dir / "__init__.py"
if not init_file.exists():
    with open(init_file, 'w') as f:
        f.write("""
# filepath: c:\\Users\\dougl\\OneDrive\\Documents\\redteaming\\gui\\__init__.py
\"\"\"
GUI components for RedTeam Toolkit
\"\"\"

from gui.main_window import RedTeamGUI
from gui.components import (
    DashboardFrame, ReconFrame, PayloadFrame, 
    PrivEscFrame, CredAccessFrame, PostExploitFrame,
    EvasionFrame, PersistenceFrame, OpsecFrame, ConfigFrame
)

__all__ = ['RedTeamGUI', 'start_gui']

def start_gui():
    \"\"\"Initialize and run the GUI application\"\"\"
    from gui.main_window import start_gui as _start_gui
    _start_gui()
""")

# Create theme.py if missing
theme_file = TOOLKIT_DIR / "gui" / "theme.py"
if not theme_file.exists():
    with open(theme_file, 'w') as f:
        f.write("""
# filepath: c:\\Users\\dougl\\OneDrive\\Documents\\redteaming\\gui\\theme.py
\"\"\"
Theme support for RedTeam Toolkit GUI
\"\"\"

import tkinter as tk
from tkinter import ttk
import sys

def apply_theme(root, theme_name="default"):
    \"\"\"Apply theme to the root window\"\"\"
    if theme_name == "dark":
        root.configure(background="#2b2b2b")
        style = ttk.Style(root)
        style.configure('TFrame', background="#2b2b2b")
        style.configure('TLabel', background="#2b2b2b", foreground="#e0e0e0")
        style.configure('TButton', background="#3c3f41")
    # Default theme - do nothing special
""")

class RedirectOutput:
    """Redirect stdout/stderr to a tkinter Text widget"""
    def __init__(self, text_widget):
        self.text_widget = text_widget
        self.buffer = ""
        
    def write(self, string):
        self.buffer += string
        self.text_widget.config(state=tk.NORMAL)
        self.text_widget.insert(tk.END, string)
        self.text_widget.see(tk.END)
        self.text_widget.config(state=tk.DISABLED)
        
    def flush(self):
        pass

class RedTeamGUI(tk.Tk):
    """Main GUI Application for RedTeam Toolkit"""
    def __init__(self):
        super().__init__()
        
        # Setup window
        self.title("RedTeam Toolkit")
        self.geometry("1200x800")
        self.minsize(1000, 700)
        
        # Create components_dir variable before use
        self.components_dir = TOOLKIT_DIR / "gui"
        
        # Initialize toolkit components
        self.toolkit_dir = Path(__file__).parent.parent
        self.session_id = self._generate_session_id()
        self.target = tk.StringVar(value=getattr(config, 'DEFAULT_TARGET', 'example.com'))
        self.status_var = tk.StringVar(value="Ready")
        self.running_thread = None
        
        # Set up logging
        self._setup_logging()
        
        # Create executor and script generator (will be initialized on first use)
        self.tool_executor = None
        self.script_gen = None
        
        # Apply theme
        apply_theme(self)
        
        # Create main layout
        self._create_layout()
        
        # Initialize modules
        self._initialize_tool_executor()
        
        # Update status
        self.update_status("RedTeam Toolkit GUI initialized")
        
    def _generate_session_id(self):
        """Generate a unique session ID"""
        import hashlib
        import time
        return hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        
    def _setup_logging(self):
        """Set up logging to file and GUI"""
        try:
            log_dir = self.toolkit_dir / "logs"
            os.makedirs(log_dir, exist_ok=True)
            log_file = log_dir / "gui.log"
            
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.FileHandler(log_file, encoding='utf-8'),
                ]
            )
            self.logger = logging.getLogger("RedTeamGUI")
            self.logger.info("GUI logging initialized")
        except Exception as e:
            print(f"Error setting up logging: {e}")
            self.logger = None
    
    def _create_layout(self):
        """Create the main application layout"""
        # Create main frame
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create left sidebar for navigation
        sidebar_frame = ttk.LabelFrame(main_frame, text="Navigation")
        sidebar_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        
        # Create content area
        content_frame = ttk.Frame(main_frame)
        content_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(content_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create bottom status bar
        status_frame = ttk.Frame(self)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)
        
        # Status bar content
        ttk.Label(status_frame, text="Target:").pack(side=tk.LEFT, padx=(0, 5))
        target_entry = ttk.Entry(status_frame, textvariable=self.target, width=30)
        target_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Label(status_frame, text="Status:").pack(side=tk.LEFT, padx=(10, 5))
        ttk.Label(status_frame, textvariable=self.status_var).pack(side=tk.LEFT)
        
        # Create sidebar buttons
        modules = [
            ("Dashboard", self._show_dashboard, "🏠"),
            ("Reconnaissance", self._show_recon, "🔍"),
            ("Payloads", self._show_payloads, "💥"),
            ("Privilege Escalation", self._show_privesc, "🔓"),
            ("Credential Access", self._show_credaccess, "🧠"),
            ("Post Exploitation", self._show_postexploit, "📡"),
            ("AV/EDR Evasion", self._show_evasion, "🦠"),
            ("Persistence", self._show_persistence, "👻"),
            ("OPSEC", self._show_opsec, "🔒"),
            ("Configuration", self._show_config, "⚙️"),
        ]
        
        for i, (name, command, emoji) in enumerate(modules):
            btn = ttk.Button(
                sidebar_frame, 
                text=f"{emoji} {name}", 
                command=command,
                width=20
            )
            btn.pack(fill=tk.X, padx=5, pady=2)
            
        # Create notebook tabs
        self.frames = {}
        
        # Create output console
        console_frame = ttk.LabelFrame(content_frame, text="Console Output")
        console_frame.pack(fill=tk.BOTH, expand=False, padx=5, pady=5, side=tk.BOTTOM, height=200)
        
        self.console = scrolledtext.ScrolledText(console_frame, state=tk.DISABLED, height=10)
        self.console.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Redirect stdout to console
        self.stdout_redirect = RedirectOutput(self.console)
        self.old_stdout = sys.stdout
        sys.stdout = self.stdout_redirect
        
        # Initialize with dashboard
        self._show_dashboard()
    
    def _initialize_tool_executor(self):
        """Initialize the tool executor with improved error handling"""
        try:
            target = self.target.get()
            if not hasattr(self, 'tool_executor') or self.tool_executor is None:
                self.tool_executor = ToolExecutor(self.session_id, target, self.toolkit_dir)
                self.script_gen = ScriptGenerator(self.tool_executor.loot_dir)
                self.logger.info("Tool executor initialized successfully")
            else:
                # Update target if changed
                self.tool_executor.target = target
                self.tool_executor.loot_dir = self.toolkit_dir / "loot" / target
                self.script_gen.loot_dir = self.tool_executor.loot_dir
                self.logger.info(f"Tool executor updated with target: {target}")
        except Exception as e:
            error_msg = f"Error initializing toolkit components: {e}"
            self.logger.error(f"{error_msg}\n{traceback.format_exc()}")
            messagebox.showerror("Initialization Error", error_msg)
            
            # Create fallback directories to prevent further errors
            try:
                loot_dir = self.toolkit_dir / "loot" / self.target.get()
                os.makedirs(loot_dir, exist_ok=True)
                if not hasattr(self, 'tool_executor') or self.tool_executor is None:
                    self.tool_executor = ToolExecutor(self.session_id, self.target.get(), self.toolkit_dir)
                if not hasattr(self, 'script_gen') or self.script_gen is None:
                    self.script_gen = ScriptGenerator(loot_dir)
            except Exception as fallback_error:
                self.logger.error(f"Failed to create fallback components: {fallback_error}")

    def update_status(self, message):
        """Update status bar message"""
        self.status_var.set(message)
        if self.logger:
            self.logger.info(message)
    
    def run_in_thread(self, func, *args, **kwargs):
        """Run a function in a separate thread"""
        if self.running_thread and self.running_thread.is_alive():
            messagebox.showwarning("Warning", "An operation is already running.")
            return
        
        def wrapper():
            try:
                self.update_status(f"Running {func.__name__}...")
                result = func(*args, **kwargs)
                self.update_status(f"Completed {func.__name__}")
                return result
            except Exception as e:
                self.update_status(f"Error in {func.__name__}: {e}")
                self.logger.error(f"Error in {func.__name__}: {e}")
                messagebox.showerror("Error", f"An error occurred: {e}")
            
        self.running_thread = threading.Thread(target=wrapper)
        self.running_thread.daemon = True
        self.running_thread.start()
    
    # Navigation methods
    def _show_dashboard(self):
        if "dashboard" not in self.frames:
            self.frames["dashboard"] = DashboardFrame(self.notebook, self)
            self.notebook.add(self.frames["dashboard"], text="Dashboard")
        self.notebook.select(self.notebook.index(self.frames["dashboard"]))
    
    def _show_recon(self):
        if "recon" not in self.frames:
            self.frames["recon"] = ReconFrame(self.notebook, self)
            self.notebook.add(self.frames["recon"], text="Reconnaissance")
        self.notebook.select(self.notebook.index(self.frames["recon"]))
    
    def _show_payloads(self):
        if "payloads" not in self.frames:
            self.frames["payloads"] = PayloadFrame(self.notebook, self)
            self.notebook.add(self.frames["payloads"], text="Payload Generation")
        self.notebook.select(self.notebook.index(self.frames["payloads"]))
    
    def _show_privesc(self):
        if "privesc" not in self.frames:
            self.frames["privesc"] = PrivEscFrame(self.notebook, self)
            self.notebook.add(self.frames["privesc"], text="Privilege Escalation")
        self.notebook.select(self.notebook.index(self.frames["privesc"]))
    
    def _show_credaccess(self):
        if "credaccess" not in self.frames:
            self.frames["credaccess"] = CredAccessFrame(self.notebook, self)
            self.notebook.add(self.frames["credaccess"], text="Credential Access")
        self.notebook.select(self.notebook.index(self.frames["credaccess"]))
    
    def _show_postexploit(self):
        if "postexploit" not in self.frames:
            self.frames["postexploit"] = PostExploitFrame(self.notebook, self)
            self.notebook.add(self.frames["postexploit"], text="Post Exploitation")
        self.notebook.select(self.notebook.index(self.frames["postexploit"]))
    
    def _show_evasion(self):
        if "evasion" not in self.frames:
            self.frames["evasion"] = EvasionFrame(self.notebook, self)
            self.notebook.add(self.frames["evasion"], text="AV/EDR Evasion")
        self.notebook.select(self.notebook.index(self.frames["evasion"]))
    
    def _show_persistence(self):
        if "persistence" not in self.frames:
            self.frames["persistence"] = PersistenceFrame(self.notebook, self)
            self.notebook.add(self.frames["persistence"], text="Persistence")
        self.notebook.select(self.notebook.index(self.frames["persistence"]))
    
    def _show_opsec(self):
        if "opsec" not in self.frames:
            self.frames["opsec"] = OpsecFrame(self.notebook, self)
            self.notebook.add(self.frames["opsec"], text="OPSEC")
        self.notebook.select(self.notebook.index(self.frames["opsec"]))
    
    def _show_config(self):
        if "config" not in self.frames:
            self.frames["config"] = ConfigFrame(self.notebook, self)
            self.notebook.add(self.frames["config"], text="Configuration")
        self.notebook.select(self.notebook.index(self.frames["config"]))
    
    def destroy(self):
        """Clean up on exit"""
        # Restore stdout
        sys.stdout = self.old_stdout
        
        # Log exit
        if self.logger:
            self.logger.info("Exiting GUI application")
            
        super().destroy()

def start_gui():
    """Start the GUI application"""
    app = RedTeamGUI()
    app.mainloop()

if __name__ == "__main__":
    start_gui()
