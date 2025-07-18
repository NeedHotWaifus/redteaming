#!/usr/bin/env python3
"""
GUI Launcher for RedTeam Toolkit
"""

import sys
import os
from pathlib import Path

# Add the project directory to the path
ROOT_DIR = Path(__file__).parent.absolute()
sys.path.insert(0, str(ROOT_DIR))

def main():
    try:
        # Import the correct function name (start_gui instead of run_gui)
        from gui import start_gui
        
        # Add version check for tkinter
        import tkinter as tk
        print(f"Using Tkinter version: {tk.TkVersion}")
        
        # Launch the GUI
        start_gui()
    except ImportError as e:
        print(f"Error importing GUI modules: {e}")
        print("Make sure all required components are installed.")
        print("\nTrying fallback import method...")
        
        try:
            # Fallback method - direct import from main_window
            from gui.main_window import start_gui
            start_gui()
        except ImportError as e2:
            print(f"Fallback import also failed: {e2}")
            print("\nPlease check that the following files exist:")
            print("- gui/__init__.py")
            print("- gui/main_window.py")
    except Exception as e:
        print(f"Error launching GUI: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
