#!/usr/bin/env python3
"""
RedTeam Toolkit - Main Entry Point
"""

import sys
import os
import traceback
import argparse
from pathlib import Path

# Add the project root directory to the Python path
ROOT_DIR = Path(__file__).parent.absolute()
sys.path.insert(0, str(ROOT_DIR))

def check_environment():
    """Check if the environment is properly set up"""
    # Check core modules structure
    required_dirs = [
        "core",
        "core/utils",
        "core/payloads",
        "core/scanners",
        "core/exploits",
        "core/c2",
        "core/persistence"
    ]
    
    missing_dirs = []
    for d in required_dirs:
        if not (ROOT_DIR / d).exists():
            missing_dirs.append(d)
            
    if missing_dirs:
        print("❌ Required directories missing:")
        for d in missing_dirs:
            print(f"  - {d}")
        print("\n📋 Run setup.py or create these directories manually")
        return False
        
    # Check required files
    required_files = [
        "cli.py",
        "core/__init__.py",
        "core/utils/__init__.py"
    ]
    
    missing_files = []
    for f in required_files:
        if not (ROOT_DIR / f).exists():
            missing_files.append(f)
            
    if missing_files:
        print("❌ Required files missing:")
        for f in missing_files:
            print(f"  - {f}")
        print("\n📋 Run setup.py or create these files manually")
        return False
        
    return True

def main():
    # Check environment before proceeding
    if not check_environment():
        print("❌ Environment check failed. Please fix the issues above.")
        return
    
    try:
        # Create required directories
        for d in ["logs", "loot"]:
            os.makedirs(ROOT_DIR / d, exist_ok=True)
        
        # Import CLI class
        try:
            from cli import RedTeamCLI
        except ImportError as e:
            print(f"❌ Failed to import RedTeamCLI from cli.py: {e}")
            print("📋 Check that cli.py exists and contains the RedTeamCLI class")
            return
        
        # Parse arguments
        parser = argparse.ArgumentParser(description="RedTeam Toolkit CLI")
        parser.add_argument("--dry-run", action="store_true", help="Simulate actions without executing")
        parser.add_argument("--debug", action="store_true", help="Enable debug mode")
        args = parser.parse_args()
        
        # Run the CLI
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
