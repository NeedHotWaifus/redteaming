#!/usr/bin/env python3
"""
Archive old folders from previous RedTeam Toolkit structure
"""
import os
import shutil
from pathlib import Path
import sys

def archive_old_folders():
    """Move old folders to archive directory"""
    toolkit_dir = Path(__file__).parent.absolute()
    archive_dir = toolkit_dir / "archive"
    
    # Create archive directory if it doesn't exist
    os.makedirs(archive_dir, exist_ok=True)
    
    # List of folders to archive
    old_folders = ["temp", "results", "ai_modules"]
    
    print("📦 Archiving old folders...")
    
    for folder in old_folders:
        old_path = toolkit_dir / folder
        if old_path.exists():
            try:
                # Create a subfolder in archive
                archive_path = archive_dir / folder
                
                # If it already exists in archive, remove it first
                if archive_path.exists():
                    shutil.rmtree(archive_path)
                
                # Move the folder to archive
                shutil.move(str(old_path), str(archive_path))
                print(f"✅ Moved {folder} to archive")
            except Exception as e:
                print(f"❌ Error archiving {folder}: {e}")
        else:
            print(f"ℹ️ {folder} not found, skipping")
    
    print("📋 Archiving complete!")
    print(f"📁 Old folders are now in {archive_dir}")
    print("🔒 You can safely delete the archive folder if you don't need this data")

if __name__ == "__main__":
    try:
        archive_old_folders()
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
