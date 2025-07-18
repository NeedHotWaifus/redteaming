"""
Script Generator Module
Handles the generation of scripts for various phases
"""

import os
from pathlib import Path

class ScriptGenerator:
    """
    Utility class for generating and saving scripts
    Used by various modules to create payload scripts, persistence mechanisms, etc.
    """
    def __init__(self, loot_dir: Path):
        """
        Initialize the script generator
        
        Args:
            loot_dir: Directory to save generated scripts
        """
        self.loot_dir = loot_dir

    def safe_write(self, filename: str, content: str, chmod_exec: bool = False):
        """
        Safely write content to a file
        
        Args:
            filename: Name of the file to create
            content: Content to write to the file
            chmod_exec: Whether to make the file executable
            
        Returns:
            Path to the created file or None if failed
        """
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

    def generate_template(self, template_name: str, replacements: dict) -> str:
        """
        Generate a script from a template with replacements
        
        Args:
            template_name: Name of the template to use
            replacements: Dictionary of placeholders and their values
            
        Returns:
            Processed template content
        """
        templates_dir = Path(__file__).parent.parent.parent / "templates"
        template_path = templates_dir / f"{template_name}.tpl"
        
        try:
            if not template_path.exists():
                # Return a basic template if file doesn't exist
                return f"# Generated {template_name} script\n# No template found\n\n"
                
            with open(template_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Replace placeholders with values
            for key, value in replacements.items():
                content = content.replace(f"{{{key}}}", str(value))
                
            return content
        except Exception as e:
            print(f"⚠️ [ScriptGenerator] Template error: {e}")
            return f"# Error generating {template_name} script\n# {e}\n\n"
