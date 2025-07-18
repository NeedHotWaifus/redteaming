"""
Tool Execution Module
Handles the execution of external tools, logging, and output parsing
"""

import os
import subprocess
import logging
import time
import traceback
import shutil
from pathlib import Path
from typing import List, Dict

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
        """Check if a tool is available in the PATH"""
        return shutil.which(tool_name) is not None

    def execute_tool(self, tool_name: str, command: List[str], output_file: str = None, 
                    timeout: int = 300, capture_output: bool = True, dry_run: bool = False) -> Dict:
        """
        Execute an external tool with comprehensive error handling
        
        Args:
            tool_name: Name of the tool to execute
            command: List of command arguments
            output_file: Optional file to save command output
            timeout: Timeout in seconds
            capture_output: Whether to capture command output
            dry_run: If True, simulate execution only
            
        Returns:
            Dictionary containing execution results
        """
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
