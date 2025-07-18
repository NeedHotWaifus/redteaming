"""
Output Formatting Module
Handles colored console output and formatting
"""

import os
import platform

# Default color codes
DEFAULT_COLORS = {
    "RED": "\033[31m",
    "GREEN": "\033[32m", 
    "YELLOW": "\033[33m",
    "BLUE": "\033[34m",
    "MAGENTA": "\033[35m",
    "CYAN": "\033[36m",
    "WHITE": "\033[37m",
    "BOLD": "\033[1m",
    "RESET": "\033[0m"
}

def print_colored(text: str, color: str = "WHITE", bold: bool = False, end: str = "\n", colors=None):
    """
    Print colored text to the console
    
    Args:
        text: The text to print
        color: Color name (RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE)
        bold: Whether to make the text bold
        end: String to append after the text
        colors: Dictionary of color codes to use
    """
    try:
        if colors is None:
            colors = DEFAULT_COLORS
        
        color_code = colors.get(color.upper(), colors["WHITE"])
        bold_code = colors["BOLD"] if bold else ""
        reset_code = colors["RESET"]
        print(f"{bold_code}{color_code}{text}{reset_code}", end=end)
    except Exception:
        # Fallback if color codes are not supported
        print(text, end=end)

def print_banner(target: str, colors=None):
    """
    Print the RedTeam Toolkit banner
    
    Args:
        target: The current target
        colors: Dictionary of color codes to use
    """
    try:
        # Clear screen
        os.system('cls' if platform.system() == "Windows" else 'clear')
    except Exception:
        # Fallback if clearing screen fails
        print("\n" * 5)
    
    if colors is None:
        colors = DEFAULT_COLORS
    
    print_colored("=" * 60, "CYAN", True, colors=colors)
    print_colored("🔥 RedTeam AI-Assisted Offensive Security Toolkit", "CYAN", True, colors=colors)
    print_colored("=" * 60, "CYAN", True, colors=colors)
    print_colored("⚠️  For authorized penetration testing use only", "YELLOW", colors=colors)
    print_colored(f"📅 2024-2025 Edition | Current Target: {target}", "GREEN", colors=colors)
    print_colored("=" * 60, "CYAN", colors=colors)
    print()

def progress_bar(current: int, total: int, prefix: str = '', suffix: str = '', length: int = 50, fill: str = '█'):
    """
    Display a progress bar in the console
    
    Args:
        current: Current progress
        total: Total progress
        prefix: Text before the progress bar
        suffix: Text after the progress bar
        length: Length of the progress bar
        fill: Character to use for filled portion
    """
    percent = ("{0:.1f}").format(100 * (current / float(total)))
    filled_length = int(length * current // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end='\r')
    # Print new line on complete
    if current == total:
        print()
