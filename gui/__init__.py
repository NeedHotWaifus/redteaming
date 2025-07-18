"""
GUI components for RedTeam Toolkit
"""

from gui.main_window import RedTeamGUI
from gui.components import DashboardFrame, ReconFrame, PayloadFrame
from gui.theme import apply_theme

__all__ = ['RedTeamGUI', 'apply_theme', 'run_gui']

def run_gui():
    """Initialize and run the GUI application"""
    from gui.main_window import start_gui
    start_gui()
