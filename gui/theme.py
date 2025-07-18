"""
Theme support for RedTeam Toolkit GUI
"""

import tkinter as tk
from tkinter import ttk
import sys
import platform

def apply_theme(root, theme_name="default"):
    """Apply theme to the root window"""
    if theme_name == "default":
        # Use default system theme
        pass
    elif theme_name == "dark":
        _apply_dark_theme(root)
    elif theme_name == "light":
        _apply_light_theme(root)
    elif theme_name == "red":
        _apply_red_theme(root)
    
    # Configure styles
    style = ttk.Style(root)
    
    # Use a theme that looks good on all platforms
    if sys.platform.startswith('win'):
        style.theme_use('vista')
    elif sys.platform.startswith('darwin'):  # macOS
        style.theme_use('aqua')
    else:  # Linux
        style.theme_use('clam')
    
    # Configure common styles
    style.configure('TButton', font=('TkDefaultFont', 10))
    style.configure('TLabel', font=('TkDefaultFont', 10))
    style.configure('TEntry', font=('TkDefaultFont', 10))
    style.configure('TFrame', background=root.cget('background'))
    style.configure('TNotebook', background=root.cget('background'))
    style.configure('TNotebook.Tab', padding=[10, 2])

def _apply_dark_theme(root):
    """Apply dark theme to the root window"""
    bg_color = "#2b2b2b"
    fg_color = "#e0e0e0"
    button_bg = "#3c3f41"
    
    root.configure(background=bg_color)
    
    style = ttk.Style(root)
    style.configure('TFrame', background=bg_color)
    style.configure('TLabel', background=bg_color, foreground=fg_color)
    style.configure('TButton', background=button_bg, foreground=fg_color)
    style.configure('TEntry', fieldbackground=button_bg, foreground=fg_color)
    style.map('TButton', background=[('active', '#4c5052')])

def _apply_light_theme(root):
    """Apply light theme to the root window"""
    bg_color = "#f2f2f2"
    fg_color = "#333333"
    button_bg = "#e0e0e0"
    
    root.configure(background=bg_color)
    
    style = ttk.Style(root)
    style.configure('TFrame', background=bg_color)
    style.configure('TLabel', background=bg_color, foreground=fg_color)
    style.configure('TButton', background=button_bg, foreground=fg_color)
    style.configure('TEntry', fieldbackground='white', foreground=fg_color)
    style.map('TButton', background=[('active', '#d0d0d0')])

def _apply_red_theme(root):
    """Apply red team themed styling"""
    bg_color = "#2b2b2b"
    fg_color = "#e0e0e0"
    accent_color = "#b71c1c"  # Deep red
    
    root.configure(background=bg_color)
    
    style = ttk.Style(root)
    style.configure('TFrame', background=bg_color)
    style.configure('TLabel', background=bg_color, foreground=fg_color)
    style.configure('TButton', background=accent_color, foreground=fg_color)
    style.configure('TEntry', fieldbackground='#3c3f41', foreground=fg_color)
    style.map('TButton', background=[('active', '#d32f2f')])  # Lighter red on hover
