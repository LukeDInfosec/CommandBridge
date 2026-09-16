"""
Preference persistence — save/load all user settings.
"""
import os
import re
import sys
import json
import subprocess
from pathlib import Path

from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtCore import QProcess, Qt, QTimer
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QTextEdit, QTabWidget, QGridLayout,
    QGroupBox, QSplitter, QScrollArea, QFileDialog, QMessageBox,
    QComboBox, QFrame, QPlainTextEdit, QProgressBar, QToolButton,
)
from command_bridge.constants import (
    APP_TITLE, APP_VERSION, THEMES, BASE_DIR, DEFAULT_OUTPUT_DIR, DEFAULT_THEME,
)



class PreferencesMixin:
    """Mixin providing preference persistence — save/load all user settings."""

    def save_theme_preference(self, theme_name):
        """Save selected theme to config file"""
        try:
            config_dir = Path.home() / ".config" / "CommandBridge"
            config_dir.mkdir(parents=True, exist_ok=True)
            config_file = config_dir / "theme.txt"
            
            with open(config_file, 'w') as f:
                f.write(theme_name)
        except Exception as e:
            print(f"Error saving theme preference: {e}")

    def load_theme_preference(self):
        """Load saved theme preference from config file"""
        try:
            config_dir = Path.home() / ".config" / "CommandBridge"
            config_file = config_dir / "theme.txt"
            
            if config_file.exists():
                with open(config_file, 'r') as f:
                    theme_name = f.read().strip()
                    if theme_name in THEMES:
                        return theme_name
        except Exception as e:
            print(f"Error loading theme preference: {e}")

        return DEFAULT_THEME

    def save_rail_preference(self, expanded: bool):
        """Remember whether the navigation rail is expanded or collapsed."""
        try:
            config_dir = Path.home() / ".config" / "CommandBridge"
            config_dir.mkdir(parents=True, exist_ok=True)
            (config_dir / "rail.txt").write_text("1" if expanded else "0")
        except Exception as e:
            print(f"Error saving rail preference: {e}")

    def load_rail_preference(self) -> bool:
        """Load the navigation rail state (defaults to expanded)."""
        try:
            config_file = Path.home() / ".config" / "CommandBridge" / "rail.txt"
            if config_file.exists():
                return config_file.read_text().strip() != "0"
        except Exception as e:
            print(f"Error loading rail preference: {e}")
        return True

    def save_output_dir_preference(self, output_dir):
        """Save output directory to config file"""
        try:
            config_dir = Path.home() / ".config" / "CommandBridge"
            config_dir.mkdir(parents=True, exist_ok=True)
            config_file = config_dir / "output_dir.txt"
            
            with open(config_file, 'w') as f:
                f.write(output_dir)
        except Exception as e:
            print(f"Error saving output directory preference: {e}")

    def load_output_dir_preference(self):
        """Load saved output directory from config file"""
        try:
            config_dir = Path.home() / ".config" / "CommandBridge"
            config_file = config_dir / "output_dir.txt"
            
            if config_file.exists():
                with open(config_file, 'r') as f:
                    output_dir = f.read().strip()
                    if output_dir and Path(output_dir).exists():
                        return Path(output_dir)
        except Exception as e:
            print(f"Error loading output directory preference: {e}")
        
        return DEFAULT_OUTPUT_DIR  # Default to current directory

    def save_target_preference(self):
        """Save target to config file"""
        try:
            config_dir = Path.home() / ".config" / "CommandBridge"
            config_dir.mkdir(parents=True, exist_ok=True)
            config_file = config_dir / "target.txt"
            
            with open(config_file, 'w') as f:
                f.write(self.target_input.text())
        except Exception as e:
            print(f"Error saving target preference: {e}")

    def load_target_preference(self):
        """Load saved target from config file"""
        try:
            config_dir = Path.home() / ".config" / "CommandBridge"
            config_file = config_dir / "target.txt"
            
            if config_file.exists():
                with open(config_file, 'r') as f:
                    return f.read().strip()
        except Exception as e:
            print(f"Error loading target preference: {e}")
        return ""

    def save_headers_preference(self):
        """Save custom headers to config file"""
        try:
            config_dir = Path.home() / ".config" / "CommandBridge"
            config_dir.mkdir(parents=True, exist_ok=True)
            config_file = config_dir / "headers.txt"
            
            with open(config_file, 'w') as f:
                f.write(self.headers_input.toPlainText())
        except Exception as e:
            print(f"Error saving headers preference: {e}")

    def load_headers_preference(self):
        """Load saved headers from config file"""
        try:
            config_dir = Path.home() / ".config" / "CommandBridge"
            config_file = config_dir / "headers.txt"
            
            if config_file.exists():
                with open(config_file, 'r') as f:
                    return f.read()
        except Exception as e:
            print(f"Error loading headers preference: {e}")
        return ""

    def load_target_and_headers(self):
        """Load saved target and headers"""
        # Load target
        target = self.load_target_preference()
        if target:
            self.target_input.setText(target)

        # Load headers
        headers = self.load_headers_preference()
        if headers:
            self.headers_input.setPlainText(headers)
