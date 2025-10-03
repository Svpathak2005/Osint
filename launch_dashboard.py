#!/usr/bin/env python3
"""
OSINT Dashboard Launcher
Launch the interactive web dashboard for OSINT data visualization.
"""

import subprocess
import sys
import os
from pathlib import Path

def check_dependencies():
    """Check if required packages are installed."""
    required_packages = ['streamlit', 'plotly', 'pandas']
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"Missing required packages: {', '.join(missing_packages)}")
        print("Installing missing packages...")
        
        try:
            subprocess.check_call([
                sys.executable, '-m', 'pip', 'install'
            ] + missing_packages)
            print("Packages installed successfully!")
        except subprocess.CalledProcessError as e:
            print(f"Error installing packages: {e}")
            return False
    
    return True

def launch_dashboard():
    """Launch the Streamlit dashboard."""
    # Ensure we're in the correct directory
    project_root = Path(__file__).parent
    os.chdir(project_root)
    
    # Check dependencies
    if not check_dependencies():
        print("Failed to install required dependencies.")
        return False
    
    # Launch Streamlit dashboard
    dashboard_path = "src/dashboard.py"
    
    print("🚀 Launching OSINT Dashboard...")
    print("📊 The dashboard will open in your default web browser")
    print("🔗 URL: http://localhost:8501")
    print("⛔ Press Ctrl+C to stop the dashboard")
    print("-" * 50)
    
    try:
        subprocess.run([
            sys.executable, '-m', 'streamlit', 'run', dashboard_path,
            '--server.port', '8501',
            '--server.address', 'localhost',
            '--browser.gatherUsageStats', 'false'
        ])
    except KeyboardInterrupt:
        print("\n🛑 Dashboard stopped by user")
    except Exception as e:
        print(f"❌ Error launching dashboard: {e}")
        return False
    
    return True

if __name__ == "__main__":
    success = launch_dashboard()
    if not success:
        sys.exit(1)