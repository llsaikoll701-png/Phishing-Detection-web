#!/usr/bin/env python3
"""
Python Version Compatibility Checker
Checks current Python version against project requirements
Author: MiniMax Agent
Created: 2026-05-11
"""

import sys
import platform
from packaging import version

def check_python_version():
    """Check if current Python version is compatible"""
    
    # Project requirements
    CURRENT_VERSION = "3.13.4"
    MIN_VERSION = "3.7.3"
    RENDER_RECOMMENDED = "3.11.5"
    
    # Get current version
    current = platform.python_version()
    current_formatted = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    
    print("=" * 60)
    print("🐍 PYTHON VERSION COMPATIBILITY CHECKER")
    print("=" * 60)
    print(f"📍 Current Python Version: {current} ({current_formatted})")
    print(f"💻 Platform: {platform.platform()}")
    print(f"🏗️  Architecture: {platform.architecture()[0]}")
    print()
    
    # Check minimum version compatibility
    try:
        current_parsed = version.parse(current)
        min_parsed = version.parse(MIN_VERSION)
        
        if current_parsed >= min_parsed:
            print(f"✅ COMPATIBLE: Python {current} meets minimum requirement ({MIN_VERSION})")
        else:
            print(f"❌ INCOMPATIBLE: Python {current} is below minimum requirement ({MIN_VERSION})")
            return False
    except Exception as e:
        print(f"⚠️  WARNING: Could not parse version: {e}")
    
    # Check current development version
    try:
        current_parsed = version.parse(current)
        dev_parsed = version.parse(CURRENT_VERSION)
        
        if current_parsed == dev_parsed:
            print(f"🎯 PERFECT: Running latest development version ({CURRENT_VERSION})")
        elif current_parsed > dev_parsed:
            print(f"⬆️  NEWER: Running newer version than development ({CURRENT_VERSION})")
        else:
            print(f"⬇️  OLDER: Running older version than development ({CURRENT_VERSION})")
    except Exception as e:
        print(f"⚠️  WARNING: Could not compare with development version: {e}")
    
    # Check Render recommendation
    try:
        current_parsed = version.parse(current)
        render_parsed = version.parse(RENDER_RECOMMENDED)
        
        if current_parsed == render_parsed:
            print(f"🚀 OPTIMAL: Current version matches Render recommendation ({RENDER_RECOMMENDED})")
        elif current_parsed.major == render_parsed.major and current_parsed.minor == render_parsed.minor:
            print(f"✅ GOOD: Compatible with Render (recommended: {RENDER_RECOMMENDED})")
        else:
            print(f"⚠️  RENDER: Consider Python {RENDER_RECOMMENDED} for optimal Render deployment")
    except Exception as e:
        print(f"⚠️  WARNING: Could not check Render compatibility: {e}")
    
    print()
    print("📋 VERSION SUMMARY:")
    print(f"   Current:  {current}")
    print(f"   Minimum:  {MIN_VERSION}")
    print(f"   Development: {CURRENT_VERSION}")
    print(f"   Render Rec: {RENDER_RECOMMENDED}")
    
    return True

def check_package_compatibility():
    """Check if required packages can be imported"""
    
    print("\n" + "=" * 60)
    print("📦 PACKAGE COMPATIBILITY CHECK")
    print("=" * 60)
    
    required_packages = [
        ('flask', 'Flask web framework'),
        ('flask_cors', 'CORS support for Flask'),
        ('sklearn', 'Scikit-learn ML library'),
        ('pandas', 'Data manipulation library'),
        ('numpy', 'Numerical computing library')
    ]
    
    all_available = True
    
    for package, description in required_packages:
        try:
            __import__(package)
            print(f"✅ {package:<12} - {description}")
        except ImportError:
            print(f"❌ {package:<12} - NOT INSTALLED")
            all_available = False
        except Exception as e:
            print(f"⚠️  {package:<12} - ERROR: {e}")
            all_available = False
    
    return all_available

def show_installation_instructions():
    """Show installation instructions for current Python version"""
    
    current = platform.python_version()
    
    print("\n" + "=" * 60)
    print("🔧 INSTALLATION INSTRUCTIONS")
    print("=" * 60)
    
    if version.parse(current) >= version.parse("3.11"):
        print("📋 For current Python version (3.11+):")
        print("   pip install -r requirements.txt")
    elif version.parse(current) >= version.parse("3.9"):
        print("📋 For Python 3.9-3.10:")
        print("   pip install flask==2.3.3 flask-cors==4.0.0")
        print("   pip install scikit-learn==1.3.0 pandas==2.0.3 numpy==1.24.3")
    else:
        print("📋 For Python 3.7-3.8:")
        print("   pip install flask==2.2.3 flask-cors==3.0.10")
        print("   pip install scikit-learn==1.1.3 pandas==1.3.5 numpy==1.21.6")
    
    print()
    print("🌐 For Render deployment:")
    print("   Use Python 3.11.x in render.yaml or environment settings")

def main():
    """Main function"""
    
    print("🔍 Checking Python version compatibility...")
    
    # Check Python version
    version_ok = check_python_version()
    
    # Check packages
    packages_ok = check_package_compatibility()
    
    # Show recommendations
    show_installation_instructions()
    
    print("\n" + "=" * 60)
    print("📊 FINAL RECOMMENDATION")
    print("=" * 60)
    
    if version_ok and packages_ok:
        print("✅ Everything looks good! Your Python setup is compatible.")
        current = platform.python_version()
        if version.parse(current) >= version.parse("3.11"):
            print("🚀 Ready for both local development and Render deployment!")
        else:
            print("💻 Good for local development, consider Python 3.11+ for Render")
    else:
        print("❌ Some issues detected. Please install missing packages or update Python version.")
    
    print("\n💡 Quick commands:")
    print("   python working_phishing_detector.py  # Test model")
    print("   python api.py                        # Start API")
    print("   python api_improved.py              # Start improved API")

if __name__ == "__main__":
    try:
        from packaging import version
    except ImportError:
        print("Installing packaging module...")
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "packaging"])
        from packaging import version
    
    main()