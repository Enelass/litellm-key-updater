#!/usr/bin/env python3
"""
Shared utilities for LiteLLM API Key Management
Common functions used across all scripts

Identify what the default user browser is, so we can extract
an auth token from existing sign-in. We'll use these session
cookies, to request a bearer token for LiteLLM endpoint.

Additional system information gathering for comprehensive logging.
"""

import os
import sys
import json
import datetime
import subprocess
import plistlib
import platform
import getpass
import socket
from datetime import timezone, timedelta

# ============================================================================
# COLOR UTILITIES
# ============================================================================

class Colors:
    """ANSI color codes for terminal output"""
    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    
    # Semantic aliases
    SUCCESS = GREEN
    ERROR = RED
    WARNING = YELLOW
    INFO = CYAN


def colored_print(message, color=Colors.WHITE):
    """Print message with specified color"""
    print(f"{color}{message}{Colors.END}")


def timestamp_print(message, color=Colors.WHITE, *args):
    """Print message with timestamp and color support"""
    tz = timezone(timedelta(hours=10))  # Sydney timezone
    timestamp = datetime.datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")
    if args:
        formatted_message = message % args if '%' in message else message.format(*args)
    else:
        formatted_message = message
    print(f"{timestamp} {color}{formatted_message}{Colors.END}")

def obfuscate_key(key):
    """Obfuscate API key for safe display - unified implementation"""
    if not key or len(key) < 8:
        return key
    return key[:4] + "***" + key[-4:]


# ============================================================================
# CONFIGURATION UTILITIES
# ============================================================================

def load_config():
    """Load configuration from config.json"""
    try:
        config_path = os.path.join(os.path.dirname(__file__), 'config.json')
        with open(config_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        colored_print("[ERROR] config.json not found", Colors.RED)
        sys.exit(1)
    except json.JSONDecodeError:
        colored_print("[ERROR] Invalid JSON in config.json", Colors.RED)
        sys.exit(1)


# ============================================================================
# BROWSER DETECTION UTILITIES
# ============================================================================

def get_default_browser():
    """Get the default browser bundle ID using macOS Launch Services."""
    try:
        # First method: Try using defaults export
        cmd = ['defaults', 'export', 'com.apple.LaunchServices/com.apple.launchservices.secure', '-']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0 and result.stdout:
            try:
                plist_data = result.stdout.encode('utf-8')
                plist = plistlib.loads(plist_data)
                handlers = plist.get('LSHandlers', [])
                
                # Look for HTML content type handler first
                for handler in handlers:
                    if handler.get('LSHandlerContentType') == 'public.html':
                        bundle_id = handler.get('LSHandlerRoleAll')
                        if bundle_id:
                            return bundle_id
                
                # Then look for HTTP URL scheme handler
                for handler in handlers:
                    if handler.get('LSHandlerURLScheme') == 'http':
                        bundle_id = handler.get('LSHandlerRoleAll')
                        if bundle_id:
                            return bundle_id
                            
            except (plistlib.InvalidFileException, UnicodeDecodeError) as e:
                print(f"Warning: Error parsing plist data: {e}", file=sys.stderr)
                
    except subprocess.TimeoutExpired:
        print("Warning: defaults command timed out", file=sys.stderr)
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    # Fallback method: Try using duti if available
    try:
        result = subprocess.run(['duti', '-x', 'html'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        pass
    
    return None


def get_browser_info():
    """Get information about the default browser including bundle ID and display name."""
    browsers = {
        'com.google.chrome': 'Google Chrome',
        'com.apple.safari': 'Safari',
        'org.mozilla.firefox': 'Firefox',
        'com.microsoft.edgemac': 'Microsoft Edge',
        'com.brave.Browser': 'Brave Browser',
        'com.operasoftware.Opera': 'Opera',
        'com.vivaldi.Vivaldi': 'Vivaldi',
        'org.chromium.Chromium': 'Chromium',
        'com.apple.Safari.Technology.Preview': 'Safari Technology Preview'
    }
    
    browser_id = get_default_browser()
    
    if not browser_id:
        return {
            'bundle_id': None,
            'name': 'No default browser found',
            'error': 'Could not determine default browser'
        }
    
    return {
        'bundle_id': browser_id,
        'name': browsers.get(browser_id, f'Unknown Browser ({browser_id})')
    }


# ============================================================================
# SYSTEM INFORMATION UTILITIES
# ============================================================================

def get_system_info():
    """Gather comprehensive system and user information for logging"""
    try:
        # Basic system information
        system_info = {
            'timestamp': datetime.datetime.now(timezone(timedelta(hours=10))).isoformat(),
            'user': getpass.getuser(),
            'hostname': socket.gethostname(),
            'os': {
                'system': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'machine': platform.machine(),
                'processor': platform.processor()
            },
            'python': {
                'version': platform.python_version(),
                'implementation': platform.python_implementation(),
                'compiler': platform.python_compiler()
            }
        }
        
        # macOS specific information
        if platform.system() == 'Darwin':
            try:
                # Get macOS version
                mac_version = platform.mac_ver()
                system_info['os']['mac_version'] = mac_version[0]
                system_info['os']['mac_build'] = mac_version[2]
                
                # Get hardware info using system_profiler
                try:
                    result = subprocess.run(['system_profiler', 'SPHardwareDataType'],
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        hardware_info = {}
                        for line in result.stdout.split('\n'):
                            if 'Model Name:' in line:
                                hardware_info['model'] = line.split(':', 1)[1].strip()
                            elif 'Model Identifier:' in line:
                                hardware_info['identifier'] = line.split(':', 1)[1].strip()
                            elif 'Chip:' in line or 'Processor Name:' in line:
                                hardware_info['chip'] = line.split(':', 1)[1].strip()
                            elif 'Total Number of Cores:' in line:
                                hardware_info['cores'] = line.split(':', 1)[1].strip()
                            elif 'Memory:' in line:
                                hardware_info['memory'] = line.split(':', 1)[1].strip()
                        system_info['hardware'] = hardware_info
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                    pass
                    
            except Exception:
                pass
        
        # Get current working directory
        system_info['cwd'] = os.getcwd()
        
        # Get environment variables relevant to the project
        env_vars = {}
        for key in ['PATH', 'HOME', 'USER', 'SHELL', 'TERM']:
            if key in os.environ:
                env_vars[key] = os.environ[key]
        system_info['environment'] = env_vars
        
        return system_info
        
    except Exception as e:
        return {
            'error': f'Failed to gather system info: {str(e)}',
            'timestamp': datetime.datetime.now().isoformat(),
            'user': getpass.getuser() if 'getpass' in globals() else 'unknown'
        }


def display_system_info():
    """Display system information in a formatted way"""
    info = get_system_info()
    
    colored_print("=" * 60, Colors.PURPLE)
    colored_print("SYSTEM INFORMATION", Colors.PURPLE + Colors.BOLD)
    colored_print("=" * 60, Colors.PURPLE)
    print()
    
    # Basic info
    colored_print(f"User: {info.get('user', 'unknown')}", Colors.CYAN)
    colored_print(f"Hostname: {info.get('hostname', 'unknown')}", Colors.CYAN)
    colored_print(f"Timestamp: {info.get('timestamp', 'unknown')}", Colors.CYAN)
    print()
    
    # OS info
    if 'os' in info:
        colored_print("Operating System:", Colors.YELLOW + Colors.BOLD)
        os_info = info['os']
        colored_print(f"  System: {os_info.get('system', 'unknown')}", Colors.WHITE)
        colored_print(f"  Release: {os_info.get('release', 'unknown')}", Colors.WHITE)
        if 'mac_version' in os_info:
            colored_print(f"  macOS Version: {os_info['mac_version']}", Colors.WHITE)
        colored_print(f"  Machine: {os_info.get('machine', 'unknown')}", Colors.WHITE)
        print()
    
    # Hardware info (macOS)
    if 'hardware' in info:
        colored_print("Hardware:", Colors.YELLOW + Colors.BOLD)
        hw = info['hardware']
        for key, value in hw.items():
            colored_print(f"  {key.title()}: {value}", Colors.WHITE)
        print()
    
    # Python info
    if 'python' in info:
        colored_print("Python Environment:", Colors.YELLOW + Colors.BOLD)
        py_info = info['python']
        colored_print(f"  Version: {py_info.get('version', 'unknown')}", Colors.WHITE)
        colored_print(f"  Implementation: {py_info.get('implementation', 'unknown')}", Colors.WHITE)
        print()
    
    # Browser info
    try:
        browser = get_browser_info()
        colored_print("Default Browser:", Colors.YELLOW + Colors.BOLD)
        colored_print(f"  Name: {browser.get('name', 'unknown')}", Colors.WHITE)
        if 'bundle_id' in browser:
            colored_print(f"  Bundle ID: {browser['bundle_id']}", Colors.WHITE)
        print()
    except Exception:
        pass
    
    # Working directory and shell
    colored_print(f"Working Directory: {info.get('cwd', 'unknown')}", Colors.CYAN)
    if 'environment' in info and 'SHELL' in info['environment']:
        colored_print(f"Default Shell: {info['environment']['SHELL']}", Colors.CYAN)
    print()
    
    colored_print("=" * 60, Colors.PURPLE)


def main():
    """Main function when utils.py is run directly"""
    display_system_info()
    return 0


if __name__ == "__main__":
    sys.exit(main())