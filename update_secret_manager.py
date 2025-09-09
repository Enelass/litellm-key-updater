#!/usr/bin/env python3
"""
API Key Keychain Updater
Updates macOS Keychain ONLY with current valid API key
Only operates when no hardcoded secrets are detected by security scanner
"""

from logger import log_success, log_warning, log_error, log_info, log_start, log_end
import os
import sys
import subprocess
import argparse
from pathlib import Path
from datetime import datetime
from utils import Colors, colored_print, obfuscate_key


def log_message(message, prefix="[INFO]"):
    """Print timestamped message with color"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    # Determine color based on prefix
    if prefix in ["❌", "[ERROR]"]:
        color = Colors.RED
        prefix = "[ERROR]"
        log_error(message)
    elif prefix in ["✅", "[SUCCESS]"]:
        color = Colors.GREEN
        prefix = "[SUCCESS]"
        log_success(message)
    elif prefix in ["⚠️", "[WARNING]"]:
        color = Colors.YELLOW
        prefix = "[WARNING]"
        log_warning(message)
    elif prefix in ["🔐", "[KEYCHAIN]"]:
        color = Colors.PURPLE
        prefix = "[KEYCHAIN]"
        log_info(f"Keychain: {message}")
    elif prefix in ["📋", "[STEPS]"]:
        color = Colors.CYAN
        prefix = "[STEPS]"
        log_info(f"Steps: {message}")
    elif prefix in ["🚨", "[ALERT]"]:
        color = Colors.RED + Colors.BOLD
        prefix = "[ALERT]"
        log_error(f"Alert: {message}")
    else:
        color = Colors.CYAN
        prefix = "[INFO]"
        log_info(message)
    
    colored_print(f"{prefix} [{timestamp}] {message}", color)

def run_security_scan():
    """Run security scanner and check for hardcoded sk- keys"""
    try:
        from report import SecurityScanner
        scanner = SecurityScanner()
        scanner.scan_common_locations()
        
        has_sk_keys, sk_keys = scanner.has_hardcoded_sk_keys()
        return has_sk_keys, sk_keys, scanner
    except Exception as e:
        log_message(f"Failed to run security scan: {e}", "❌")
        return True, [], None  # Assume unsafe on error

def get_current_api_key():
    """Get current API key from check_key.py"""
    try:
        # Import and use check_key functionality
        sys.path.insert(0, os.path.dirname(__file__))
        from check_key import check_current_api_key
        from get_bearer import get_bearer_token
        
        # Get bearer token and cookies
        result = get_bearer_token()
        if not result['success']:
            log_message("Failed to get bearer token", "❌")
            return None
            
        token_value = result['token']
        cookies = result['cookies']
        
        # Get current API key
        success, current_api_key = check_current_api_key(token_value, cookies, return_key=True)
        
        if success and current_api_key:
            return current_api_key
        else:
            log_message("Failed to retrieve current API key", "❌")
            return None
            
    except Exception as e:
        log_message(f"Error getting current API key: {e}", "❌")
        return None

def update_keychain_key(service_name, account_name, new_key):
    """Update or create keychain entry using delete-then-add approach"""
    try:
        # First delete existing entry (ignore errors if it doesn't exist)
        delete_result = subprocess.run([
            'security', 'delete-generic-password',
            '-s', service_name
        ], capture_output=True, text=True)
        
        # Then add the new entry
        add_result = subprocess.run([
            'security', 'add-generic-password',
            '-s', service_name,
            '-a', account_name,
            '-w', new_key
        ], capture_output=True, text=True)
        
        if add_result.returncode == 0:
            log_message(f"✅ Updated keychain entry: {service_name}", "🔐")
            return True
        else:
            log_message(f"Failed to add keychain entry {service_name}: {add_result.stderr}", "❌")
            return False
            
    except Exception as e:
        log_message(f"Error updating keychain: {e}", "❌")
        return False

def update_environment_files(new_key, dry_run=False):
    """DISABLED: Environment file updates removed to prevent corruption"""
    log_message("Environment file updates disabled for safety", "⚠️")
    return []

def main():
    """Main function"""
    log_start()
    parser = argparse.ArgumentParser(description='Update API key in environment variables and keychain')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be updated without making changes')
    parser.add_argument('--force', action='store_true', help='Force update even if security issues are found (NOT RECOMMENDED)')
    parser.add_argument('--key', type=str, help='API key to use (if not provided, will be retrieved automatically)')
    args = parser.parse_args()
    
    log_message("Starting API key environment update process")
    
    # Step 1: Run security scan
    log_message("Running security scan to check for hardcoded secrets...")
    has_hardcoded_sk_keys, sk_keys, scanner = run_security_scan()
    
    if has_hardcoded_sk_keys and not args.force:
        log_message("🚨 SECURITY VIOLATION DETECTED!", "❌")
        log_message(f"Found {len(sk_keys)} hardcoded sk- API key(s) in your codebase:", "❌")
        
        for sk_key in sk_keys:
            log_message(f"  • {obfuscate_key(sk_key['value'])} in {sk_key['file']}:{sk_key['line']}", "⚠️")
        
        log_message("", "")
        log_message("🔒 For security reasons, key update is BLOCKED until hardcoded keys are removed.", "❌")
        log_message("", "")
        log_message("📋 Required actions:", "🔧")
        log_message("  1. Remove all hardcoded sk- keys from your files", "")
        log_message("  2. Use secure storage methods (keychain, environment variables)", "")
        log_message("  3. Run security scan again to verify: python3 sec_recmm.py", "")
        log_message("", "")
        
        if scanner:
            report_path = scanner.save_report('security_report.html')
            log_message(f"📊 Detailed security report: {report_path}", "📄")
            import webbrowser
            webbrowser.open(f'file://{Path(report_path).absolute()}')
        
        log_end()
        sys.exit(1)
    
    if args.force and has_hardcoded_sk_keys:
        log_message(f"⚠️  FORCED UPDATE: Ignoring {len(sk_keys)} hardcoded sk- key(s) (SECURITY RISK)", "🚨")
    
    # Step 2: Get current valid API key
    if args.key:
        log_message("Using provided API key...")
        current_key = args.key
        log_message(f"Provided API key: {obfuscate_key(current_key)}", "🔑")
    else:
        log_message("Retrieving current valid API key...")
        current_key = get_current_api_key()
        
        if not current_key:
            log_message("Failed to retrieve current API key. Cannot proceed.", "❌")
            log_end()
            sys.exit(1)
        
        log_message(f"Current API key: {obfuscate_key(current_key)}", "🔑")
    
    if args.dry_run:
        log_message("DRY RUN MODE - No changes will be made", "🔍")
    
    # Step 3: Update keychain entries
    log_message("Updating macOS Keychain entries...")
    import getpass
    current_user = getpass.getuser()
    keychain_services = [
        ('LITELLM_API_KEY', current_user),
        ('OpenAI API Key', current_user),
        ('Anthropic API Key', current_user),
        ('Gemini API Key', current_user)
    ]
    
    keychain_updated = 0
    for service_name, account_name in keychain_services:
        if not args.dry_run:
            if update_keychain_key(service_name, account_name, current_key):
                keychain_updated += 1
        else:
            log_message(f"🔍 Would update keychain: {service_name}", "🔐")
            keychain_updated += 1
    
    # Step 4: Environment files (DISABLED for safety)
    log_message("Environment file updates disabled for safety", "⚠️")
    updated_files = []
    
    # Step 5: Summary
    log_message("", "")
    log_message("📊 UPDATE SUMMARY", "✅")
    log_message(f"  • Keychain entries updated: {keychain_updated}", "")
    log_message(f"  • Environment files updated: {len(updated_files)}", "")
    
    if updated_files:
        log_message("  • Updated files:", "")
        for file_path in updated_files:
            log_message(f"    - {file_path}", "")
    
    if not args.dry_run:
        log_message("", "")
        log_message("🔄 Next steps:", "📋")
        log_message("  1. Keychain updated - environment variables can access via:", "")
        log_message("     security find-generic-password -s 'LITELLM_API_KEY' -w", "")
        log_message("  2. Verify with: python3 check_key.py", "")
        log_message("  3. Test environment integration: python3 analyse_env.py", "")
    else:
        log_message("", "")
        log_message("To apply these changes, run without --dry-run flag", "🔧")
    
    log_end()

if __name__ == "__main__":
    main()