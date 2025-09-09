#!/usr/bin/env python3
"""
Check current API key using extracted bearer token and cookies
Similar to renew_key.py but only retrieves existing API key without generating new ones
"""

import sys
import argparse
import json
import os
import requests
from datetime import datetime
from get_bearer import get_browser_cookies_for_domain
from utils import Colors, colored_print, timestamp_print, load_config, get_browser_info, obfuscate_key
from renew_key import request_api_key_with_token



def validate_api_key(api_key, final_token, cookies):
    """Validate if an API key is still active by testing it against the models endpoint"""
    config = load_config()
    
    # Use the proper API endpoint for validation (not the web UI endpoint)
    api_base_url = config['oauth']['api_base_url']
    models_url = f"{api_base_url.rstrip('/')}{config['oauth']['models_endpoint']}"
    
    # Prepare headers for validation request
    headers = {
        'Host': config['oauth']['base_url'].replace('https://', '').replace('http://', '').split('/')[0],
        'Authorization': f'Bearer {api_key}',  # Use the API key for authorization
        'Content-Type': config['headers']['content_type'],
        'Accept': config['headers']['accept'],
        'Accept-Language': config['headers']['accept_language'],
        'Accept-Encoding': config['headers']['accept_encoding'],
        'Connection': config['headers']['connection'],
        'User-Agent': config['headers']['user_agent'],
        'Origin': config['oauth']['base_url'].rstrip('/'),
        'Referer': config['oauth']['base_url']
    }
    
    # Convert cookies to requests format (though API key should be sufficient)
    request_cookies = {}
    for name, cookie_data in cookies.items():
        request_cookies[name] = cookie_data['value']
    
    try:
        # Test the API key by making a GET request to the models endpoint
        response = requests.get(models_url, headers=headers, cookies=request_cookies, timeout=config['timeouts']['api_request'])
        
        if response.status_code == 200:
            return True
        elif response.status_code == 401:
            colored_print("[INVALID] Current API key is expired or invalid", Colors.RED)
            colored_print("[RENEW] Automatically renewing API key...", Colors.YELLOW)
            
            # Call renewal function
            try:
                success, new_key = request_api_key_with_token(final_token, cookies, silent=True)
                if success and new_key:
                    print(f"✅ New API key generated: {obfuscate_key(new_key)}", file=sys.stderr)
                    return True
                else:
                    print("❌ Failed to generate new API key", file=sys.stderr)
                    return False
            except Exception as e:
                print(f"❌ Error during key renewal: {e}", file=sys.stderr)
                return False
        elif response.status_code == 403:
            colored_print("[ERROR] Current API key lacks permissions", Colors.RED)
            return False
        else:
            print(f"⚠️  API key validation unclear: HTTP {response.status_code}", file=sys.stderr)
            return False
            
    except Exception as e:
        print(f"❌ API key validation error: {e}", file=sys.stderr)
        return False

def check_current_api_key(final_token, cookies, return_key=False):
    """Check current API key using bearer token and cookies
    
    Args:
        final_token: Bearer token from browser
        cookies: Browser cookies
        return_key: If True, return the actual API key instead of just success status
    
    Returns:
        If return_key=False: Boolean indicating success
        If return_key=True: Tuple of (success, api_key) where api_key is None if failed
    """
    config = load_config()
    
    # Build API key URL
    api_key_url = f"{config['oauth']['base_url'].rstrip('/')}{config['oauth']['api_key_endpoint']}"
    
    # Prepare headers using config values
    headers = {
        'Host': config['oauth']['base_url'].replace('https://', '').replace('http://', '').split('/')[0],
        'Authorization': f'Bearer {final_token}',
        'Content-Type': config['headers']['content_type'],
        'Accept': config['headers']['accept'],
        'Accept-Language': config['headers']['accept_language'],
        'Accept-Encoding': config['headers']['accept_encoding'],
        'Connection': config['headers']['connection'],
        'User-Agent': config['headers']['user_agent'],
        'Origin': config['oauth']['base_url'].rstrip('/'),
        'Referer': config['oauth']['base_url']
    }
    
    # Convert cookies to requests format
    request_cookies = {}
    for name, cookie_data in cookies.items():
        request_cookies[name] = cookie_data['value']
    
    try:
        timestamp_print("[INFO] Checking current API key from: {}", Colors.CYAN, api_key_url)
        
        # Use GET request to retrieve current API key
        response = requests.get(api_key_url, headers=headers, cookies=request_cookies, timeout=config['timeouts']['api_request'])
        
        if response.status_code == 200:
            try:
                data = response.json()
                if data.get('api_key'):
                    api_key = data['api_key']
                    obfuscated_key = obfuscate_key(api_key)
                    timestamp_print("[SUCCESS] Current API key retrieved: {}", Colors.GREEN, obfuscated_key)
                    
                    # Now validate if the key is still active
                    print("", file=sys.stderr)
                    timestamp_print("[INFO] Validating API key status...", Colors.CYAN)
                    is_valid = validate_api_key(api_key, final_token, cookies)
                    
                    if is_valid:
                        timestamp_print("[VALID] Current API key is active", Colors.GREEN)
                    
                    if return_key:
                        return (is_valid, api_key if is_valid else None)
                    return is_valid
                elif data.get('keys') and isinstance(data['keys'], list) and len(data['keys']) > 0:
                    # Handle case where API returns array of keys
                    api_key = data['keys'][0]
                    obfuscated_key = obfuscate_key(api_key)
                    print(f"SUCCESS! Current API key retrieved: {obfuscated_key}", file=sys.stderr)
                    
                    # Now validate if the key is still active
                    print("", file=sys.stderr)
                    print("Validating API key status...", file=sys.stderr)
                    is_valid = validate_api_key(api_key, final_token, cookies)
                    
                    if is_valid:
                        print("Current API key is active", file=sys.stderr)
                    
                    if return_key:
                        return (is_valid, api_key if is_valid else None)
                    return is_valid
                else:
                    print("WARNING: No API key found in response", file=sys.stderr)
                    print(f"Response data: {data}", file=sys.stderr)
                    if return_key:
                        return (False, None)
                    return False
            except Exception as e:
                print(f"Failed to parse JSON response: {e}", file=sys.stderr)
                print(f"Raw response: {response.text[:500]}", file=sys.stderr)
                if return_key:
                    return (False, None)
                return False
        elif response.status_code == 404:
            print("❌ No API key exists for this account", file=sys.stderr)
            if return_key:
                return (False, None)
            return False
        elif response.status_code == 401:
            print("❌ Authentication failed - token may be expired", file=sys.stderr)
            if return_key:
                return (False, None)
            return False
        elif response.status_code == 403:
            print("❌ Access forbidden - insufficient permissions", file=sys.stderr)
            if return_key:
                return (False, None)
            return False
        else:
            print(f"❌ API request failed: {response.status_code}", file=sys.stderr)
            print(f"Response: {response.text[:500]}", file=sys.stderr)
            if return_key:
                return (False, None)
            return False
        
    except Exception as e:
        print(f"❌ API request error: {e}", file=sys.stderr)
        if return_key:
            return (False, None)
        return False

def main():
    """Main function for standalone usage"""
    parser = argparse.ArgumentParser(
        description="Check current API key using bearer token from browser cookies",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 check_key.py               # Check current API key and validate if it's still active
        """
    )
    
    args = parser.parse_args()
    
    colored_print("LiteLLM User API Key Validation...", Colors.PURPLE + Colors.BOLD)
    print("")
    
    # Load configuration and get browser info
    config = load_config()
    browser_info = get_browser_info()
    
    if not browser_info or not browser_info.get('bundle_id'):
        colored_print("[ERROR] Could not detect default browser", Colors.RED)
        sys.exit(1)
    
    # Extract cookies and token from browser
    domain = config['oauth']['base_url'].replace('https://', '').replace('http://', '').split('/')[0]
    colored_print(f"[INFO] Attempting to extract cookies for domain: {domain}", Colors.CYAN)
    
    # Temporarily redirect get_browser_cookies_for_domain verbose output
    import os
    from contextlib import redirect_stderr
    
    # Capture the verbose output and only show what we want
    with open(os.devnull, 'w') as devnull:
        with redirect_stderr(devnull):
            cookies = get_browser_cookies_for_domain(browser_info['bundle_id'], domain)
    
    if not cookies:
        colored_print("[ERROR] No cookies found in browser session", Colors.RED)
        colored_print("[INFO] Please make sure you're logged in to the service in your browser", Colors.YELLOW)
        sys.exit(1)
    
    # Remove verbose cookie listing
    
    # Look for bearer token in cookies
    token_value = None
    for name, cookie_data in cookies.items():
        if name == 'token' and cookie_data['value']:
            token_value = cookie_data['value']
            break
    
    if not token_value:
        colored_print("[ERROR] No bearer token found in cookies", Colors.RED)
        colored_print("[INFO] Please make sure you're logged in and authenticated", Colors.YELLOW)
        sys.exit(1)
    
    timestamp_print(f"[SUCCESS] Found bearer token in {browser_info.get('name', 'browser')} cookies", Colors.GREEN)
    print("")
    
    # Check the current API key
    success = check_current_api_key(token_value, cookies)
    
    if success:
        # Get the actual API key for environment analysis
        success, current_api_key = check_current_api_key(token_value, cookies, return_key=True)
        
        if success and current_api_key:
            print("", file=sys.stderr)
            timestamp_print("[INFO] Cross-referencing with environment analysis...", Colors.CYAN)
            
            # Call analyse_env.py with the current active key
            try:
                import subprocess
                result = subprocess.run([
                    sys.executable, 'analyse_env.py', '--verify-key', current_api_key
                ], capture_output=True, text=True, timeout=30)
                
                # Display the verification results to stdout
                if result.stdout.strip():
                    print(result.stdout.strip())
                
                # Check if there was a key update for auto-synchronization
                key_update_detected = '🔄 KEY UPDATE' in result.stdout
                
                # Auto-synchronize if key update detected
                if key_update_detected:
                    print("Attempting to synchronize environment with active key...", file=sys.stderr)
                    try:
                        # Pass the current active key to update_secret_manager.py
                        sync_result = subprocess.run([sys.executable, './update_secret_manager.py', '--key', current_api_key],
                                                   capture_output=True, text=True, cwd='.')
                        if sync_result.returncode == 0:
                            print("Environment synchronization completed successfully", file=sys.stderr)
                            print("Please run 'source ~/.zshrc' to reload environment variables", file=sys.stderr)
                            
                            # Regenerate HTML report after successful synchronization
                            print("Updating security report...", file=sys.stderr)
                            try:
                                report_result = subprocess.run([sys.executable, 'analyse_env.py', '--no-browser'],
                                                            capture_output=True, text=True, timeout=30)
                                if report_result.returncode == 0:
                                    print("Security report updated successfully", file=sys.stderr)
                                else:
                                    print("Warning: Failed to update security report", file=sys.stderr)
                            except subprocess.TimeoutExpired:
                                print("Warning: Security report update timed out", file=sys.stderr)
                            except Exception as e:
                                print(f"Warning: Security report update failed: {e}", file=sys.stderr)
                        else:
                            print(f"❌ Environment synchronization failed: {sync_result.stderr.strip()}", file=sys.stderr)
                    except Exception as e:
                        print(f"❌ Failed to call update_secret_manager.py: {str(e)}", file=sys.stderr)
                
                if result.returncode != 0:
                    print("⚠️  Environment analysis completed with warnings", file=sys.stderr)
                    
            except subprocess.TimeoutExpired:
                print("⚠️  Environment analysis timed out", file=sys.stderr)
            except Exception as e:
                print(f"⚠️  Could not run environment analysis: {e}", file=sys.stderr)
        
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()