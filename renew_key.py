#!/usr/bin/env python3
"""
Request API key using extracted bearer token and cookies
Separated from get_bearer.py to keep token extraction and API requests separate
"""

from logger import log_success, log_warning, log_error, log_info, log_start, log_end
import sys
import os
import json
import argparse
import requests
from get_bearer import (
    get_browser_cookies_for_domain,
)
from utils import Colors, colored_print, load_config, get_browser_info

def copy_to_clipboard(text):
    """Copy text to clipboard using macOS pbcopy"""
    try:
        import subprocess
        process = subprocess.run(['pbcopy'], input=text, text=True, timeout=5)
        return process.returncode == 0
    except Exception:
        return False

def request_api_key_with_token(final_token, cookies, silent=False, no_logging=False):
    """Request API key using bearer token and cookies
    
    Returns:
        tuple: (success, api_key) where api_key is None if failed
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
        if not silent:
            print(f"🔑 Requesting API key from: {api_key_url}", file=sys.stderr)
        
        # Try POST to create API key
        response = requests.post(api_key_url, json={}, headers=headers, cookies=request_cookies, timeout=config['timeouts']['api_request'])
        if not silent:
            print(f"API key POST request: {response.status_code}", file=sys.stderr)
        
        if response.status_code in [200, 201]:
            try:
                data = response.json()
                if data.get('api_key'):
                    if not silent:
                        colored_print("[SUCCESS] Success! Created API key", Colors.GREEN)
                        if not no_logging:
                            log_success("API key created successfully")
                        print(f"API_KEY: {data['api_key']}")
                    return (True, data['api_key'])
            except:
                pass
        
        # Try GET to retrieve existing API key
        response = requests.get(api_key_url, headers=headers, cookies=request_cookies, timeout=config['timeouts']['api_request'])
        if not silent:
            print(f"API key GET request: {response.status_code}", file=sys.stderr)
        
        if response.status_code == 200:
            try:
                data = response.json()
                if data.get('api_key'):
                    if not silent:
                        colored_print("[SUCCESS] Retrieved existing API key", Colors.GREEN)
                        if not no_logging:
                            log_success("Retrieved existing API key")
                        print(f"API_KEY: {data['api_key']}")
                    return (True, data['api_key'])
            except:
                pass
        
        # If unauthorized/forbidden, attempt cookie-session auth without Bearer
        if response.status_code in [401, 403]:
            try:
                cookie_headers = dict(headers)
                cookie_headers.pop('Authorization', None)
                if not silent:
                    print("🔄 Retrying with cookie-session auth (no Bearer)...", file=sys.stderr)
                # Retry POST using cookies only
                retry_post = requests.post(api_key_url, json={}, headers=cookie_headers, cookies=request_cookies, timeout=config['timeouts']['api_request'])
                if retry_post.status_code in [200, 201]:
                    try:
                        data = retry_post.json()
                        if data.get('api_key'):
                            if not silent:
                                colored_print("[SUCCESS] Success! Created API key (cookie-session)", Colors.GREEN)
                                if not no_logging:
                                    log_success("API key created successfully via cookie-session")
                                print(f"API_KEY: {data['api_key']}")
                            return (True, data['api_key'])
                    except:
                        pass
                # Retry GET using cookies only
                retry_get = requests.get(api_key_url, headers=cookie_headers, cookies=request_cookies, timeout=config['timeouts']['api_request'])
                if retry_get.status_code == 200:
                    try:
                        data = retry_get.json()
                        if data.get('api_key'):
                            if not silent:
                                colored_print("[SUCCESS] Retrieved existing API key (cookie-session)", Colors.GREEN)
                                if not no_logging:
                                    log_success("Retrieved existing API key via cookie-session")
                                print(f"API_KEY: {data['api_key']}")
                            return (True, data['api_key'])
                    except:
                        pass
            except Exception as e:
                if not silent:
                    colored_print(f"[ERROR] Cookie-session retry failed: {e}", Colors.RED)

        if not silent:
            colored_print(f"[ERROR] API request failed: {response.status_code}", Colors.RED)
            log_error(f"API request failed: {response.status_code}")
            print(f"Response: {response.text[:500]}", file=sys.stderr)
        return (False, None)
        
    except Exception as e:
        if not silent:
            colored_print(f"[ERROR] API request error: {e}", Colors.RED)
            log_error(f"API request error: {e}")
        return (False, None)

def main():
    """Main function for standalone usage"""
    log_start()
    parser = argparse.ArgumentParser(
        description="Generate API key using bearer token from browser cookies",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 renew_key.py                 # Interactive mode - prompts before generating key
  python3 renew_key.py --silent        # Silent mode - generates key without prompting
        """
    )
    parser.add_argument(
        '--silent',
        action='store_true',
        help='Generate API key without interactive confirmation'
    )
    
    args = parser.parse_args()
    
    print("🔑 API Key Generator", file=sys.stderr)
    print("", file=sys.stderr)
    
    # Load configuration and get browser info
    config = load_config()
    browser_info = get_browser_info()
    
    if not browser_info or not browser_info.get('bundle_id'):
        colored_print("[ERROR] Could not detect default browser", Colors.RED)
        log_error("Could not detect default browser")
        log_end()
        sys.exit(1)
    
    # Extract cookies and token from browser
    domain = config['oauth']['base_url'].replace('https://', '').replace('http://', '').split('/')[0]
    cookies = get_browser_cookies_for_domain(browser_info['bundle_id'], domain)
    
    if not cookies:
        colored_print("[ERROR] No cookies found in browser session", Colors.RED)
        log_error("No cookies found in browser session")
        colored_print("[INFO] Please make sure you're logged in to the service in your browser", Colors.CYAN)
        sys.exit(1)
    
    # Look for bearer token in cookies
    token_value = None
    for name, cookie_data in cookies.items():
        if name == 'token' and cookie_data['value']:
            token_value = cookie_data['value']
            break
    
    if not token_value:
        colored_print("[ERROR] No bearer token found in cookies", Colors.RED)
        log_error("No bearer token found in cookies")
        colored_print("[INFO] Please make sure you're logged in and authenticated", Colors.CYAN)
        sys.exit(1)
    
    colored_print(f"[SUCCESS] Found bearer token in {browser_info.get('name', 'browser')} cookies", Colors.GREEN)
    log_success(f"Found bearer token in {browser_info.get('name', 'browser')} cookies")
    
    # Interactive confirmation unless --silent is specified
    if not args.silent:
        print("", file=sys.stderr)
        colored_print("[WARNING] This will generate a new API key for your account.", Colors.YELLOW)
        log_warning("User initiated API key generation")
        colored_print("[INFO] Note: This may invalidate existing API keys.", Colors.CYAN)
        print("", file=sys.stderr)
        
        try:
            response = input("Do you want to proceed with API key generation? [y/N]: ").strip().lower()
            if response not in ['y', 'yes']:
                colored_print("[ERROR] API key generation cancelled by user", Colors.RED)
                log_info("API key generation cancelled by user")
                sys.exit(0)
        except KeyboardInterrupt:
            colored_print("\n[ERROR] API key generation cancelled by user", Colors.RED)
            sys.exit(0)
        
        print("", file=sys.stderr)
    
    # Generate the API key
    print("🔄 Generating API key...", file=sys.stderr)
    success, api_key = request_api_key_with_token(token_value, cookies)
    
    if success and api_key:
        colored_print("[SUCCESS] API key generated successfully!", Colors.GREEN)
        log_success("API key generated successfully")
        
        # Copy to clipboard
        if copy_to_clipboard(api_key):
            print("📋 API key copied to clipboard!", file=sys.stderr)
        else:
            print("⚠️  Could not copy to clipboard (pbcopy not available)", file=sys.stderr)
        
        log_end()
        sys.exit(0)
    else:
        colored_print("[ERROR] Failed to generate API key", Colors.RED)
        log_error("Failed to generate API key")
        log_end()
        sys.exit(1)

if __name__ == "__main__":
    main()
