#!/usr/bin/env python3
"""
Extract JWT token from the default browser's session data
Uses browser-cookie3 library to handle encrypted cookies automatically
Includes interactive authentication flow when no cookies are found
"""

from logger import log_success, log_warning, log_error, log_info, log_start, log_end
import sys
import os
import json
import requests
import browser_cookie3
import subprocess
import time
from utils import Colors, colored_print, load_config, get_browser_info

def get_browser_cookies_for_domain(browser_id, domain):
    """Extract cookies from the default browser using browser-cookie3 with fallbacks"""
    
    # Map browser IDs to browser-cookie3 functions (Safari excluded due to sandboxing)
    browser_functions = {
        'com.microsoft.edgemac': browser_cookie3.edge,
        'com.google.chrome': browser_cookie3.chrome,
        'com.brave.Browser': browser_cookie3.brave,
        'com.brave.browser': browser_cookie3.brave,  # Alternative Brave bundle ID
        'org.mozilla.firefox': browser_cookie3.firefox
    }
    
    browser_func = browser_functions.get(browser_id)
    if not browser_func:
        if browser_id == 'com.apple.safari':
            colored_print("[ERROR] Safari is not supported due to strict sandboxing restrictions", Colors.RED)
            log_error("Safari is not supported due to strict sandboxing restrictions")
            colored_print("[INFO] Please use Chrome, Edge, Firefox, or Brave for automated token extraction", Colors.CYAN)
            colored_print("[INFO] You can temporarily set one of these as your default browser", Colors.CYAN)
        else:
            colored_print(f"[ERROR] Unsupported browser: {browser_id}", Colors.RED)
            log_error(f"Unsupported browser: {browser_id}")
        return {}
    
    # Try multiple approaches for better compatibility
    cookies = {}
    
    # Approach 1: Try with specific domain
    try:
        print(f" Attempting to extract cookies for domain: {domain}", file=sys.stderr)
        cookie_jar = browser_func(domain_name=domain)
        cookies = extract_cookies_from_jar(cookie_jar, domain)
        if cookies:
            return cookies
    except Exception as e:
        pass  # Silent fallback
    
    # Approach 2: Try without domain filter (get all cookies)
    try:
        cookie_jar = browser_func()
        cookies = extract_cookies_from_jar(cookie_jar, domain)
        if cookies:
            return cookies
    except Exception as e:
        pass  # Silent fallback
    
    return {}

def extract_cookies_from_jar(cookie_jar, domain):
    """Extract and filter cookies from a cookie jar"""
    cookies = {}
    cookie_names = []
    
    for cookie in cookie_jar:
        # Check if cookie belongs to our domain
        if (domain in cookie.domain or
            cookie.domain.endswith(f'.{domain}') or
            cookie.domain.startswith(f'.{domain}') or
            cookie.domain == domain):
            
            cookies[cookie.name] = {
                'value': cookie.value,
                'domain': cookie.domain,
                'path': cookie.path,
                'secure': cookie.secure,
                'httponly': hasattr(cookie, 'httponly') and cookie.httponly
            }
            cookie_names.append(cookie.name)
    
    if cookie_names:
        print(f" Total cookies found: {', '.join(cookie_names)}", file=sys.stderr)
    else:
        print(f" No cookies found for domain {domain}", file=sys.stderr)
    
    return cookies

def obfuscate_token(token):
    """Obfuscate the middle portion of a token with fewer asterisks"""
    if len(token) < 12:
        return token[:2] + "***" + token[-2:]
    
    # Keep only first 4 chars and last 4 chars for better security
    return token[:4] + "***" + token[-4:]

def test_api_key_with_cookies(cookies, config):
    """Test that the extracted bearer token is valid"""
    api_key_url = f"{config['oauth']['base_url'].rstrip('/')}{config['oauth']['api_key_endpoint']}"
    
    # Look for token cookies
    token_value = None
    oauth_id_token_value = None
    
    for name, cookie_data in cookies.items():
        if name == 'token' and cookie_data['value']:
            token_value = cookie_data['value']
            print(f" Found bearer token: {obfuscate_token(token_value)}", file=sys.stderr)
    
    final_token = token_value or oauth_id_token_value
    if not final_token:
        colored_print("[ERROR] No bearer token cookies found", Colors.RED)
        log_error("No bearer token cookies found")
        return False
    
    # Prepare headers and cookies for API request
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
        # Test the token by making a request to the API key endpoint (GET request to validate token)
        api_key_url = f"{config['oauth']['base_url'].rstrip('/')}{config['oauth']['api_key_endpoint']}"
        print(f" Testing bearer token with API request to: {api_key_url}", file=sys.stderr)
        
        response = requests.get(
            api_key_url,
            headers=headers,
            cookies=request_cookies,
            timeout=config['timeouts']['api_request']
        )
        
        print(f" Token validation response: {response.status_code}", file=sys.stderr)
        
        if response.status_code == 200:
            colored_print("[SUCCESS] Bearer token extracted and validated", Colors.GREEN)
            log_success("Bearer token extracted and validated")
            colored_print("[INFO] Token is working - use renew_key.py to generate API key with this token", Colors.CYAN)
            return True
        elif response.status_code == 401:
            colored_print("[ERROR] Token validation failed: Unauthorized (401)", Colors.RED)
            log_error("Token validation failed: Unauthorized (401)")
            colored_print("[INFO] Token may be expired or invalid", Colors.YELLOW)
            return False
        elif response.status_code == 403:
            colored_print("[ERROR] Token validation failed: Forbidden (403)", Colors.RED)
            log_error("Token validation failed: Forbidden (403)")
            colored_print("[INFO] Token may not have required permissions", Colors.YELLOW)
            return False
        else:
            colored_print(f"[ERROR] Token validation failed: HTTP {response.status_code}", Colors.RED)
            print(f"Response: {response.text[:200]}", file=sys.stderr)
            return False
        
    except requests.exceptions.Timeout:
        colored_print("[ERROR] Token validation timed out", Colors.RED)
        log_error("Token validation timed out")
        return False
    except requests.exceptions.ConnectionError:
        colored_print("[ERROR] Connection error during token validation", Colors.RED)
        log_error("Connection error during token validation")
        return False
    except Exception as e:
        colored_print(f"[ERROR] API request error: {e}", Colors.RED)
        log_error(f"API request error: {e}")
        return False

def open_browser_for_authentication(browser_info, config):
    """Open the default browser and prompt user to authenticate"""
    login_url = config['oauth']['base_url']
    browser_name = browser_info.get('name', 'Unknown')
    browser_id = browser_info.get('bundle_id')
    
    print(f"🌐 Opening {browser_name} for interactive authentication...", file=sys.stderr)
    print(f"📋 You will be redirected to: {login_url}", file=sys.stderr)
    
    try:
        # Use macOS 'open' command to open URL in default browser
        subprocess.run(['open', login_url], check=True)
        print(f"✅ Browser opened successfully", file=sys.stderr)
        
        # Wait for user to authenticate
        print(f"", file=sys.stderr)
        colored_print("[AUTH] Please complete the following steps:", Colors.YELLOW)
        print(f"   1. Log in to your account in the browser window that just opened", file=sys.stderr)
        print(f"   2. Make sure you are fully authenticated and can access the dashboard", file=sys.stderr)
        print(f"   3. Keep the browser window open", file=sys.stderr)
        print(f"   4. Press Enter here when you have completed authentication", file=sys.stderr)
        print(f"", file=sys.stderr)
        
        # Wait for user confirmation
        input("Press Enter when you have completed authentication in the browser...")
        
        print(f" Attempting to extract cookies after authentication...", file=sys.stderr)
        return True
        
    except subprocess.CalledProcessError as e:
        colored_print(f"[ERROR] Failed to open browser: {e}", Colors.RED)
        log_error(f"Failed to open browser: {e}")
        return False
    except KeyboardInterrupt:
        colored_print("\n[ERROR] Authentication cancelled by user", Colors.RED)
        return False
    except Exception as e:
        colored_print(f"[ERROR] Error during browser authentication: {e}", Colors.RED)
        return False

def retry_cookie_extraction_with_delay(browser_id, domain, max_retries=3, delay=2):
    """Retry cookie extraction with delays to allow browser session to update"""
    for attempt in range(max_retries):
        if attempt > 0:
            print(f"🔄 Retry attempt {attempt + 1}/{max_retries} (waiting {delay}s for browser session to update)...", file=sys.stderr)
            time.sleep(delay)
        
        cookies = get_browser_cookies_for_domain(browser_id, domain)
        if cookies:
            print(f"✅ Successfully extracted cookies on attempt {attempt + 1}", file=sys.stderr)
            return cookies
    
    colored_print(f"[ERROR] Failed to extract cookies after {max_retries} attempts", Colors.RED)
    return {}

def get_bearer_token():
    """Extract bearer token and cookies for use by other scripts"""
    try:
        # Load configuration
        config = load_config()
        domain = config['oauth']['base_url'].replace('https://', '').replace('http://', '').split('/')[0]
        
        # Get default browser info
        browser_info = get_browser_info()
        if not browser_info or not browser_info.get('bundle_id'):
            return {'success': False, 'error': 'Could not detect default browser'}
        
        browser_id = browser_info.get('bundle_id')
        
        # Extract cookies from browser session
        cookies = get_browser_cookies_for_domain(browser_id, domain)
        
        if not cookies:
            return {'success': False, 'error': 'No cookies found in browser session'}
        
        # Look for token cookies
        token_value = None
        for name, cookie_data in cookies.items():
            if name == 'token' and cookie_data['value']:
                token_value = cookie_data['value']
                break
        
        if not token_value:
            return {'success': False, 'error': 'No bearer token cookies found'}
        
        # Return cookies in the original format for compatibility with check_key.py
        return {
            'success': True,
            'token': token_value,
            'cookies': cookies  # Keep original format with nested 'value' keys
        }
    
    except Exception as e:
        return {'success': False, 'error': str(e)}

def main():
    """Main function"""
    log_start()
    colored_print(" Extracting JWT token from default browser session data...", Colors.CYAN)
    
    # Load configuration
    config = load_config()
    domain = config['oauth']['base_url'].replace('https://', '').replace('http://', '').split('/')[0]
    
    # Get default browser info
    browser_info = get_browser_info()
    if not browser_info or not browser_info.get('bundle_id'):
        colored_print("[ERROR] Could not detect default browser", Colors.RED)
        log_error("Could not detect default browser")
        log_end()
        sys.exit(1)
    
    browser_id = browser_info.get('bundle_id')
    browser_name = browser_info.get('name', 'Unknown')
    colored_print(f" Using default browser: {browser_name} ({browser_id})", Colors.CYAN)
    
    # Extract cookies from browser session
    cookies = get_browser_cookies_for_domain(browser_id, domain)
    
    if not cookies:
        colored_print("[ERROR] No cookies found in browser session", Colors.RED)
        log_error("No cookies found in browser session")
        colored_print("[AUTH] Starting interactive authentication flow...", Colors.YELLOW)
        
        # Open browser for interactive authentication
        auth_success = open_browser_for_authentication(browser_info, config)
        
        if not auth_success:
            colored_print("[ERROR] Interactive authentication failed", Colors.RED)
            log_error("Interactive authentication failed")
            log_end()
            sys.exit(1)
        
        # Retry cookie extraction after authentication
        cookies = retry_cookie_extraction_with_delay(browser_id, domain)
        
        if not cookies:
            colored_print("[ERROR] Still no cookies found after authentication", Colors.RED)
            colored_print("[INFO] Troubleshooting:", Colors.CYAN)
            colored_print("   1. Make sure you completed the login process", Colors.WHITE)
            colored_print("   2. Verify you can access the dashboard", Colors.WHITE)
            colored_print("   3. Try running the script again", Colors.WHITE)
            if browser_id == 'com.apple.safari':
                colored_print("   4. For Safari: Grant Terminal 'Full Disk Access' in System Preferences", Colors.WHITE)
            log_end()
            sys.exit(1)
    
    # Test API key generation with extracted cookies
    success = test_api_key_with_cookies(cookies, config)
    
    if not success:
        colored_print("[ERROR] FAILED TO EXTRACT BEARER TOKEN FROM COOKIES", Colors.RED)
        log_error("Failed to extract bearer token from cookies")
        log_end()
        sys.exit(1)
    
    log_end()

if __name__ == "__main__":
    main()