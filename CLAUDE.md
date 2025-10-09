# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

LiteLLM API Key Updater is a macOS Python toolkit that automates API key rotation for Open-WebUI + LiteLLM Enterprise deployments. It extracts browser session tokens, generates fresh API keys, and manages secure storage in macOS Keychain.

## Core Architecture

- **Browser Token Extraction**: Uses `browser_cookie3` to extract JWT tokens from browser sessions (Chrome, Edge, Firefox, Brave - not Safari due to sandboxing)
- **API Key Management**: Generates new API keys via LiteLLM Enterprise API using extracted bearer tokens
- **Secure Storage**: Stores API keys in macOS Keychain and auto-configures shell environment variables
- **Environment Analysis**: Scans for hardcoded secrets and generates security reports

## Common Development Commands

### Setup
```bash
# Clone and setup virtual environment
git clone https://github.com/Enelass/litellm-key-updater.git
cd litellm-key-updater
uv venv && source .venv/bin/activate
uv pip install -e .

# Alternative: Install from source without virtual environment
pip install -e .
```

### Configuration
```bash
# Copy and edit configuration template
cp config.template.json config.json
# Edit config.json with your server URLs
```

### Key Operations
```bash
# Check current API key status and validate
python3 check_key.py
# OR use CLI command after installation: check-key

# Force renewal of API key regardless of status
python3 check_key.py --renew
# OR: check-key --renew

# Generate new API key (interactive mode)
python3 renew_key.py
# OR: renew-key

# Extract bearer token from browser
python3 get_bearer.py
# OR: get-bearer

# Analyze environment for hardcoded secrets
python3 analyse_env.py

# Update secrets in Secret Manager (alternative storage)
python3 update_secretmgr.py
```

### Testing and Development
```bash
# Install daemon for automatic daily key checking
./install.sh --daemon

# Run environment analysis without opening browser
python3 analyse_env.py --no-browser

# Verify specific API key
python3 analyse_env.py --verify-key sk-xxxxx
```

## Key Components

### Core Scripts
- `check_key.py`: Main script - validates current API key, auto-renews if expired, syncs keychain
- `renew_key.py`: API key generation using browser bearer tokens
- `get_bearer.py`: Browser session token extraction with fallback authentication
- `analyse_env.py`: Environment scanning for security analysis
- `update_secretmgr.py`: Alternative Secret Manager integration for cloud storage
- `report.py`: HTML report generation for security analysis
- `utils.py`: Shared utilities (browser detection, config loading, system info)
- `logger.py`: Centralized logging system

### Configuration
- `config.json`: Server URLs, API endpoints, request headers, timeouts
- `pyproject.toml`: Package definition with entry points for CLI commands

### Browser Support Matrix
- ✅ Chrome (`com.google.chrome`)
- ✅ Edge (`com.microsoft.edgemac`)
- ✅ Firefox (`org.mozilla.firefox`)
- ✅ Brave (`com.brave.Browser`)
- ❌ Safari (sandboxing restrictions)

## Key Integration Points

### Authentication Flow
1. Browser session detection → Bearer token extraction
2. Bearer token validation → API key request/renewal
3. Keychain storage → Shell environment variable setup
4. Environment analysis → Security report generation

### Error Handling Patterns
- Browser detection failures trigger interactive authentication flow
- API key validation failures automatically trigger renewal
- Keychain sync maintains consistency between active and stored keys
- Network timeouts have configurable retry logic

### Security Considerations
- API keys are obfuscated in logs (first 4 + last 4 chars)
- Keychain integration uses macOS `security` command
- Environment scanning detects hardcoded secrets in shell configs
- HTML reports generated for security analysis

## Testing Notes

- Scripts expect macOS environment with supported browsers
- Interactive authentication flow opens browser when no session found
- Keychain operations require user permission on first run
- Environment analysis scans common config files (`~/.zshrc`, `~/.bashrc`, etc.)