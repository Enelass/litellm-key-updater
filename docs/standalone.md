# Standalone Scripts Guide

This document describes each Python script in the LiteLLM Key Updater toolkit and provides visual examples of their output.

## Core Scripts

### `check-key` - API Key Validation
**Purpose**: Validates your current API key and checks environment synchronization

**Features**:
- Extracts browser authentication tokens
- Retrieves current API key from LiteLLM server
- Validates key is active by testing against models endpoint
- Cross-references with local environment (keychain, env vars, VSCode)
- Reports mismatches and provides sync recommendations

**Usage**:
```bash
check-key
```

**Example Output**:
![Check Key Screenshot](../assets/check_key.png)

---

### `get-bearer` - Browser Token Extraction
**Purpose**: Extracts and validates browser authentication tokens

**Features**:
- Supports Chrome, Edge, Firefox, Brave browsers
- Handles encrypted cookie stores automatically
- Validates token against LiteLLM API endpoints
- Interactive authentication flow when no session found

**Usage**:
```bash
get-bearer
```

**Example Output**:
![Bearer Token Screenshot](../assets/get_bearer.png)

---

### `renew-key` - API Key Generation
**Purpose**: Generates fresh API keys using browser session

**Features**:
- Extracts authenticated bearer token from browser
- Requests new API key from LiteLLM server
- Automatically copies key to clipboard
- Silent mode for scripting integration

**Usage**:
```bash
renew-key
```

**Example Output**:
![Renew Key Screenshot](../assets/renew_key.png)

---

### `analyse-env` - Environment Analysis
**Purpose**: Comprehensive environment analysis and discovery

**Features**:
- Scans for AI CLI tools (Claude, Gemini, etc.)
- Discovers VSCode AI extensions with API key storage
- Checks macOS Keychain for stored credentials
- Validates environment variable configuration
- Cross-references active key with environment

**Usage**:
```bash
analyse-env
```

**Example Output**:
![Environment Analysis Screenshot](../assets/Analysis%20Report.png)

---

### `generate-report` - Security Analysis
**Purpose**: Generates comprehensive security reports

**Features**:
- Scans for hardcoded API keys and secrets
- Analyzes file permissions and security risks
- Provides remediation recommendations
- Generates HTML reports with detailed findings
- Secure storage guidance and best practices

**Usage**:
```bash
generate-report
```

**Example Output**:
![Security Report Screenshot](../assets/Analysis%20Report.png)

---

### `update-secretmgr` - Credential Synchronization
**Purpose**: Updates macOS Keychain with validated API keys

**Features**:
- Security scanner integration (blocks if hardcoded secrets found)
- Keychain-only updates (no environment file modification)
- Current key validation before updates
- Timestamped logging and audit trail

**Usage**:
```bash
update-secretmgr
```

**Example Output**:
![Secret Manager Screenshot](../assets/update_secret_manager.png)

---

## Utility Scripts

### `litellm_key_updater.utils` - Shared Utilities
**Purpose**: Provides common functionality across all scripts

**Features**:
- Configuration loading and validation
- Browser detection and cookie extraction helpers
- Color-coded console output
- System information gathering
- API key obfuscation for safe logging

**Usage**: Imported by other scripts, not run directly

**Example Output**:
![Utils Screenshot](../assets/utils.png)

---

### `install.sh` - Automated Installation
**Purpose**: Automates the download and setup process

**Features**:
- Checks for existing installation
- Downloads from GitHub repository
- Sets up virtual environment with uv
- Installs dependencies automatically
- Validates installation completeness

**Usage**:
```bash
./install.sh
```

**Example Output**:
*Installation output shown in terminal*

---

## Configuration Files

### `config/config.json` - Main Configuration
Contains all endpoint URLs, headers, and timeout settings for your LiteLLM instance.

### `config/config.template.json` - Configuration Template
Template file with placeholder values for initial setup.

---

## Integration Workflows

### Basic Validation Workflow
```bash
# 1. Check current key status
check-key

# 2. Generate new key if needed
renew-key

# 3. Validate environment sync
analyse-env
```

### Security Audit Workflow
```bash
# 1. Run security scan
generate-report

# 2. Fix any hardcoded secrets
# (manual step)

# 3. Update keychain safely
update-secretmgr
```

### Troubleshooting Workflow
```bash
# 1. Extract browser token manually
get-bearer

# 2. Validate token works
check-key

# 3. Generate fresh key if needed
renew-key
```

---

## Script Dependencies

```mermaid
graph LR
    A[check-key] --> B[get-bearer]
    A --> C[renew-key]
    A --> D[analyse-env]
    A --> E[litellm_key_updater.utils]
    
    F[generate-report] --> E
    G[update-secretmgr] --> A
    G --> F
    
    H[install.sh] --> I[All Scripts]
```

All commands depend on `litellm_key_updater.utils` for shared functionality and `config/config.json` for configuration settings.
