# Architecture Overview

## System Architecture

The LiteLLM Key Updater follows a modular architecture with clear separation of concerns:

![System Architecture](assets/Architecture.svg)

## Data Flow

### Authentication Flow

1. **User** executes `check_key.py`
2. **check_key.py** calls `get_bearer.py` to extract browser token
3. **get_bearer.py** returns bearer token + cookies
4. **check_key.py** requests current API key from LiteLLM API
5. **LiteLLM API** returns API key response
6. **check_key.py** validates key permissions against API
7. **LiteLLM API** returns validation result

**If Key Valid:**
- **check_key.py** calls `analyse_env.py` to cross-reference environment
- **analyse_env.py** returns environment analysis
- **check_key.py** returns success + analysis to user

**If Key Expired:**
- **check_key.py** calls `renew_key.py` for auto-renewal
- **renew_key.py** generates new key via LiteLLM API
- **LiteLLM API** returns new API key
- **renew_key.py** returns renewal success
- **check_key.py** returns key renewed status to user

## Module Responsibilities

### Authentication Layer
- **get_bearer.py**: Browser session token extraction
- **renew_key.py**: API key generation and renewal
- **check_key.py**: Key validation and orchestration

### Analysis Layer
- **analyse_env.py**: Environment scanning and discovery
- **report.py**: Security analysis and reporting
- **update_secret_manager.py**: Credential synchronization

### Utility Layer  
- **utils.py**: Shared utilities and configuration management
- **config.json**: Centralized configuration
- **install.sh**: Automated setup and deployment

## Security Design

### Principle of Least Privilege
- Scripts only request necessary permissions
- Sensitive operations isolated to specific modules
- Configuration externalized from code

### Defense in Depth
- Multi-layer authentication (browser → bearer token → API key)
- Environment validation and cross-referencing
- Security scanning and hardcoded secret detection

### Safe Defaults
- Obfuscated output for sensitive data
- Secure file permissions recommended
- No hardcoded credentials in source code

## Integration Points

### Browser Integration
- Encrypted cookie extraction via `browser_cookie3`
- Support for Chrome, Edge, Firefox, Brave
- Automatic session detection and token extraction

### System Integration
- macOS Keychain integration for secure storage
- Environment variable management
- VSCode extension credential detection

### API Integration
- RESTful API communication with LiteLLM
- Standardized headers and authentication
- Timeout and error handling

## Error Handling Strategy

### Graceful Degradation
- Fallback mechanisms for authentication failures
- Continue operation with reduced functionality when possible
- Clear error reporting with actionable recommendations

### Auto-Recovery
- Automatic API key renewal on expiration
- Retry logic for transient network failures
- Session refresh when browser tokens expire

### User Feedback
- Color-coded status messages
- Progress indicators for long operations
- Detailed error context and resolution steps