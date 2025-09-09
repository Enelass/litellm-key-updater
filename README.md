# LiteLLM API Key Updater

**Automated API Key Management for LiteLLM Environments**

A Python toolkit that automatically manages API keys for LiteLLM deployments by extracting authentication tokens from your browser session and synchronizing credentials across your development environment.

## Quick Start

### 1. Download
```bash
# Method 1: Automated installer (recommended)
./install.sh

# Method 2: Manual installation
git clone https://github.com/user/litellm-key-updater.git
cd litellm-key-updater
uv venv && source .venv/bin/activate
uv pip install -e .
```

### 2. Configure
Copy and edit the configuration template:
```bash
cp config.template.json config.json
```

Edit `config.json` with your LiteLLM server details:
```json
{
  "oauth": {
    "base_url": "https://your-litellm-instance.com/",
    "api_base_url": "https://api.your-litellm-instance.com/",
    "api_key_endpoint": "/api/v1/auths/api_key",
    "models_endpoint": "/api/v1/models"
  }
}
```

### 3. Run
```bash
# Check current API key status
python3 check_key.py

# Generate new API key  
python3 renew_key.py

# Run complete environment analysis
python3 analyse_env.py
```

## Features

- 🔐 **Browser Token Extraction** - Extracts bearer tokens from Chrome, Edge, Firefox, Brave
- 🔄 **Automatic Key Renewal** - Generates fresh API keys using authenticated sessions
- ✅ **Environment Validation** - Verifies synchronization across keychain, environment variables, VSCode
- 🛡️ **Security Analysis** - Scans for hardcoded secrets with detailed remediation
- 📊 **HTML Reports** - Comprehensive credential management status reports

## Documentation

- **[Standalone Scripts Guide](standalone.md)** - Detailed description of each Python script with screenshots
- **[Architecture Overview](Architecture.md)** - System design, data flow, and integration points  
- **[Authentication Analysis](auth_analysis.md)** - Deep dive into the multi-layer authentication system

## Browser Support

### ✅ Supported
- Google Chrome, Microsoft Edge, Mozilla Firefox, Brave Browser

### ❌ Not Supported  
- Safari (sandboxing restrictions), Opera, Arc Browser

## System Requirements

- **OS**: macOS (primary), Linux (partial support)
- **Python**: 3.8+
- **Browser**: Active LiteLLM session in supported browser

## Troubleshooting

### Common Issues

**"No bearer token found"**
- Ensure you're logged into LiteLLM in your browser
- Check browser is set as system default
- Try refreshing your session

**"API key validation failed"**  
- Verify `config.json` URLs are correct
- Check LiteLLM server accessibility
- Ensure browser session hasn't expired

**Permission errors**
- Check file permissions: `chmod 600 config.json`
- Grant keychain access if prompted

### Debug Mode
```bash
export DEBUG=1
python3 check_key.py
```

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Author

**Florian Bidabe** - [florian@photonsec.com.au](mailto:florian@photonsec.com.au)