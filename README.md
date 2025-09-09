# LiteLLM API Key Updater

![LiteLLM](https://img.shields.io/badge/LiteLLM-1.73-blue?style=flat-square)
![macOS](https://img.shields.io/badge/macOS-Tested-green?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.8+-orange?style=flat-square)

**sk- API Key renewal on MacOS**

Security should not be at the expense of usability. Short-lived API keys provide superior security benefits - the shorter the expiry, the more secure the system becomes. However, frequent key rotation traditionally creates friction for users.

I like to improve UX while maintaining security, which often isn't the case and results in productivity loss. This toolkit bridges that gap by automating the tedious manual renewal process while enhancing security through proper credential management.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          WITHOUT THIS TOOL                                      │
│                    (Manual + Waste of Time + Poor UX)                           │
└─────────────────────────────────────────────────────────────────────────────────┘

    Every time your API key expires (every few days):

    User → SSO Auth → Login → Navigate → Click Renew → Copy Key → Paste Insecurely
     ↓                         ↓                                          ↓
    😤                         🕐                                   🚨 INSECURE
                              Time                                  (.env files,
                             Wasted                                 ~/.zshrc, etc.)

┌─────────────────────────────────────────────────────────────────────────────────┐
│                           WITH THIS TOOL                                        │
│                  (Nothing to do past the setup)                                 │
└─────────────────────────────────────────────────────────────────────────────────┘

    One-time setup:

    User → Install → Configure → Done Forever
      ↓       ↓        ↓          ↓
              🚀       ⚙️        🔐
            Quick    Simple    Secure Keychain
            Setup    Config    Auto-rotation
                               (Daily @ 9:30 AM)

    Then: 🎯 ZERO ongoing user effort - keys rotate automatically in background
```

This Python toolkit eliminates the manual process by automatically managing API key rotation for [Open-WebUI](https://github.com/open-webui/open-webui) + [LiteLLM Enterprise](https://www.litellm.ai/enterprise) deployments, making security transparent to users while protecting LLM endpoints through seamless credential management.

## Quick Start

### 1. Download
#### Method 1: Automated installer (recommended)
```bash
/bin/zsh -c "$(curl -fsSL https://raw.githubusercontent.com/Enelass/litellm-key-updater/refs/heads/main/install.sh)"
```

#### Method 2: Manual installation
```bash
git clone https://github.com/Enelass/litellm-key-updater.git
cd litellm-key-updater
uv venv && source .venv/bin/activate
uv pip install -e .
```

### 2. Configure (One-Off)
Copy and edit the configuration template:
```bash
cd ~/Applications/litellm-key-updater/
cp config.template.json config.json
```

Edit `config.json` with your server details:
```json
  "oauth": {
    "base_url": "https://your-open-webui-instance.com/",
    "api_base_url": "https://your-litellm-enterprise-api.com/",
```

**Configuration Details:**
- `base_url`: Your [Open-WebUI](https://github.com/open-webui/open-webui) frontend instance URL
- `api_base_url`: Your [LiteLLM Enterprise](https://www.litellm.ai/enterprise) API backend URL

### Shell Configuration
Configure your shell to automatically load the API key from Keychain. Add these lines to your shell configuration file:

** For ZSH or Bash Users `~/.zshrc`, `~/.bash_profile` or `~/.bashrc`:**
```bash
# LiteLLM API Key from Keychain
export LITELLM_MASTER_KEY=$(security find-generic-password -s "LITELLM_API_KEY" -w)
export OPENAI_API_KEY="$LITELLM_MASTER_KEY"
export ANTHROPIC_AUTH_TOKEN="$LITELLM_MASTER_KEY"
export GEMINI_API_KEY="$LITELLM_MASTER_KEY"
```

After adding these lines, restart your terminal or run `source ~/.zshrc` (or `source ~/.bash_profile`) to apply the changes.

**Environment Variable Details:**
- `LITELLM_MASTER_KEY`: Main API key retrieved from Keychain
- `ANTHROPIC_AUTH_TOKEN`: Anthropic Claude API compatibility for Claude Code or Claude App
- `GEMINI_API_KEY`: Google Gemini API compatibility for Gemini CLI
- `OPENAI_API_KEY`: OpenAI API compatibility


### 3. Run
```bash
# Check current API key status
python3 check_key.py
```

### 4. Automatic Renewal (Optional)
If step 3 is successful, you can enable automatic daily key checking:
```bash
./install.sh --daemon
```

## Features

- 🔄 **Automatic Key Renewal** - Generates fresh API keys using authenticated sessions
- 🛡️ **Security Analysis** - HTML Reports for hardcoded secrets with detailed remediation

## Documentation

- **[Standalone Scripts Guide](standalone.md)** - Detailed description of each Python script with screenshots
- **[Architecture Overview](Architecture.md)** - System design, data flow, and integration points  
- **[Authentication Analysis](auth_analysis.md)** - Deep dive into the multi-layer authentication system

## Browser Support

### ✅ Supported
- Google Chrome, Microsoft Edge, Mozilla Firefox, Brave Browser

### ❌ Not Supported
- Safari (Strict Sandboxing)
- Opera or less mainstream browsers
- VSCode API Key update (WIP)
- Linux (untested)

## System Requirements

- **OS**: macOS (primary)
- **Python**: 3.8+
- **Browser**: Active Open-WebUI session in supported browser

## Troubleshooting

### Common Issues

**"No bearer token found"**
You haven't SSOed into your system yet or a token would have been found

Ensure you're logged into LiteLLM in your browser

**"API key validation failed"**  
- Verify `config.json` URLs are correct
- Check LiteLLM server accessibility
- Ensure browser session hasn't expired

**Permission errors**
- Check file permissions: `chmod 600 config.json`
- Grant keychain access if prompted


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
