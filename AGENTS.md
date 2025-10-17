# Repository Guidelines

## Project Structure & Module Organization
- Root contains Python utilities: `check_key.py`, `renew_key.py`, `get_bearer.py`, `update_secretmgr.py`, `utils.py`, `logger.py`, `report.py`.
- Configuration: `config.json` (local), `config.template.json` (example). Docs in `README.md`, `Architecture.md`, `auth_analysis.md`, `standalone.md`.
- Assets and diagrams: `assets/`.
- Installer: `install.sh`. Packaging metadata: `pyproject.toml`.

## Build, Test, and Development Commands
- Run scripts directly (Python 3.8–3.12 supported):
  - `python check_key.py` — validate current API key and config.
  - `python renew_key.py` — rotate/renew keys via configured endpoints.
  - `python get_bearer.py` — obtain OAuth bearer/token.
  - `python report.py` — generate key/report outputs.
- Install dependencies:
  - `./install.sh` — optional helper to set up environment and tools.

## Coding Style & Naming Conventions
- Python style: 4‑space indentation, snake_case for functions/variables, PascalCase for classes.
- Keep modules small and focused; prefer pure functions in `utils.py`.
- Logging via `logger.py`; avoid print in library modules.
- Configuration keys follow JSON lower_snake_case (e.g., `oauth.base_url`).

## Testing Guidelines
- Add targeted tests for new logic (pytest recommended). Place tests under `tests/` (create if absent) mirroring module names: `tests/test_utils.py`.
- Use deterministic inputs; mock network calls when possible.
- Run locally: `pytest -q`.

## Commit & Pull Request Guidelines
- Commit messages: short imperative subject (≤72 chars), concise body when needed.
- PRs should include: purpose, summary of changes, how to run, and any config impacts.
- Link related issues; include sample commands or screenshots when relevant.

## Security & Configuration Tips
- Do not commit real secrets or production `config.json`; use `config.template.json`.
- Prefer environment variables or secret managers; rotate keys with `renew_key.py`.
- Review `security_report.html` and `auth_analysis.md` when changing auth flows.
