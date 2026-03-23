"""Regression tests for renew-key output safety."""

from types import SimpleNamespace

from litellm_key_updater import renew_key


def test_request_api_key_with_token_does_not_print_raw_key(monkeypatch, capsys):
    """Interactive renew output should not echo the full API key."""
    api_key = "sk-dP9loLkhXJRxcm_53teJDg"

    monkeypatch.setattr(
        renew_key,
        "load_config",
        lambda: {
            "oauth": {
                "base_url": "https://example.com",
                "api_key_endpoint": "/api/v1/auths/api_key",
            },
            "headers": {
                "content_type": "application/json",
                "accept": "application/json",
                "accept_language": "en-AU,en;q=0.9",
                "accept_encoding": "gzip, deflate, br",
                "connection": "keep-alive",
                "user_agent": "pytest",
            },
            "timeouts": {"api_request": 5},
        },
    )

    monkeypatch.setattr(
        renew_key.requests,
        "post",
        lambda *args, **kwargs: SimpleNamespace(
            status_code=200,
            json=lambda: {"api_key": api_key},
        ),
    )

    success, returned_key = renew_key.request_api_key_with_token(
        "token",
        {"token": {"value": "token"}},
        silent=False,
        no_logging=True,
    )

    captured = capsys.readouterr()

    assert success is True
    assert returned_key == api_key
    assert api_key not in captured.out
    assert api_key not in captured.err
    assert renew_key.obfuscate_key(api_key) in captured.out
