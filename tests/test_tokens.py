"""Tests for Capability Tokens."""

import time
from taintgate.core.decisions import CapabilityToken

SECRET_KEY = b"test-secret-key-32-bytes-long!!!"


def test_token_mint_and_verify():
    args = {"to": "alice@example.com", "body": "hello"}
    token = CapabilityToken.mint("email.send", args, SECRET_KEY, ttl_seconds=10.0)

    # Valid verification
    assert token.verify("email.send", args, SECRET_KEY) is True


def test_token_tampered_args_rejected():
    args = {"to": "alice@example.com", "body": "hello"}
    token = CapabilityToken.mint("email.send", args, SECRET_KEY, ttl_seconds=10.0)

    # Attacker changes recipient to evil.com
    tampered_args = {"to": "evil@attacker.com", "body": "hello"}
    assert token.verify("email.send", tampered_args, SECRET_KEY) is False


def test_token_wrong_tool_rejected():
    args = {"path": "file.txt"}
    token = CapabilityToken.mint("fs.read", args, SECRET_KEY, ttl_seconds=10.0)
    assert token.verify("fs.write", args, SECRET_KEY) is False


def test_token_expired_rejected():
    args = {"cmd": "run"}
    token = CapabilityToken.mint("tool", args, SECRET_KEY, ttl_seconds=0.01)
    time.sleep(0.05)
    assert token.verify("tool", args, SECRET_KEY) is False
