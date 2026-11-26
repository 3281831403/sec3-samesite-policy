"""Public tests for the SameSite policy helpers."""

from samesite import (
    check_secure,
    cookie_batch,
    enforce,
    parse_cookie,
    parse_samesite,
)

POLICY = {
    "default_samesite": "Strict",
    "allow_missing_samesite": False,
    "allow_insecure": False,
}


def test_parse_cookie_reads_name_value_and_attributes():
    cookie = parse_cookie("sid=abc; sAmEsItE=Lax; SeCuRe; hTtPoNlY; Path=/app")

    assert cookie["name"] == "sid"
    assert cookie["value"] == "abc"
    assert cookie["attrs"].get("samesite") == "Lax"
    assert cookie["attrs"].get("secure") is True
    assert cookie["attrs"].get("httponly") is True
    assert cookie["attrs"].get("path") == "/app"


def test_parse_samesite_returns_canonical_values():
    assert parse_samesite("Strict") == "Strict"
    assert parse_samesite("LAX") == "Lax"
    assert parse_samesite(" none ") == "None"
    assert parse_samesite("unexpected-value") == "Strict"


def test_enforce_adds_default_samesite_to_session_cookie():
    cookie = parse_cookie("sid=abc; Secure")
    result = enforce(cookie, POLICY)

    assert result["accepted"] is True
    assert result["attrs"].get("samesite") == "Strict"


def test_cross_site_cookie_without_secure_is_not_protected():
    cookie = parse_cookie("tracker=1; samesite=None")

    assert check_secure(cookie) is False


def test_batch_keeps_two_cookies_independent():
    first = parse_cookie("a=1; SameSite=None; Secure; Max-Age=60")
    second = parse_cookie("b=2; SameSite=None; Max-Age=60")

    batch = cookie_batch([first, second], POLICY)

    assert len(batch["results"]) == 2
    assert batch["results"][0]["accepted"] is True
    assert batch["results"][1]["accepted"] is False