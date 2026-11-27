"""Cookie parsing and SameSite policy enforcement.

A parsed cookie has the shape::

    {
        "name": "sid",
        "value": "abc",
        "attrs": {
            "samesite": "Lax",
            "secure": True,
            "httponly": True,
            "path": "/",
        },
    }

Policies are dictionaries with ``default_samesite``,
``allow_missing_samesite`` and ``allow_insecure`` entries. Attribute names are
stored in normalized form and SameSite values use the canonical spelling
``Strict``, ``Lax`` or ``None``.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

SAMESITE_VALUES = ("Strict", "Lax", "None")
SAMESITE_RANK = {"None": 0, "Lax": 1, "Strict": 2}
_STRICTEST = "Strict"

_KNOWN_SAMESITE = {
    "strict": "Strict",
    "s": "Strict",
    "lax": "Lax",
    "l": "Lax",
    "none": "None",
    "n": "None",
}


def normalize_attr(name: Any) -> str:
    """Return the canonical spelling of a cookie attribute name."""
    return str(name).strip().lower()


def parse_samesite(value: Any) -> str:
    """Map a SameSite value to ``Strict``, ``Lax`` or ``None``.

    Unrecognized values and non-string input fall back to the strictest valid
    policy rather than to a permissive default.
    """
    if not isinstance(value, str):
        return _STRICTEST
    return _KNOWN_SAMESITE.get(value.strip().lower(), _STRICTEST)


def _as_flag(value: Any) -> bool:
    """Interpret a valueless or boolean-like attribute value."""
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() not in {"", "false", "0", "no", "off"}


def _is_session(attrs: Mapping[str, Any]) -> bool:
    """A cookie without an expiry attribute lives for the browser session."""
    return "max-age" not in attrs and "expires" not in attrs


def _merge_attr(name: str, current: Any, candidate: Any) -> Any:
    """Merge a repeated attribute using the security-strictest occurrence."""
    if name == "samesite":
        if SAMESITE_RANK[candidate] > SAMESITE_RANK[current]:
            return candidate
        return current

    if name in {"secure", "httponly"}:
        # A present/true protection flag cannot be cancelled by a repeat.
        return bool(current) or bool(candidate)

    return candidate


def _canonical_attrs(attrs: Mapping[str, Any] | None) -> dict[str, Any]:
    """Normalize attribute names/values and merge duplicate names."""
    canonical: dict[str, Any] = {}
    for raw_name, raw_value in (attrs or {}).items():
        name = normalize_attr(raw_name)

        if name == "samesite":
            value: Any = parse_samesite(raw_value)
        elif name in {"secure", "httponly"}:
            value = _as_flag(raw_value)
        else:
            value = raw_value

        if name in canonical:
            canonical[name] = _merge_attr(name, canonical[name], value)
        else:
            canonical[name] = value

    return canonical


def _resolve_attrs(pairs: Iterable[tuple[Any, Any]]) -> dict[str, Any]:
    """Resolve raw ``(name, value)`` pairs into a canonical attribute map."""
    resolved: dict[str, Any] = {}

    for raw_name, raw_value in pairs:
        name = normalize_attr(raw_name)

        if name == "samesite":
            value: Any = parse_samesite(raw_value)
        elif name in {"secure", "httponly"}:
            value = _as_flag(raw_value)
        else:
            value = raw_value

        if name in resolved:
            resolved[name] = _merge_attr(name, resolved[name], value)
        else:
            resolved[name] = value

    return resolved


def parse_cookie(line: str) -> dict:
    """Parse a Set-Cookie-style header fragment into name, value and attrs."""
    pieces = str(line).split(";")
    head = pieces[0].strip()

    if "=" in head:
        name, value = head.split("=", 1)
    else:
        name, value = head, ""

    pairs: list[tuple[Any, Any]] = []
    for piece in pieces[1:]:
        token = piece.strip()
        if not token:
            continue

        if "=" in token:
            attr_name, attr_value = token.split("=", 1)
        else:
            attr_name, attr_value = token, True

        pairs.append((attr_name, attr_value))

    return {
        "name": name.strip(),
        "value": value.strip(),
        "attrs": _resolve_attrs(pairs),
    }


def check_secure(cookie: Mapping[str, Any]) -> bool:
    """Return whether a cookie has the transport protection it needs."""
    attrs = _canonical_attrs(cookie.get("attrs", {}))

    if attrs.get("samesite") == "None":
        return _as_flag(attrs.get("secure", False))

    return True


def _is_valid_samesite(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value.strip().lower() in _KNOWN_SAMESITE
    )


def _deny(cookie: Mapping[str, Any], reason: str) -> dict:
    """Build a rejection without echoing cookie value or attributes."""
    return {
        "name": cookie.get("name", ""),
        "value": "",
        "attrs": {},
        "accepted": False,
        "reason": reason,
    }


def enforce(cookie: Mapping[str, Any], policy: Mapping[str, Any]) -> dict:
    """Apply a SameSite policy to one cookie and return its effective form."""
    policy = policy or {}

    raw_name = cookie.get("name", "")
    name = "" if raw_name is None else str(raw_name)
    raw_value = cookie.get("value", "")
    value = "" if raw_value is None else str(raw_value)

    attrs = _canonical_attrs(cookie.get("attrs", {}))
    session = _is_session(attrs)

    if "samesite" not in attrs:
        default = policy.get("default_samesite")
        if default is not None:
            # An invalid policy default is itself treated as Strict.
            attrs["samesite"] = parse_samesite(default)
        elif session or not policy.get("allow_missing_samesite", False):
            return _deny(cookie, "missing_samesite")
        # A non-session cookie may remain unset only when policy permits it.

    samesite = attrs.get("samesite")

    # SameSite=None permits cross-site delivery, so it is not a restriction
    # that satisfies a session cookie's required same-site boundary.
    if session and samesite == "None":
        return _deny(cookie, "session_samesite_not_restrictive")

    if (
        samesite == "None"
        and not _as_flag(attrs.get("secure", False))
        and not policy.get("allow_insecure", False)
    ):
        return _deny(cookie, "missing_secure")

    return {
        "name": name,
        "value": value,
        "attrs": attrs,
        "accepted": True,
        "reason": "",
    }


def check_duplicates(attrs: Iterable[tuple[Any, Any]]) -> bool:
    """Return whether ordered SameSite occurrences end at the strictest value.

    The parsed attribute map always keeps the strictest value via
    :func:`_resolve_attrs`; this helper additionally checks whether the input
    ordering itself follows strictest-wins semantics.
    """
    values = [
        parse_samesite(raw_value)
        for raw_name, raw_value in attrs
        if normalize_attr(raw_name) == "samesite"
    ]

    if not values:
        return True

    strictest = max(values, key=lambda item: SAMESITE_RANK[item])
    return values[-1] == strictest


def validate_policy(policy: Mapping[str, Any]) -> list[str]:
    """Return the security problems found in a policy document."""
    policy = policy or {}
    issues: list[str] = []

    default = policy.get("default_samesite")
    if default is None:
        issues.append("policy requires a default SameSite value")
    elif not _is_valid_samesite(default):
        issues.append("policy has an invalid default SameSite value")

    if policy.get("allow_missing_samesite"):
        issues.append("policy allows cookies without SameSite")
    if policy.get("allow_insecure"):
        issues.append("policy allows insecure transport")

    return issues


def _as_cookie(item: Any) -> dict:
    """Coerce a batch item into the cookie dictionary shape."""
    if isinstance(item, str):
        return parse_cookie(item)
    if isinstance(item, Mapping):
        return dict(item)
    return {"name": "", "value": "", "attrs": {}}


def cookie_batch(cookies: Iterable[Any], policy: Mapping[str, Any]) -> dict:
    """Validate cookies independently and summarize the decisions."""
    results: list[dict] = [
        enforce(_as_cookie(item), policy)
        for item in cookies
    ]

    accepted = sum(1 for result in results if result["accepted"])
    return {
        "results": results,
        "accepted": accepted,
        "rejected": len(results) - accepted,
    }
