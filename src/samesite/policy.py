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
``allow_missing_samesite`` and ``allow_insecure`` entries.  Attribute names
are stored in normalized form and SameSite values use the canonical spelling
``Strict``, ``Lax`` or ``None``.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

SAMESITE_VALUES = ("Strict", "Lax", "None")
SAMESITE_RANK = {"None": 0, "Lax": 1, "Strict": 2}
_KNOWN_SAMESITE = {
    "strict": "Strict",
    "lax": "Lax",
    "none": "None",
}


def normalize_attr(name: Any) -> str:
    """Return the canonical spelling of a cookie attribute name."""
    return str(name).strip()


def parse_samesite(value: Any) -> str:
    """Map an attribute value to one of the three canonical SameSite values."""
    if not isinstance(value, str):
        return "Lax"
    return _KNOWN_SAMESITE.get(value.strip().lower(), "Lax")


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


def _resolve_attrs(pairs: Iterable[tuple[Any, Any]]) -> dict[str, Any]:
    resolved: dict[str, Any] = {}
    for raw_name, raw_value in pairs:
        name = normalize_attr(raw_name)
        if name == "samesite":
            resolved[name] = parse_samesite(raw_value)
        elif name in {"secure", "httponly"}:
            resolved[name] = _as_flag(raw_value)
        else:
            resolved[name] = raw_value
    return resolved


def parse_cookie(line: str) -> dict:
    """Parse a Cookie header fragment into a name, value and attribute map."""
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
    """Return whether a cookie carries the transport protection it needs."""
    attrs = cookie.get("attrs", {})
    if attrs.get("samesite") == "None":
        return bool(attrs.get("secure", True))
    return True


def _canonical_attrs(attrs: Mapping[str, Any]) -> dict[str, Any]:
    canonical: dict[str, Any] = {}
    for raw_name, raw_value in attrs.items():
        name = normalize_attr(raw_name)
        if name == "samesite":
            canonical[name] = parse_samesite(raw_value)
        elif name in {"secure", "httponly"}:
            canonical[name] = _as_flag(raw_value)
        else:
            canonical[name] = raw_value
    return canonical


def _is_valid_samesite(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value.strip().lower() in _KNOWN_SAMESITE
    )


def _deny(cookie: Mapping[str, Any], reason: str) -> dict:
    return {
        "name": cookie.get("name", ""),
        "value": cookie.get("value", ""),
        "attrs": dict(cookie.get("attrs", {})),
        "accepted": False,
        "reason": reason,
    }


def enforce(cookie: Mapping[str, Any], policy: Mapping[str, Any]) -> dict:
    """Apply a policy to one cookie and return the effective cookie."""
    name = str(cookie.get("name", ""))
    value = str(cookie.get("value", ""))
    attrs = dict(cookie.get("attrs", {}))
    session = _is_session(attrs)
    samesite = attrs.get("samesite")

    if samesite is None:
        if not session:
            default = policy.get("default_samesite")
            if default is None:
                return _deny(
                    {"name": name, "value": value, "attrs": attrs},
                    "missing_samesite",
                )
    else:
        attrs["samesite"] = parse_samesite(samesite)

    return {
        "name": name,
        "value": value,
        "attrs": attrs,
        "accepted": True,
        "reason": "",
    }


def check_duplicates(attrs: Iterable[tuple[Any, Any]]) -> bool:
    """Check whether duplicate attributes keep their strictest value."""
    seen: dict[str, Any] = {}
    for raw_name, raw_value in attrs:
        name = normalize_attr(raw_name)
        if name == "samesite":
            seen[name] = parse_samesite(raw_value)
    return all(value in SAMESITE_VALUES for value in seen.values())


def validate_policy(policy: Mapping[str, Any]) -> list[str]:
    """Return the security problems found in a policy document."""
    issues: list[str] = []
    if policy.get("allow_missing_samesite"):
        issues.append("policy allows cookies without SameSite")
    if policy.get("allow_insecure"):
        issues.append("policy allows insecure transport")
    return issues


def cookie_batch(cookies: Iterable[Any], policy: Mapping[str, Any]) -> dict:
    """Apply a policy to a list of cookies and summarize the decisions."""
    results: list[dict] = []
    carried_attrs: dict[str, Any] = {}

    for item in cookies:
        cookie = parse_cookie(item) if isinstance(item, str) else dict(item)
        if carried_attrs:
            merged_attrs = dict(carried_attrs)
            merged_attrs.update(cookie.get("attrs", {}))
            cookie = {
                "name": cookie.get("name", ""),
                "value": cookie.get("value", ""),
                "attrs": merged_attrs,
            }

        result = enforce(cookie, policy)
        results.append(result)
        carried_attrs.update(cookie.get("attrs", {}))

    accepted = sum(1 for result in results if result["accepted"])
    return {
        "results": results,
        "accepted": accepted,
        "rejected": len(results) - accepted,
    }