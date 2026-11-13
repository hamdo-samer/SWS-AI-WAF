"""Shared request-text formatting for model training and inference."""

from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit


_HTTP_VERSION_SUFFIX = re.compile(r"\s+HTTP/\d(?:\.\d)?$", re.IGNORECASE)


def normalize_request_url(url: str) -> str:
    if not isinstance(url, str):
        raise TypeError("The request URL must be a string.")

    request_target = _HTTP_VERSION_SUFFIX.sub("", url.strip())
    parsed = urlsplit(request_target)
    if parsed.scheme or parsed.netloc:
        return urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    return request_target


def format_request_text(
    method: str,
    url: str,
    query: str = "",
) -> str:
    if not all(isinstance(value, str) for value in (method, url, query)):
        raise TypeError("Request features must be strings.")

    url = normalize_request_url(url)
    query = query.strip()
    if query:
        url += ("&" if "?" in url else "?") + query

    return "\n".join(
        f"{name}: {value.strip()}"
        for name, value in (
            ("Method", method),
            ("URL", url),
        )
        if value.strip()
    )
