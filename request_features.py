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

    normalized_url = normalize_request_url(url)
    query = query.strip()
    if query:
        normalized_url += ("&" if "?" in normalized_url else "?") + query

    lowered_url = normalized_url.lower()
    length = len(normalized_url)
    special_chars = sum(
        not character.isalnum()
        and character not in ("/", "?", "=", "&", ".", "_", "-")
        for character in normalized_url
    )
    has_sql_keywords = int(
        re.search(r"\b(?:select|union|or|drop)\b", lowered_url) is not None
    )
    has_script = int("<script>" in lowered_url)
    features = (
        f"LEN:{length // 10} SPEC:{special_chars} "
        f"SQL:{has_sql_keywords} JS:{has_script}"
    )

    return f"Method: {method.strip()}\nURL: {normalized_url}\n{features}"
