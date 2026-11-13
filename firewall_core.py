"""SWS."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote, unquote_plus


@dataclass(frozen=True)
class Inspection:
    score: int
    decision: str
    reasons: tuple[str, ...]


_SIGNALS = (
    (re.compile(r"<\s*script\b", re.IGNORECASE), 55, "Betik etiketi göstergesi"),
    (re.compile(r"\b(?:union\s+select|sleep\s*\(|benchmark\s*\()", re.IGNORECASE), 65, "Sorgu manipülasyonu göstergesi"),
    (
        re.compile(
            r"(?:'|%27)\s*(?:or|and)\s*(?:'|%27)?\s*\d+(?:'|%27)?\s*=\s*(?:'|%27)?\s*\d+",
            re.IGNORECASE,
        ),
        65,
        "SQL Injection (OR/AND manipülasyonu)",
    ),
    (re.compile(r"(?:--|#|/\*)", re.IGNORECASE), 40, "SQL yorum (comment) göstergesi"),
    (
        re.compile(
            r"(?:;|&&|\|\|)\s*(?:cat|curl|wget|bash|sh|nc|python|powershell|whoami|id)\b",
            re.IGNORECASE,
        ),
        65,
        "Komut enjeksiyonu göstergesi",
    ),
    (re.compile(r"(?:\.\./|%2e%2e|%2f%2e)", re.IGNORECASE), 60, "Yol geçişi göstergesi"),
)
_ALLOWED_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
_MAX_FIELD_LENGTH = 4096
_MAX_BODY_LENGTH = 1024 * 1024


def _decode_for_inspection(value: str, *, plus_as_space: bool = False) -> str:
    decoded = unquote_plus(value) if plus_as_space else unquote(value)
    for _ in range(4):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    return decoded


def inspect_request(
    path: str,
    method: str,
    query: str = "",
    user_agent: str = "",
    body: str = "",
    body_content_type: str = "",
) -> Inspection:
    """Score user-supplied request metadata without sending it over the network."""
    fields = (path, method, query, user_agent, body, body_content_type)
    if any(not isinstance(value, str) for value in fields):
        raise TypeError("İstek alanları metin olmalıdır.")
    if any(len(value) > _MAX_FIELD_LENGTH for value in (path, method, query, user_agent)):
        raise ValueError("Her alan en fazla 4096 karakter olabilir.")
    if len(body) > _MAX_BODY_LENGTH:
        raise ValueError("İstek gövdesi en fazla 1048576 karakter olabilir.")

    score = 0
    reasons: list[str] = []
    normalized_method = method.strip().upper()
    normalized_path = _decode_for_inspection(path)
    normalized_query = _decode_for_inspection(query, plus_as_space=True)
    is_form_body = body_content_type.split(";", 1)[0].strip().lower() == (
        "application/x-www-form-urlencoded"
    )
    normalized_body = _decode_for_inspection(body, plus_as_space=is_form_body)
    combined = f"{normalized_path}\n{normalized_query}\n{normalized_body}"

    if not path.strip().startswith("/"):
        score += 15
        reasons.append("İstek yolu / ile başlamıyor")
    if normalized_method not in _ALLOWED_METHODS:
        score += 25
        reasons.append("Alışılmadık HTTP yöntemi")
    if not user_agent.strip():
        score += 10
        reasons.append("Tarayıcı bilgisi bulunamadı")
    if len(path) > 512:
        score += 20
        reasons.append("İstek yolu beklenenden uzun")
    if len(query) > 1024:
        score += 15
        reasons.append("Sorgu alanı beklenenden uzun")

    for pattern, weight, description in _SIGNALS:
        if pattern.search(combined):
            score += weight
            reasons.append(description)

    score = min(score, 100)
    if not reasons:
        reasons.append("Belirgin risk göstergesi bulunamadı")

    return Inspection(
        score=score,
        decision="Engellendi" if score >= 50 else "İzin verildi",
        reasons=tuple(reasons),
    )
