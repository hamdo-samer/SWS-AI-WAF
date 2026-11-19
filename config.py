"""Central application configuration."""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None


PROJECT_ROOT = Path(__file__).resolve().parent
if load_dotenv is not None:
    load_dotenv(PROJECT_ROOT / ".env")


def env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError as error:
        raise RuntimeError(f"{name} must be an integer.") from error


@dataclass(frozen=True)
class Settings:
    secret_key: str
    dashboard_host: str
    dashboard_port: int
    proxy_host: str
    proxy_port: int
    backend_url: str
    database_url: str
    admin_username: str
    admin_password: str
    admin_password_hash: str
    trusted_proxy_cidrs: tuple[str, ...]
    csrf_enabled: bool

    @classmethod
    def from_env(cls) -> "Settings":
        secret = os.getenv("SECRET_KEY", "").strip()
        if not secret:
            secret = "development-only-" + secrets.token_hex(32)
        return cls(
            secret_key=secret,
            dashboard_host=os.getenv("DASHBOARD_HOST", "127.0.0.1").strip(),
            dashboard_port=env_int("DASHBOARD_PORT", 5000),
            proxy_host=os.getenv("PROXY_HOST", "127.0.0.1").strip(),
            proxy_port=env_int("PROXY_PORT", 8081),
            backend_url=os.getenv("BACKEND_URL", "http://127.0.0.1:8080").rstrip("/"),
            database_url=os.getenv(
                "DATABASE_URL",
                str(PROJECT_ROOT / "instance" / "firewall.sqlite3"),
            ).strip(),
            admin_username=os.getenv("ADMIN_USERNAME", "admin").strip(),
            admin_password=os.getenv("ADMIN_PASSWORD", "").strip(),
            admin_password_hash=os.getenv("ADMIN_PASSWORD_HASH", "").strip(),
            trusted_proxy_cidrs=tuple(
                item.strip()
                for item in os.getenv(
                    "TRUSTED_PROXY_CIDRS",
                    "127.0.0.1/32,::1/128",
                ).split(",")
                if item.strip()
            ),
            csrf_enabled=os.getenv("CSRF_ENABLED", "true").strip().lower()
            in {"1", "true", "yes", "on"},
        )
