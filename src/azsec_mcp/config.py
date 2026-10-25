"""Server settings, loaded once at startup from .env and the environment."""

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import dotenv_values

REPO_ROOT = Path(__file__).resolve().parents[2]  # src/azsec_mcp/config.py -> repo root

REQUIRED = (
    "AZURE_TENANT_ID",
    "AZURE_CLIENT_ID",
    "AZURE_SUBSCRIPTION_ID",
    "SENTINEL_RESOURCE_GROUP",
    "SENTINEL_WORKSPACE_NAME",
)


@dataclass(frozen=True)
class Settings:
    # Identifiers, not secrets, but kept out of repr() so they never land in
    # an error message or tool result that the model reads.
    tenant_id: str = field(repr=False)
    client_id: str = field(repr=False)
    subscription_id: str = field(repr=False)
    sentinel_rg: str
    sentinel_workspace: str
    cert_path: Path
    max_tier: str
    audit_path: Path


def load_settings(env: Mapping[str, str] | None = None) -> Settings:
    """Build Settings from `env`, or from the process environment overlaid with .env.

    .env wins over the shell so the server always runs with the repo's own
    config (same rule as the JS server, commit 2c445f3).
    """
    if env is None:
        file_values = {k: v for k, v in dotenv_values(REPO_ROOT / ".env").items() if v is not None}
        env = {**os.environ, **file_values}

    missing = [name for name in REQUIRED if not env.get(name)]
    if missing:
        raise ValueError(f"Missing required settings: {', '.join(missing)}")

    return Settings(
        tenant_id=env["AZURE_TENANT_ID"],
        client_id=env["AZURE_CLIENT_ID"],
        subscription_id=env["AZURE_SUBSCRIPTION_ID"],
        sentinel_rg=env["SENTINEL_RESOURCE_GROUP"],
        sentinel_workspace=env["SENTINEL_WORKSPACE_NAME"],
        cert_path=Path(
            env.get("AZURE_CLIENT_CERTIFICATE_PATH", REPO_ROOT / "cavalry-sp.combined.pem")
        ),
        max_tier=env.get("MCP_MAX_TIER", "read"),
        audit_path=Path(env.get("MCP_AUDIT_PATH", REPO_ROOT / "audit.log")),
    )
