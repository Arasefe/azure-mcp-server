"""Entry point: `azsec-mcp` (or `python -m azsec_mcp`). Claude Code launches it over stdio."""

from .audit import AuditLog
from .config import load_settings
from .http import make_http
from .server import build_server


def main() -> None:
    settings = load_settings()
    server = build_server(settings, make_http(settings), AuditLog(settings.audit_path))
    server.mcp.run()  # stdio, the SDK default


if __name__ == "__main__":
    main()
