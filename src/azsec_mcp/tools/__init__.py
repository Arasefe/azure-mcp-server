"""Domain tool modules. Each exposes register(server); register_all wires them in."""

from .. import resources
from ..server import SecureServer
from . import defender, entra_logs, identity, intune, purview, sentinel


def register_all(server: SecureServer) -> None:
    for module in (identity, intune, defender, sentinel, purview, entra_logs):
        module.register(server)
    resources.register(server.mcp)
