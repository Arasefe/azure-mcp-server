"""Domain tool modules. Each exposes register(server); register_all wires them in."""

from ..server import SecureServer
from . import defender, identity, intune


def register_all(server: SecureServer) -> None:
    identity.register(server)
    intune.register(server)
    defender.register(server)
