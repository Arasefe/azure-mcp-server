"""Domain tool modules. Each exposes register(server); register_all wires them in."""

from ..server import SecureServer
from . import identity


def register_all(server: SecureServer) -> None:
    identity.register(server)
