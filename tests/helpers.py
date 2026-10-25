"""Shared test helpers (importable because pytest adds tests/ to pythonpath)."""

from types import SimpleNamespace
from typing import Literal

from mcp import types
from mcp.types import CallToolResult, TextContent


class FakeCred:
    """Stands in for CertificateCredential; records the scopes it was asked for."""

    def __init__(self):
        self.scopes: list[str] = []

    def get_token(self, *scopes):
        self.scopes.append(scopes[0])
        return SimpleNamespace(token=f"tok:{scopes[0]}")


def text(result: CallToolResult) -> str:
    """The single text block of a tool result (fails loudly on any other content type)."""
    block = result.content[0]
    assert isinstance(block, TextContent)
    return block.text


def answer(
    retype: str,
    action: Literal["accept", "decline", "cancel"] = "accept",
    asked: list | None = None,
):
    """Elicitation callback standing in for the human at the client."""

    async def callback(context, params):
        if asked is not None:
            asked.append(params.message)
        content = {"confirm": True, "retype_target": retype} if action == "accept" else None
        return types.ElicitResult(action=action, content=content)

    return callback
