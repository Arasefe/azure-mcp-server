"""SecureServer: the one decorator every tool goes through.

Per call: SDK validates args -> tier check -> [destructive: human confirmation]
-> run -> audit -> wrap as untrusted data. A tool cannot be registered without a tier.
"""

import inspect
from collections.abc import Awaitable, Callable
from typing import Any

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from .audit import AuditLog
from .config import Settings
from .confirm import Describe, confirmation_param, confirmed, expected_text
from .http import AzureError, AzureHttp
from .policy import Tier, authorize, parse_tier
from .untrusted import wrap

ToolFn = Callable[..., Awaitable[Any]]


class SecureServer:
    def __init__(self, settings: Settings, http: AzureHttp, audit: AuditLog) -> None:
        self.settings = settings
        self.http = http
        self._audit = audit
        self._max_tier = parse_tier(settings.max_tier)  # a typo stops startup
        self.mcp = MCPServer("azsec-mcp")

    def _record(
        self, name: str, tier: Tier, decision: str, args: dict[str, Any], **extra: Any
    ) -> None:
        self._audit.append(
            {"tool": name, "tier": tier.name.lower(), "decision": decision, "args": args, **extra}
        )

    def _gate(self, name: str, tier: Tier, args: dict[str, Any]) -> None:
        decision = authorize(tier, self._max_tier)
        if not decision.allowed:
            self._record(name, tier, "denied", args, reason=decision.reason)
            raise ToolError(decision.reason)

    def tool(
        self,
        name: str,
        tier: Tier,
        *,
        retype: tuple[str, ...] = (),
        show: tuple[str, ...] = (),
        describe: Describe | None = None,
    ) -> Callable[[ToolFn], ToolFn]:
        """Register `fn` as MCP tool `name` behind every control.

        Destructive tools must name the arguments the operator retypes (`retype`), may
        show more arguments read-only (`show`), and may add looked-up names (`describe`).
        """
        if (tier is Tier.DESTRUCTIVE) != bool(retype) or (not retype and (show or describe)):
            raise ValueError(
                f"{name}: destructive tools need retype=(...); other tiers must not confirm"
            )

        def decorator(fn: ToolFn) -> ToolFn:
            async def wrapper(**kwargs: Any) -> str:
                answer = kwargs.pop("confirm", None)
                self._gate(name, tier, kwargs)
                if retype:
                    ok, why = confirmed(answer, expected_text(kwargs, retype))
                    if not ok:
                        self._record(name, tier, "declined", kwargs, reason=why)
                        raise ToolError(f"Not executed: {why}")
                try:
                    result = await fn(**kwargs)
                except ToolError as exc:
                    # A deliberate refusal written by this server: trusted text, passed through.
                    self._record(name, tier, "allowed", kwargs, outcome="refused", reason=str(exc))
                    raise
                except AzureError as exc:
                    # Azure error text can echo attacker-set values, so it is enveloped too.
                    self._record(name, tier, "allowed", kwargs, outcome="error", error=str(exc))
                    error = {"status": exc.status, "code": exc.code, "message": exc.message}
                    raise ToolError(wrap(error, name)) from exc
                except Exception as exc:
                    detail = f"{type(exc).__name__}: {exc}"[:500]
                    self._record(name, tier, "allowed", kwargs, outcome="error", error=detail)
                    raise ToolError("Internal error; details are in the audit log") from exc
                self._record(name, tier, "allowed", kwargs, outcome="ok")
                return wrap(result, name)

            # Expose fn's own parameters (plus the hidden confirm) so the SDK builds the
            # schema and validates arguments exactly as if fn were registered directly.
            params = list(inspect.signature(fn).parameters.values())
            if retype:

                def gate(args: dict[str, Any]) -> None:
                    self._gate(name, tier, args)

                params.append(
                    inspect.Parameter(
                        "confirm",
                        inspect.Parameter.KEYWORD_ONLY,
                        annotation=confirmation_param(name, retype, show, gate, describe),
                    )
                )
            # The SDK reads parameters via inspect.signature() but finds resolvers via
            # typing.get_type_hints(), which reads __annotations__: both must agree, or
            # `confirm` would surface as an argument the model is asked to supply.
            wrapper.__signature__ = inspect.Signature(params, return_annotation=str)  # type: ignore[attr-defined]
            wrapper.__annotations__ = {p.name: p.annotation for p in params} | {"return": str}
            wrapper.__name__, wrapper.__doc__ = fn.__name__, fn.__doc__
            self.mcp.tool(
                name=name,
                description=fn.__doc__,
                annotations=ToolAnnotations(
                    read_only_hint=tier is Tier.READ, destructive_hint=tier is Tier.DESTRUCTIVE
                ),
                structured_output=False,
            )(wrapper)
            return fn

        return decorator


def build_server(settings: Settings, http: AzureHttp, audit: AuditLog) -> SecureServer:
    return SecureServer(settings, http, audit)
