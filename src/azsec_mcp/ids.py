"""Validated identifier types and safe URL / OData building blocks.

Every value that reaches a URL path or an OData filter is one of these
types. Patterns are allowlists: they describe a good value, so an unknown
trick (encoded slash, full-width slash, trailing newline) simply fails.
"""

import re
from typing import Annotated
from urllib.parse import quote

from pydantic import StringConstraints

_HEX = "[0-9a-fA-F]"
_GUID_BODY = rf"{_HEX}{{8}}-{_HEX}{{4}}-{_HEX}{{4}}-{_HEX}{{4}}-{_HEX}{{12}}"
_ARM_NAME_BODY = r"[A-Za-z0-9._()-]{0,89}[A-Za-z0-9_()-]"
_GUID_RE = re.compile(_GUID_BODY)

Guid = Annotated[str, StringConstraints(pattern=rf"^{_GUID_BODY}$")]
"""Object / device / incident / case IDs."""

ArmName = Annotated[str, StringConstraints(pattern=rf"^{_ARM_NAME_BODY}$")]
"""Resource group or alert name: ARM's character set, 1-90 chars, not ending in '.'."""

RbacScope = Annotated[
    str,
    StringConstraints(
        pattern=rf"^/subscriptions/{_GUID_BODY}(/(?i:resourcegroups)/{_ARM_NAME_BODY})?$"
    ),
]
"""Azure RBAC scope: a subscription or one resource group in it, nothing else."""

AzureRegion = Annotated[str, StringConstraints(pattern=r"^[a-z0-9]{2,40}$")]
"""Region short name such as eastus or westeurope."""

WatchlistAlias = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{1,64}$")]

Upn = Annotated[
    str, StringConstraints(pattern=r"^[A-Za-z0-9._'+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$")
]
"""Member UPN. Guest UPNs (#EXT#) are not accepted; address guests by object ID."""

UserRef = Guid | Upn
"""A user given either as object ID or as UPN."""

IsoDuration = Annotated[str, StringConstraints(pattern=r"^P(T?[0-9]{1,4}[DHMS]){1,4}$")]
"""KQL timespan such as P1D, PT4H, P1DT12H."""

RoleName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9 ._()-]{1,128}$")]
"""Azure RBAC role display name, e.g. 'Key Vault Secrets User'. No quotes possible."""


def is_guid(value: str) -> bool:
    """True if `value` is exactly a GUID (fullmatch: no leading/trailing extras, no newline)."""
    return _GUID_RE.fullmatch(value) is not None


def seg(value: str) -> str:
    """Percent-encode one URL path segment; '/', '?', '#', '%' can never escape it."""
    if value in ("", ".", ".."):
        raise ValueError(f"Invalid path segment: {value!r}")
    return quote(value, safe="")


def odata_str(value: str) -> str:
    """Escape a value for use inside an OData string literal ('...')."""
    return value.replace("'", "''")
