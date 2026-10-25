"""The only way this server talks to Azure: fixed hosts, encoded relative paths, capped paging.

The bearer token is attached here and nowhere else, and only after the target URL is
checked to be HTTPS on the exact host of the API the token was issued for.
"""

from enum import StrEnum
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx
from anyio import to_thread
from azure.identity import CertificateCredential

from .config import Settings

_MAX_ERROR = 500


class Api(StrEnum):
    GRAPH = "https://graph.microsoft.com"
    ARM = "https://management.azure.com"
    LA = "https://api.loganalytics.io"

    @property
    def scope(self) -> str:
        return f"{self.value}/.default"


class TokenSource(Protocol):
    def get_token(self, *scopes: str) -> Any: ...


class AzureError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(f"{status} {code}: {message}")
        self.status, self.code, self.message = status, code, message


def _is_api_url(url: str, api: Api) -> bool:
    """True only for https on the API's exact host and default port (no userinfo tricks)."""
    target, expected = urlsplit(url), urlsplit(api.value)
    return (
        target.scheme == "https"
        and target.hostname == expected.hostname
        and target.port in (None, 443)
        and target.username is None
    )


def _error(resp: httpx.Response) -> AzureError:
    """Status, code and trimmed message from any error body shape (never raises)."""
    try:
        body = resp.json()
    except ValueError:
        return AzureError(resp.status_code, "Unknown", resp.text[:_MAX_ERROR])
    err = body.get("error") if isinstance(body, dict) else None
    if isinstance(err, dict):
        code, message = str(err.get("code", "Unknown")), str(err.get("message", ""))
    else:
        code, message = "Unknown", str(err if err is not None else body)
    return AzureError(resp.status_code, code, message[:_MAX_ERROR])


class AzureHttp:
    def __init__(self, credential: TokenSource, client: httpx.AsyncClient) -> None:
        self._credential = credential
        self._client = client

    async def request(
        self,
        method: str,
        api: Api,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Call `api` at a relative `path` built from seg() parts."""
        if not path.startswith("/") or "://" in path:
            raise ValueError("path must be relative and built from seg() parts")
        extra = {k: v for k, v in (headers or {}).items() if k.lower() != "authorization"}
        return await self._send(
            method, api, api.value + path, params=params, json=json, extra_headers=extra
        )

    async def paginate(
        self, api: Api, path: str, *, params: dict[str, Any] | None = None, max_items: int = 500
    ) -> list[dict[str, Any]]:
        """Collect `value` items across pages (Graph @odata.nextLink or ARM nextLink)."""
        items: list[dict[str, Any]] = []
        page = await self.request("GET", api, path, params=params)
        while True:
            items.extend(page.get("value", []))
            if len(items) >= max_items:
                return items[:max_items]
            next_link = page.get("@odata.nextLink") or page.get("nextLink")
            if not next_link:
                return items
            page = await self._send("GET", api, next_link)

    async def _send(
        self,
        method: str,
        api: Api,
        url: str,
        extra_headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        if not _is_api_url(url, api):
            host = urlsplit(url).hostname
            raise AzureError(0, "ForeignHost", f"Refused to send a token to {host}")
        token = await to_thread.run_sync(self._credential.get_token, api.scope)
        # The token header is set last so no caller-supplied header can replace it.
        headers = {**(extra_headers or {}), "Authorization": f"Bearer {token.token}"}
        resp = await self._client.request(method, url, headers=headers, **kwargs)
        if resp.status_code >= 400:
            raise _error(resp)
        return resp.json() if resp.content else {}

    async def aclose(self) -> None:
        await self._client.aclose()


def make_http(settings: Settings) -> AzureHttp:
    credential = CertificateCredential(
        settings.tenant_id, settings.client_id, certificate_path=str(settings.cert_path)
    )
    client = httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=10.0), follow_redirects=False)
    return AzureHttp(credential, client)
