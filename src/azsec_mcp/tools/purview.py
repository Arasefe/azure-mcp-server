"""Purview tools: sensitivity labels, DLP and insider risk alerts, eDiscovery, retention events."""

from typing import Any

from ..http import Api
from ..ids import Guid, UserRef, seg
from ..policy import Tier
from ..server import SecureServer

CASES = "/v1.0/security/cases/ediscoveryCases"


def register(s: SecureServer) -> None:
    async def list_all(path: str, **params: str) -> list[dict[str, Any]]:
        return await s.http.paginate(Api.GRAPH, path, params=params or None)

    def labels_path(user: str) -> str:
        return f"/beta/users/{seg(user)}/security/informationProtection/sensitivityLabels"

    # ── Information protection ──────────────────────────────────────────────

    @s.tool("list_sensitivity_labels", Tier.READ)
    async def list_sensitivity_labels(user: UserRef) -> list[dict[str, Any]]:
        """List the sensitivity labels published to a user (Graph beta)."""
        return await list_all(labels_path(user))

    @s.tool("get_sensitivity_label", Tier.READ)
    async def get_sensitivity_label(user: UserRef, label_id: Guid) -> dict[str, Any]:
        """Get one sensitivity label as published to a user (Graph beta)."""
        return await s.http.request("GET", Api.GRAPH, f"{labels_path(user)}/{seg(label_id)}")

    @s.tool("list_sensitive_info_types", Tier.READ)
    async def list_sensitive_info_types() -> list[dict[str, Any]]:
        """List Purview sensitive information types (Graph beta)."""
        return await list_all("/beta/security/informationProtection/sensitiveTypes")

    # ── Alerts ──────────────────────────────────────────────────────────────

    @s.tool("list_dlp_alerts", Tier.READ)
    async def list_dlp_alerts() -> list[dict[str, Any]]:
        """List Purview Data Loss Prevention alerts (Graph security alerts_v2)."""
        return await list_all(
            "/v1.0/security/alerts_v2", **{"$filter": "serviceSource eq 'dataLossPrevention'"}
        )

    @s.tool("list_insider_risk_alerts", Tier.READ)
    async def list_insider_risk_alerts() -> list[dict[str, Any]]:
        """List Purview Insider Risk Management alerts (Graph beta alerts_v2)."""
        return await list_all(
            "/beta/security/alerts_v2",
            **{"$filter": "serviceSource eq 'microsoftInsiderRiskManagement'"},
        )

    # ── eDiscovery ──────────────────────────────────────────────────────────

    @s.tool("list_ediscovery_cases", Tier.READ)
    async def list_ediscovery_cases() -> list[dict[str, Any]]:
        """List Purview eDiscovery cases."""
        return await list_all(CASES)

    @s.tool("get_ediscovery_case", Tier.READ)
    async def get_ediscovery_case(case_id: Guid) -> dict[str, Any]:
        """Get one Purview eDiscovery case."""
        return await s.http.request("GET", Api.GRAPH, f"{CASES}/{seg(case_id)}")

    @s.tool("list_ediscovery_custodians", Tier.READ)
    async def list_ediscovery_custodians(case_id: Guid) -> list[dict[str, Any]]:
        """List the custodians in an eDiscovery case."""
        return await list_all(f"{CASES}/{seg(case_id)}/custodians")

    @s.tool("list_ediscovery_holds", Tier.READ)
    async def list_ediscovery_holds(case_id: Guid) -> list[dict[str, Any]]:
        """List the legal holds in an eDiscovery case."""
        return await list_all(f"{CASES}/{seg(case_id)}/legalHolds")

    @s.tool("list_ediscovery_searches", Tier.READ)
    async def list_ediscovery_searches(case_id: Guid) -> list[dict[str, Any]]:
        """List the searches in an eDiscovery case."""
        return await list_all(f"{CASES}/{seg(case_id)}/searches")

    @s.tool("list_ediscovery_review_sets", Tier.READ)
    async def list_ediscovery_review_sets(case_id: Guid) -> list[dict[str, Any]]:
        """List the review sets in an eDiscovery case."""
        return await list_all(f"{CASES}/{seg(case_id)}/reviewSets")

    # ── Records management ──────────────────────────────────────────────────

    @s.tool("list_retention_event_types", Tier.READ)
    async def list_retention_event_types() -> list[dict[str, Any]]:
        """List Purview retention event types (application permission supported)."""
        return await list_all("/v1.0/security/triggerTypes/retentionEventTypes")
