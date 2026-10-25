"""Defender for Cloud tools: alerts, secure score, recommendations."""

import re
from typing import Any, Literal

from ..http import Api
from ..ids import ArmName, AzureRegion, seg
from ..policy import Tier
from ..server import SecureServer

ALERTS_API = "2022-01-01"
SCORE_API = "2020-01-01"
ASSESSMENTS_API = "2025-05-04"

# Alert state changes are POST actions, not a PATCH of the alert.
ALERT_ACTIONS = {
    "Dismissed": "dismiss",
    "Resolved": "resolve",
    "Active": "activate",
    "InProgress": "inProgress",
}
_RG = re.compile(r"/resourceGroups/([^/]+)/", re.IGNORECASE)
_LOCATION = re.compile(r"/locations/([^/]+)/alerts/", re.IGNORECASE)


def _match(pattern: re.Pattern[str], value: str) -> str | None:
    found = pattern.search(value)
    return found.group(1) if found else None


def register(s: SecureServer) -> None:
    sub_path = f"/subscriptions/{seg(s.settings.subscription_id)}"
    security = f"{sub_path}/providers/Microsoft.Security"

    def alert_path(alert_name: str, asc_location: str, resource_group: str | None) -> str:
        base = sub_path + (f"/resourceGroups/{seg(resource_group)}" if resource_group else "")
        return (
            f"{base}/providers/Microsoft.Security/locations/{seg(asc_location)}"
            f"/alerts/{seg(alert_name)}"
        )

    async def describe_alert(args: dict[str, Any]) -> dict[str, str]:
        """Alert title and severity for the confirmation prompt."""
        found = await s.http.request(
            "GET",
            Api.ARM,
            alert_path(args["alert_name"], args["asc_location"], args.get("resource_group")),
            params={"api-version": ALERTS_API},
        )
        props = found.get("properties", {})
        return {"alert": str(props.get("alertDisplayName")), "severity": str(props.get("severity"))}

    @s.tool("list_defender_alerts", Tier.READ)
    async def list_defender_alerts() -> list[dict[str, Any]]:
        """List Defender for Cloud alerts, with the resourceGroup and location an update needs."""
        alerts = await s.http.paginate(
            Api.ARM, f"{security}/alerts", params={"api-version": ALERTS_API}
        )
        rows = []
        for a in alerts:
            props, alert_id = a.get("properties", {}), str(a.get("id", ""))
            rows.append(
                {
                    "name": a.get("name"),
                    "alertDisplayName": props.get("alertDisplayName"),
                    "severity": props.get("severity"),
                    "status": props.get("status"),
                    "alertType": props.get("alertType"),
                    "compromisedEntity": props.get("compromisedEntity"),
                    "timeGeneratedUtc": props.get("timeGeneratedUtc"),
                    "resourceGroup": _match(_RG, alert_id),
                    "location": _match(_LOCATION, alert_id),
                }
            )
        return rows

    @s.tool("get_secure_score", Tier.READ)
    async def get_secure_score() -> list[dict[str, Any]]:
        """Get the classic Defender for Cloud secure score (not the Defender portal score)."""
        return await s.http.paginate(
            Api.ARM, f"{security}/secureScores", params={"api-version": SCORE_API}
        )

    @s.tool("list_defender_recommendations", Tier.READ)
    async def list_defender_recommendations() -> list[dict[str, Any]]:
        """List Defender for Cloud recommendations (security assessments) and their status."""
        items = await s.http.paginate(
            Api.ARM, f"{security}/assessments", params={"api-version": ASSESSMENTS_API}
        )
        rows = []
        for item in items:
            props = item.get("properties", {})
            details = props.get("resourceDetails", {})
            rows.append(
                {
                    "name": item.get("name"),
                    "displayName": props.get("displayName"),
                    "status": props.get("status", {}).get("code"),
                    "resourceId": details.get("Id") or details.get("id"),
                }
            )
        return rows

    @s.tool(
        "update_defender_alert",
        Tier.DESTRUCTIVE,
        retype=("alert_name",),
        show=("status", "resource_group", "asc_location"),
        describe=describe_alert,
    )
    async def update_defender_alert(
        alert_name: ArmName,
        asc_location: AzureRegion,
        status: Literal["Dismissed", "Resolved", "Active", "InProgress"],
        resource_group: ArmName | None = None,
    ) -> dict[str, Any]:
        """Change a Defender for Cloud alert's state. Closing an alert hides it from responders.

        Take asc_location and resource_group from list_defender_alerts; leave resource_group
        empty for subscription-level alerts.
        """
        await s.http.request(
            "POST",
            Api.ARM,
            f"{alert_path(alert_name, asc_location, resource_group)}/{ALERT_ACTIONS[status]}",
            params={"api-version": ALERTS_API},
        )
        return {"alert": alert_name, "status": status}
