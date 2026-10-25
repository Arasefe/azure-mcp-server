"""Intune tools: managed devices and their remote actions, policies, apps, Autopilot, scripts."""

from typing import Any

from ..http import Api
from ..ids import Guid, seg
from ..policy import Tier
from ..server import SecureServer

DEVICES = "/v1.0/deviceManagement/managedDevices"
DEVICE_LIST_FIELDS = (
    "id,deviceName,complianceState,operatingSystem,userPrincipalName,lastSyncDateTime"
)
# Security-relevant fields only: no IMEI, phone number, MAC addresses or carrier data.
DEVICE_FIELDS = (
    "id,deviceName,operatingSystem,osVersion,complianceState,managementState,isEncrypted,"
    "jailBroken,userPrincipalName,enrolledDateTime,lastSyncDateTime,serialNumber,"
    "azureADDeviceId,managedDeviceOwnerType,deviceEnrollmentType"
)


def register(s: SecureServer) -> None:
    async def list_all(path: str, select: str | None = None, **params: str) -> list[dict[str, Any]]:
        if select:
            params["$select"] = select
        return await s.http.paginate(Api.GRAPH, path, params=params or None)

    async def device_action(device_id: str, action: str, body: dict[str, Any] | None = None):
        await s.http.request("POST", Api.GRAPH, f"{DEVICES}/{seg(device_id)}/{action}", json=body)

    async def describe_device(args: dict[str, Any]) -> dict[str, str]:
        """Which physical device this is, for the confirmation prompt."""
        d = await s.http.request(
            "GET",
            Api.GRAPH,
            f"{DEVICES}/{seg(args['device_id'])}",
            params={
                "$select": "deviceName,operatingSystem,osVersion,userPrincipalName,serialNumber"
            },
        )
        return {
            "device": f"{d.get('deviceName')} ({d.get('operatingSystem')} {d.get('osVersion')})",
            "user": str(d.get("userPrincipalName")),
            "serial": str(d.get("serialNumber")),
        }

    # ── Managed devices ─────────────────────────────────────────────────────

    @s.tool("list_intune_devices", Tier.READ)
    async def list_intune_devices() -> list[dict[str, Any]]:
        """List Intune managed devices."""
        return await list_all(DEVICES, DEVICE_LIST_FIELDS)

    @s.tool("list_noncompliant_devices", Tier.READ)
    async def list_noncompliant_devices() -> list[dict[str, Any]]:
        """List Intune devices whose compliance state is noncompliant."""
        return await list_all(
            DEVICES, DEVICE_LIST_FIELDS, **{"$filter": "complianceState eq 'noncompliant'"}
        )

    @s.tool("get_intune_device", Tier.READ)
    async def get_intune_device(device_id: Guid) -> dict[str, Any]:
        """Get the security-relevant details of one Intune managed device."""
        return await s.http.request(
            "GET", Api.GRAPH, f"{DEVICES}/{seg(device_id)}", params={"$select": DEVICE_FIELDS}
        )

    @s.tool("sync_intune_device", Tier.WRITE)
    async def sync_intune_device(device_id: Guid) -> dict[str, Any]:
        """Ask an Intune device to check in now."""
        await device_action(device_id, "syncDevice")
        return {"device_id": device_id, "status": "Sync requested."}

    @s.tool("reboot_intune_device", Tier.WRITE)
    async def reboot_intune_device(device_id: Guid) -> dict[str, Any]:
        """Restart an Intune device at its next check-in (unsaved work on it is lost)."""
        await device_action(device_id, "rebootNow")
        return {"device_id": device_id, "status": "Reboot requested."}

    @s.tool(
        "retire_intune_device",
        Tier.DESTRUCTIVE,
        retype=("device_id",),
        describe=describe_device,
    )
    async def retire_intune_device(device_id: Guid) -> dict[str, Any]:
        """Retire a device: remove company data and unenroll it, keeping personal data.

        Intune allows at most 1,000 retire actions per tenant per day.
        """
        await device_action(device_id, "retire")
        return {"device_id": device_id, "status": "Retire requested; runs at next check-in."}

    @s.tool(
        "wipe_intune_device",
        Tier.DESTRUCTIVE,
        retype=("device_id",),
        show=("keep_user_data", "keep_enrollment_data"),
        describe=describe_device,
    )
    async def wipe_intune_device(
        device_id: Guid, keep_user_data: bool = False, keep_enrollment_data: bool = False
    ) -> dict[str, Any]:
        """Factory-reset an Intune device.

        Macs that need a recovery PIN must be wiped from the Intune portal: the PIN is a
        secret and is deliberately not accepted through this tool.
        """
        await device_action(
            device_id,
            "wipe",
            {"keepUserData": keep_user_data, "keepEnrollmentData": keep_enrollment_data},
        )
        return {"device_id": device_id, "status": "Wipe requested; runs at next check-in."}

    # ── Policies and configuration ──────────────────────────────────────────

    @s.tool("list_intune_compliance_policies", Tier.READ)
    async def list_intune_compliance_policies() -> list[dict[str, Any]]:
        """List Intune device compliance policies."""
        return await list_all(
            "/v1.0/deviceManagement/deviceCompliancePolicies",
            "id,displayName,description,createdDateTime,lastModifiedDateTime",
        )

    @s.tool("list_intune_configuration_profiles", Tier.READ)
    async def list_intune_configuration_profiles() -> list[dict[str, Any]]:
        """List Intune device configuration profiles."""
        return await list_all(
            "/v1.0/deviceManagement/deviceConfigurations",
            "id,displayName,description,createdDateTime,lastModifiedDateTime",
        )

    @s.tool("list_intune_enrollment_configurations", Tier.READ)
    async def list_intune_enrollment_configurations() -> list[dict[str, Any]]:
        """List Intune enrollment configurations and restrictions."""
        return await list_all(
            "/v1.0/deviceManagement/deviceEnrollmentConfigurations",
            "id,displayName,description,priority,createdDateTime,lastModifiedDateTime",
        )

    # ── Apps ────────────────────────────────────────────────────────────────

    @s.tool("list_intune_apps", Tier.READ)
    async def list_intune_apps() -> list[dict[str, Any]]:
        """List Intune managed apps (Win32, store, LOB)."""
        return await list_all(
            "/v1.0/deviceAppManagement/mobileApps",
            "id,displayName,publisher,publishingState,createdDateTime,lastModifiedDateTime",
        )

    @s.tool("list_intune_app_assignments", Tier.READ)
    async def list_intune_app_assignments(app_id: Guid) -> list[dict[str, Any]]:
        """List the group assignments of one Intune app."""
        return await list_all(f"/v1.0/deviceAppManagement/mobileApps/{seg(app_id)}/assignments")

    @s.tool("list_intune_managed_app_policies", Tier.READ)
    async def list_intune_managed_app_policies() -> list[dict[str, Any]]:
        """List Intune app protection (MAM) policies."""
        return await list_all(
            "/v1.0/deviceAppManagement/managedAppPolicies",
            "id,displayName,description,createdDateTime,lastModifiedDateTime",
        )

    # ── Autopilot and scripts ───────────────────────────────────────────────

    @s.tool("list_intune_autopilot_devices", Tier.READ)
    async def list_intune_autopilot_devices() -> list[dict[str, Any]]:
        """List Windows Autopilot device identities."""
        return await list_all(
            "/v1.0/deviceManagement/windowsAutopilotDeviceIdentities",
            "id,serialNumber,model,manufacturer,enrollmentState,azureAdDeviceId",
        )

    @s.tool("list_intune_scripts", Tier.READ)
    async def list_intune_scripts() -> list[dict[str, Any]]:
        """List Intune platform scripts (PowerShell/shell). Graph beta: no v1.0 API exists."""
        return await list_all(
            "/beta/deviceManagement/deviceManagementScripts",
            "id,displayName,description,runAsAccount,createdDateTime,lastModifiedDateTime",
        )

    @s.tool("list_intune_remediation_scripts", Tier.READ)
    async def list_intune_remediation_scripts() -> list[dict[str, Any]]:
        """List Intune remediation (device health) scripts. Graph beta: no v1.0 API exists."""
        return await list_all(
            "/beta/deviceManagement/deviceHealthScripts",
            "id,displayName,description,publisher,runAsAccount,createdDateTime,lastModifiedDateTime",
        )
