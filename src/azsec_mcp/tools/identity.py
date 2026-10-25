"""Identity and access tools: resource groups, Azure RBAC (with PIM), Entra users, admin units."""

import re
import secrets
import uuid
from datetime import UTC, datetime
from fnmatch import fnmatchcase
from typing import Annotated, Any

from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field

from ..http import Api, AzureError
from ..ids import (
    ArmName,
    AzureRegion,
    Guid,
    RbacScope,
    RoleName,
    Upn,
    UserRef,
    is_guid,
    odata_str,
    seg,
)
from ..policy import Tier
from ..server import SecureServer

RG_API = "2025-04-01"
RBAC_API = "2022-04-01"
PIM_API = "2020-10-01"

# Microsoft's definition of a privileged administrator role: any of these actions.
# https://learn.microsoft.com/azure/role-based-access-control/role-definitions#privileged-administrator-role-definition
PRIVILEGED_ACTIONS = (
    "*",
    "*/delete",
    "*/write",
    "microsoft.authorization/denyassignments/delete",
    "microsoft.authorization/denyassignments/write",
    "microsoft.authorization/roleassignments/delete",
    "microsoft.authorization/roleassignments/write",
    "microsoft.authorization/roledefinitions/delete",
    "microsoft.authorization/roledefinitions/write",
)

DisplayName = Annotated[str, Field(min_length=1, max_length=256)]
Description = Annotated[str, Field(max_length=1024)]
Justification = Annotated[str, Field(min_length=10, max_length=500)]
EligibilityDays = Annotated[int, Field(ge=1, le=365)]


def is_privileged(definition: dict[str, Any]) -> bool:
    """True if any action in the role (wildcards included) grants a privileged operation."""
    actions = [
        a.lower()
        for p in definition.get("properties", {}).get("permissions", [])
        for a in p.get("actions", [])
    ]
    return any(fnmatchcase(op, act) for op in PRIVILEGED_ACTIONS for act in actions)


def _nickname(upn: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "", upn.split("@", 1)[0]) or "user"


def register(s: SecureServer) -> None:
    sub_path = f"/subscriptions/{seg(s.settings.subscription_id)}"
    authz = "providers/Microsoft.Authorization"

    async def resolve_user(user: str) -> str:
        """Object ID for a UserRef: a GUID passes through, a UPN is looked up."""
        if is_guid(user):
            return user
        found = await s.http.request(
            "GET", Api.GRAPH, f"/v1.0/users/{seg(user)}", params={"$select": "id"}
        )
        return found["id"]

    async def role_definition(role: str, scope: str) -> dict[str, Any]:
        """Role definition by GUID, or by exact display name."""
        base = f"{scope}/{authz}/roleDefinitions"
        if is_guid(role):
            return await s.http.request(
                "GET", Api.ARM, f"{base}/{seg(role)}", params={"api-version": RBAC_API}
            )
        found = await s.http.request(
            "GET",
            Api.ARM,
            base,
            params={"api-version": RBAC_API, "$filter": f"roleName eq '{odata_str(role)}'"},
        )
        if not found.get("value"):
            raise ToolError(f"Role definition not found: {role}")
        return found["value"][0]

    async def display_name(path: str) -> str:
        found = await s.http.request("GET", Api.GRAPH, path, params={"$select": "displayName"})
        return str(found.get("displayName"))

    async def describe_au(args: dict[str, Any]) -> dict[str, str]:
        """Human-readable AU name for the confirmation prompt."""
        au = f"/v1.0/directory/administrativeUnits/{seg(args['au_id'])}"
        return {"administrative unit": await display_name(au)}

    async def describe_au_role(args: dict[str, Any]) -> dict[str, str]:
        """Role and AU names for the confirmation prompt (IDs are shown too)."""
        role = f"/v1.0/roleManagement/directory/roleDefinitions/{seg(args['role_template_id'])}"
        return {"role": await display_name(role), **await describe_au(args)}

    # ── Resource groups ─────────────────────────────────────────────────────

    @s.tool("list_resource_groups", Tier.READ)
    async def list_resource_groups() -> list[dict[str, Any]]:
        """List the resource groups in this server's subscription."""
        groups = await s.http.paginate(
            Api.ARM, f"{sub_path}/resourcegroups", params={"api-version": RG_API}
        )
        return [{"name": g.get("name"), "location": g.get("location")} for g in groups]

    @s.tool("create_resource_group", Tier.WRITE)
    async def create_resource_group(name: ArmName, location: AzureRegion = "eastus") -> dict:
        """Create a new resource group in this server's subscription (refuses existing ones)."""
        path = f"{sub_path}/resourcegroups/{seg(name)}"
        try:
            # "Check existence" (HEAD: 204 exists, 404 not found). A PUT on an existing group
            # is a full replace and would silently drop its tags.
            await s.http.request("HEAD", Api.ARM, path, params={"api-version": RG_API})
        except AzureError as exc:
            if exc.status != 404:
                raise
        else:
            raise ToolError(f"Resource group {name} already exists; not modified")
        created = await s.http.request(
            "PUT", Api.ARM, path, params={"api-version": RG_API}, json={"location": location}
        )
        return {"name": created.get("name"), "location": created.get("location")}

    @s.tool("delete_resource_group", Tier.DESTRUCTIVE, retype=("name",))
    async def delete_resource_group(name: ArmName) -> dict:
        """Delete a resource group and everything in it. Returns once Azure accepts the deletion."""
        await s.http.request(
            "DELETE",
            Api.ARM,
            f"{sub_path}/resourcegroups/{seg(name)}",
            params={"api-version": RG_API},
        )
        return {"name": name, "status": "Deletion accepted; it continues in the background."}

    # ── Azure RBAC and PIM ──────────────────────────────────────────────────

    @s.tool(
        "assign_role",
        Tier.DESTRUCTIVE,
        retype=("role", "assignee"),
        show=("scope", "eligibility_days", "justification"),
    )
    async def assign_role(
        assignee: UserRef,
        role: RoleName | Guid,
        scope: RbacScope,
        justification: Justification,
        eligibility_days: EligibilityDays = 30,
    ) -> dict:
        """Assign an Azure RBAC role in this subscription to a user.

        Privileged administrator roles (Owner, Contributor, User Access Administrator, RBAC
        Administrator, or any role that can write role assignments) become a time-bound PIM
        eligible assignment that the user activates in PIM; PIM cannot make service principals
        eligible. Other roles are assigned active.
        """
        if scope.lower() != sub_path.lower() and not scope.lower().startswith(
            sub_path.lower() + "/"
        ):
            raise ToolError("scope must be inside this server's subscription")
        definition = await role_definition(role, scope)
        principal = await resolve_user(assignee)
        request_id = str(uuid.uuid4())
        summary = {
            "role": definition.get("properties", {}).get("roleName"),
            "principalId": principal,
            "scope": scope,
        }

        if is_privileged(definition):
            await s.http.request(
                "PUT",
                Api.ARM,
                f"{scope}/{authz}/roleEligibilityScheduleRequests/{request_id}",
                params={"api-version": PIM_API},
                json={
                    "properties": {
                        "principalId": principal,
                        "roleDefinitionId": definition["id"],
                        "requestType": "AdminAssign",
                        "justification": justification,
                        "scheduleInfo": {
                            "startDateTime": datetime.now(UTC).isoformat(),
                            "expiration": {
                                "type": "AfterDuration",
                                "duration": f"P{eligibility_days}D",
                            },
                        },
                    }
                },
            )
            return {
                "assignment": "eligible (PIM)",
                **summary,
                "expires_in_days": eligibility_days,
                "next_step": "The user activates the role in Entra ID > PIM > My roles "
                "(MFA/justification per PIM policy).",
            }

        await s.http.request(
            "PUT",
            Api.ARM,
            f"{scope}/{authz}/roleAssignments/{request_id}",
            params={"api-version": RBAC_API},
            json={
                "properties": {
                    "roleDefinitionId": definition["id"],
                    "principalId": principal,
                    "description": justification,
                }
            },
        )
        return {"assignment": "active", **summary, "roleAssignmentId": request_id}

    @s.tool("list_role_assignments", Tier.READ)
    async def list_role_assignments(assignee: UserRef) -> list[dict[str, Any]]:
        """List active Azure RBAC role assignments for a user in this subscription."""
        principal = await resolve_user(assignee)
        return await s.http.paginate(
            Api.ARM,
            f"{sub_path}/{authz}/roleAssignments",
            params={"api-version": RBAC_API, "$filter": f"principalId eq '{principal}'"},
        )

    @s.tool("list_role_eligibilities", Tier.READ)
    async def list_role_eligibilities() -> list[dict[str, Any]]:
        """List PIM eligible Azure role assignments at or above this server's subscription."""
        items = await s.http.paginate(
            Api.ARM,
            f"{sub_path}/{authz}/roleEligibilityScheduleInstances",
            params={"api-version": PIM_API, "$filter": "atScope()"},
        )
        rows = []
        for item in items:
            props = item.get("properties", {})
            expanded = props.get("expandedProperties", {})
            rows.append(
                {
                    "principal": expanded.get("principal", {}).get("displayName"),
                    "principalId": props.get("principalId"),
                    "role": expanded.get("roleDefinition", {}).get("displayName"),
                    "scope": props.get("scope"),
                    "start": props.get("startDateTime"),
                    "end": props.get("endDateTime"),
                    "status": props.get("status"),
                }
            )
        return rows

    # ── Entra users ─────────────────────────────────────────────────────────

    @s.tool("list_users", Tier.READ)
    async def list_users() -> list[dict[str, Any]]:
        """List Entra ID users (id, name, UPN, mail, enabled)."""
        return await s.http.paginate(
            Api.GRAPH,
            "/v1.0/users",
            params={
                "$select": "id,displayName,userPrincipalName,mail,accountEnabled",
                "$top": "999",
            },
        )

    @s.tool("list_graph_users", Tier.READ)
    async def list_graph_users() -> list[dict[str, Any]]:
        """List Entra ID users (name and UPN only)."""
        return await s.http.paginate(
            Api.GRAPH,
            "/v1.0/users",
            params={"$select": "displayName,userPrincipalName", "$top": "999"},
        )

    @s.tool("create_user", Tier.WRITE)
    async def create_user(upn: Upn, display_name: DisplayName) -> dict:
        """Create an Entra ID member user. The initial password is random and never revealed."""
        initial = secrets.token_urlsafe(24) + "aA1!"  # 32+ chars covering all 4 classes
        created = await s.http.request(
            "POST",
            Api.GRAPH,
            "/v1.0/users",
            json={
                "accountEnabled": True,
                "displayName": display_name,
                "userPrincipalName": upn,
                "mailNickname": _nickname(upn),
                "usageLocation": "US",
                "passwordProfile": {"password": initial, "forceChangePasswordNextSignIn": True},
            },
        )
        return {
            "id": created.get("id"),
            "upn": upn,
            "next_step": "Onboard the user with a Temporary Access Pass or an admin password "
            "reset; the initial password was never shown.",
        }

    @s.tool("delete_user", Tier.DESTRUCTIVE, retype=("user",))
    async def delete_user(user: UserRef) -> dict:
        """Delete an Entra ID user (soft delete; restorable for 30 days)."""
        await s.http.request("DELETE", Api.GRAPH, f"/v1.0/users/{seg(user)}")
        return {"user": user, "status": "deleted"}

    # ── Administrative units ────────────────────────────────────────────────

    @s.tool("list_aus", Tier.READ)
    async def list_aus() -> list[dict[str, Any]]:
        """List Entra ID administrative units."""
        return await s.http.paginate(
            Api.GRAPH,
            "/v1.0/directory/administrativeUnits",
            params={"$select": "id,displayName"},
        )

    @s.tool("create_au", Tier.WRITE)
    async def create_au(display_name: DisplayName, description: Description = "") -> dict:
        """Create an Entra ID administrative unit."""
        payload = {"displayName": display_name}
        if description:
            payload["description"] = description
        created = await s.http.request(
            "POST", Api.GRAPH, "/v1.0/directory/administrativeUnits", json=payload
        )
        return {"id": created.get("id"), "displayName": created.get("displayName")}

    @s.tool(
        "assign_au_role",
        Tier.DESTRUCTIVE,
        retype=("user",),
        show=("au_id", "role_template_id", "eligibility_days", "justification"),
        describe=describe_au_role,
    )
    async def assign_au_role(
        au_id: Guid,
        user: UserRef,
        role_template_id: Guid,
        justification: Justification,
        eligibility_days: EligibilityDays = 30,
    ) -> dict:
        """Make a user PIM-eligible for an Entra role scoped to one administrative unit.

        Every role that can be scoped to an AU is an admin role, so all of them go through
        PIM as a time-bound eligible assignment that the user activates in PIM.
        """
        principal = await resolve_user(user)
        created = await s.http.request(
            "POST",
            Api.GRAPH,
            "/v1.0/roleManagement/directory/roleEligibilityScheduleRequests",
            json={
                "action": "adminAssign",
                "justification": justification,
                "roleDefinitionId": role_template_id,
                "directoryScopeId": f"/administrativeUnits/{au_id}",
                "principalId": principal,
                "scheduleInfo": {
                    "startDateTime": datetime.now(UTC).isoformat(),
                    "expiration": {"type": "afterDuration", "duration": f"P{eligibility_days}D"},
                },
            },
        )
        return {
            "assignment": "eligible (PIM)",
            "requestId": created.get("id"),
            "status": created.get("status"),
            "principalId": principal,
            "auId": au_id,
            "expires_in_days": eligibility_days,
            "next_step": "The user activates the role in Entra ID > PIM > My roles.",
        }

    @s.tool(
        "add_au_member",
        Tier.DESTRUCTIVE,
        retype=("user",),
        show=("au_id",),
        describe=describe_au,
    )
    async def add_au_member(au_id: Guid, user: UserRef) -> dict:
        """Add a user to an administrative unit, placing them under that AU's scoped admins."""
        principal = await resolve_user(user)
        await s.http.request(
            "POST",
            Api.GRAPH,
            f"/v1.0/directory/administrativeUnits/{seg(au_id)}/members/$ref",
            json={"@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{principal}"},
        )
        return {"auId": au_id, "principalId": principal, "status": "added"}
