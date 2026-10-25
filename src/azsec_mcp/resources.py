"""azsec://capability-gaps: what this server deliberately does not do, and where to do it instead.

These replace the JS server's stub tools that answered every call with "not available".
A resource costs the model nothing until it chooses to read it.
"""

import json

from mcp.server import MCPServer

_PURVIEW = "Microsoft Purview portal"

CAPABILITY_GAPS: dict[str, dict[str, str]] = {
    "list_dlp_policies": {
        "reason": "Microsoft Graph has no admin API for DLP policies.",
        "alternative": f"{_PURVIEW} > Data loss prevention, or Get-DlpCompliancePolicy "
        "(Security & Compliance PowerShell). DLP alerts are available: list_dlp_alerts.",
        "docsUrl": "https://learn.microsoft.com/purview/dlp-learn-about-dlp",
    },
    "list_insider_risk_policies": {
        "reason": "Microsoft Graph exposes Insider Risk alerts, not its policies.",
        "alternative": f"{_PURVIEW} > Insider Risk Management, or Get-InsiderRiskPolicy.",
        "docsUrl": "https://learn.microsoft.com/purview/insider-risk-management-policies",
    },
    "list_information_barrier_policies": {
        "reason": "Information barrier policies are not available through Microsoft Graph.",
        "alternative": "Get-InformationBarrierPolicy (Security & Compliance PowerShell).",
        "docsUrl": "https://learn.microsoft.com/purview/information-barriers-policies",
    },
    "list_information_barrier_segments": {
        "reason": "Information barrier segments are not available through Microsoft Graph.",
        "alternative": "Get-OrganizationSegment (Security & Compliance PowerShell).",
        "docsUrl": "https://learn.microsoft.com/purview/information-barriers-policies",
    },
    "list_retention_labels": {
        "reason": "GET /security/labels/retentionLabels supports delegated permissions only; "
        "this server signs in app-only, so the call would always return 403.",
        "alternative": f"{_PURVIEW} > Data lifecycle management > Retention labels. "
        "Retention event types are available: list_retention_event_types.",
        "docsUrl": "https://learn.microsoft.com/graph/api/security-labelsroot-list-retentionlabel",
    },
    "list_communication_compliance_policies": {
        "reason": "Communication Compliance policies are not available through Microsoft Graph.",
        "alternative": f"{_PURVIEW} > Communication compliance, or Get-SupervisoryReviewPolicyV2.",
        "docsUrl": "https://learn.microsoft.com/purview/communication-compliance-solution-overview",
    },
    "list_compliance_assessments": {
        "reason": "Compliance Manager assessments are not available through Microsoft Graph.",
        "alternative": f"{_PURVIEW} > Compliance Manager > Assessments.",
        "docsUrl": "https://learn.microsoft.com/purview/compliance-manager",
    },
    "get_compliance_assessment": {
        "reason": "Compliance Manager assessments are not available through Microsoft Graph.",
        "alternative": f"{_PURVIEW} > Compliance Manager > Assessments.",
        "docsUrl": "https://learn.microsoft.com/purview/compliance-manager",
    },
    "list_compliance_improvement_actions": {
        "reason": "Compliance Manager improvement actions are not available through Graph.",
        "alternative": f"{_PURVIEW} > Compliance Manager > Improvement actions.",
        "docsUrl": "https://learn.microsoft.com/purview/compliance-manager",
    },
    "list_sensitive_info_types": {
        "reason": "No Graph endpoint lists sensitive information types: the JS server's "
        "/beta/security/informationProtection/sensitiveTypes returned 400 (segment not found) "
        "against Cavalry77 on 2026-10-24.",
        "alternative": f"{_PURVIEW} > Data classification > Sensitive info types, or "
        "Get-DlpSensitiveInformationType (Security & Compliance PowerShell).",
        "docsUrl": "https://learn.microsoft.com/purview/sit-sensitive-information-type-learn-about",
    },
    "list_label_policies": {
        "reason": "Sensitivity label policies have no app-only Graph API. The JS tool of this "
        "name only re-listed labels, which list_sensitivity_labels already does.",
        "alternative": f"{_PURVIEW} > Information protection > Label policies, or "
        "Get-LabelPolicy (Security & Compliance PowerShell).",
        "docsUrl": "https://learn.microsoft.com/purview/create-sensitivity-labels",
    },
    "get_dspm_insights": {
        "reason": "Data Security Posture Management has no general Graph API for its insights. "
        "The JS tool of this name only re-listed sensitivity labels.",
        "alternative": f"{_PURVIEW} > Data Security Posture Management.",
        "docsUrl": "https://learn.microsoft.com/purview/data-security-posture-management",
    },
}


def register(mcp: MCPServer) -> None:
    @mcp.resource("azsec://capability-gaps", mime_type="application/json")
    def capability_gaps() -> str:
        """Capabilities this server deliberately omits, why, and where to do them instead."""
        return json.dumps(CAPABILITY_GAPS, indent=1)
