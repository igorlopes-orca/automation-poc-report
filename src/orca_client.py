from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import httpx

SERVING_LAYER_PATH = "/api/serving-layer/query"
COMPLIANCE_FRAMEWORKS_PATH = "/api/serving-layer/compliance/frameworks/overview"


# The full set of standard alert categories. Used by slide-9 query 1
# ("any alert" filter, equivalent to leaving Category unfiltered in the
# UI). Kept explicit because the curl the SE captured included the list
# verbatim.
ALERT_CATEGORIES_ALL: list[str] = [
    "Authentication",
    "Best practices",
    "Data at risk",
    "Data protection",
    "IAM misconfigurations",
    "Lateral movement",
    "Logging and monitoring",
    "Malicious activity",
    "Malware",
    "Neglected assets",
    "Network misconfigurations",
    "Source code vulnerabilities",
    "Suspicious activity",
    "System integrity",
    "Vendor services misconfigurations",
    "Vulnerabilities",
    "Workload misconfigurations",
]


# Cloud-identity-related serving-layer models. Slide 7 metrics filter
# across all of them at once because "an identity" can be a user, role,
# group, policy, or service principal in any cloud. Treat as opaque.
IDENTITY_MODELS: list[str] = [
    "AliCloudRamPolicy",
    "AliCloudResourceGroup",
    "AliCloudResourcePolicy",
    "AwsIamAccountSummary",
    "AwsIamInstanceProfile",
    "AwsIamManagedPolicy",
    "AwsIamPasswordPolicy",
    "AwsIamPolicy",
    "AwsPermissionBoundary",
    "AwsResourcePolicy",
    "AwsScp",
    "AwsSsoPermissionSet",
    "AwsWorkSpaceDirectory",
    "AzureConditionalAccessPolicy",
    "AzureExternalAppRoleAssignment",
    "AzureTenantRoleAssignment",
    "AzureTenantRoleDefinition",
    "AzurePolicyAssignment",
    "AzurePolicyDefinition",
    "AzureIamRoleAssignment",
    "AzureIamRoleDefinition",
    "AzureResourceLock",
    "AzureUserSettings",
    "GcpAccessApprovalSettings",
    "GcpIamPolicy",
    "GcpIamPolicyBindingRecommendation",
    "GcpIamRole",
    "GcpOrganizationPolicy",
    "GcpOrganizationPolicyRule",
    "OciAuthenticationPolicy",
    "OciIamPolicy",
    "TencentCloudCamPolicy",
    "TencentCloudResourcePolicy",
    "AliCloudRamRole",
    "AwsIamRole",
    "AzureServicePrincipal",
    "GcpIamServiceAccount",
    "OciIamDynamicGroup",
    "TencentCloudCamRole",
    "AliCloudRamGroup",
    "AliCloudUser",
    "AwsUser",
    "AwsIamGroup",
    "AwsSsoGroup",
    "AwsSsoUser",
    "AzureGroup",
    "AzurePrincipal",
    "AzureUser",
    "GcpGroup",
    "GcpUser",
    "LinodeUser",
    "OciIamGroup",
    "OciUser",
    "TencentCloudCamGroup",
    "TencentCloudUser",
    "User",
]


@dataclass
class VulnerabilityMetrics:
    total: int
    critical_with_fix: int
    high_with_fix: int
    exposed_crit_high: int
    exposed_crit_high_sensitive: int

    def as_dict(self) -> dict[str, int]:
        return {
            "total": self.total,
            "critical_with_fix": self.critical_with_fix,
            "high_with_fix": self.high_with_fix,
            "exposed_crit_high": self.exposed_crit_high,
            "exposed_crit_high_sensitive": self.exposed_crit_high_sensitive,
        }


@dataclass
class AssetMetrics:
    malware: int
    critical_exposed: int
    critical: int
    high_exposed: int
    high: int

    def as_dict(self) -> dict[str, int]:
        return {
            "malware": self.malware,
            "critical_exposed": self.critical_exposed,
            "critical": self.critical,
            "high_exposed": self.high_exposed,
            "high": self.high,
        }


@dataclass
class IamMetrics:
    permissive_identities: int
    attack_path_identities: int

    def as_dict(self) -> dict[str, int]:
        return {
            "permissive_identities": self.permissive_identities,
            "attack_path_identities": self.attack_path_identities,
        }


@dataclass
class FrameworkScore:
    display_name: str
    avg_score_percent: int


@dataclass
class ComplianceMetrics:
    total_count: int
    frameworks: list[FrameworkScore]


@dataclass
class AppSecMetrics:
    critical_alerts: int
    repos_with_critical: int
    high_alerts: int
    repos_with_high: int
    sensitive_crit_high_alerts: int
    repos_with_sensitive_crit_high: int
    repos_with_deployed_assets: int

    def as_dict(self) -> dict[str, int]:
        return {
            "critical_alerts": self.critical_alerts,
            "repos_with_critical": self.repos_with_critical,
            "high_alerts": self.high_alerts,
            "repos_with_high": self.repos_with_high,
            "sensitive_crit_high_alerts": self.sensitive_crit_high_alerts,
            "repos_with_sensitive_crit_high": self.repos_with_sensitive_crit_high,
            "repos_with_deployed_assets": self.repos_with_deployed_assets,
        }


@dataclass
class FindingsMetrics:
    crit_high_exposed_sensitive: int
    dspm_crit_high: int
    validated_sensitive_data: int
    high_impact_attack_paths: int
    malware_crit_high: int

    def as_dict(self) -> dict[str, int]:
        return {
            "crit_high_exposed_sensitive": self.crit_high_exposed_sensitive,
            "dspm_crit_high": self.dspm_crit_high,
            "validated_sensitive_data": self.validated_sensitive_data,
            "high_impact_attack_paths": self.high_impact_attack_paths,
            "malware_crit_high": self.malware_crit_high,
        }


class OrcaClient:
    def __init__(
        self,
        api_token: str | None = None,
        base_url: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        token = api_token or os.environ.get("ORCA_API_TOKEN")
        if not token:
            raise RuntimeError("ORCA_API_TOKEN is not set")
        self._token = token
        self._base_url = (base_url or os.environ.get("ORCA_BASE_URL") or "https://api.orcasecurity.io").rstrip("/")
        self._client = httpx.Client(
            timeout=timeout,
            headers={
                "authorization": f"TOKEN {self._token}",
                "accept": "application/json, text/plain, */*",
                "content-type": "application/json",
            },
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "OrcaClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---------- Low-level HTTP plumbing ----------

    def _post(self, path: str, body: dict) -> dict:
        response = self._client.post(self._base_url + path, json=body)
        response.raise_for_status()
        return response.json()

    def _get(self, path: str, params: dict | None = None) -> dict:
        response = self._client.get(self._base_url + path, params=params)
        response.raise_for_status()
        return response.json()

    # ---------- Serving-layer count primitive ----------

    def count(
        self,
        models: str | list[str],
        with_filter: dict | None = None,
        *,
        order_by: list[str] | None = None,
    ) -> int:
        """POST a serving-layer query with limit=1 and return total_items.

        We request one row because the endpoint requires
        ``get_results_and_count`` to be paired with at least one result
        row — we discard the row. ``order_by`` defaults to unset because
        the choice of sort column depends on the model; it doesn't affect
        the count. ``models`` may be a single model name or a list — some
        Orca queries (e.g. identities) span dozens of underlying models.
        """
        model_list = [models] if isinstance(models, str) else list(models)
        query: dict[str, Any] = {"models": model_list, "type": "object_set"}
        if with_filter is not None:
            query["with"] = with_filter
        body = {
            "query": query,
            "limit": 1,
            "start_at_index": 0,
            "order_by[]": order_by or [],
            "select": [],
            "get_results_and_count": True,
            "full_graph_fetch": {"enabled": True},
            "debug_enable_bu_tags": True,
            "max_tier": 2,
        }
        payload = self._post(SERVING_LAYER_PATH, body)
        if "total_items" not in payload:
            raise RuntimeError(f"Unexpected serving-layer response: missing total_items. Body: {payload!r}")
        return int(payload["total_items"])

    # ---------- Slide 5: Vulnerability Mgmt ----------

    def get_vulnerability_metrics(self) -> VulnerabilityMetrics:
        crit_or_high = _in("CvssSeverity", ["CRITICAL", "HIGH"])

        exposed_asset = _has("Inventory", _eq("IsInternetFacing", True, type_="bool"))
        exposed_asset_with_sensitive_data = _has(
            "Inventory",
            _and(
                _eq("IsInternetFacing", True, type_="bool"),
                _has_any("SensitiveData"),
            ),
        )

        return VulnerabilityMetrics(
            total=self.count("VulnerabilityV2", order_by=["-CvssScore"]),
            critical_with_fix=self.count(
                "VulnerabilityV2",
                _and(_in("PatchAvailable", ["Yes"]), _in("CvssSeverity", ["CRITICAL"])),
            ),
            high_with_fix=self.count(
                "VulnerabilityV2",
                _and(_in("PatchAvailable", ["Yes"]), _in("CvssSeverity", ["HIGH"])),
            ),
            exposed_crit_high=self.count(
                "VulnerabilityV2",
                _and(exposed_asset, crit_or_high),
            ),
            exposed_crit_high_sensitive=self.count(
                "VulnerabilityV2",
                _and(exposed_asset_with_sensitive_data, crit_or_high),
            ),
        )

    # ---------- Slide 6: Asset Discovery ----------

    def get_asset_metrics(self) -> AssetMetrics:
        exposed = _eq("IsInternetFacing", True, type_="bool")
        return AssetMetrics(
            malware=self.count(
                "Inventory", _eq("HasMalwareWithHighConfidence", True, type_="bool")
            ),
            critical_exposed=self.count("Inventory", _and(_has_alert("critical"), exposed)),
            critical=self.count("Inventory", _has_alert("critical")),
            high_exposed=self.count("Inventory", _and(_has_alert("high"), exposed)),
            high=self.count("Inventory", _has_alert("high")),
        )

    # ---------- Slide 7: Identity & Access ----------

    def get_identity_metrics(self) -> IamMetrics:
        return IamMetrics(
            permissive_identities=self.count(
                IDENTITY_MODELS,
                _eq("IsPermissive", True, type_="bool"),
                order_by=["-OrcaScore"],
            ),
            attack_path_identities=self.count(
                IDENTITY_MODELS,
                _has_any("AttackPathInventories"),
                order_by=["-OrcaScore"],
            ),
        )

    # ---------- Slide 9: Top Findings ----------

    def get_findings_metrics(self) -> FindingsMetrics:
        open_status = _in("Status", ["open", "in_progress"])
        crit_high = _in("RiskLevel", ["critical", "high"])

        exposed_with_sensitive = _has(
            "Inventory",
            _and(
                _in("Exposure", ["public_facing", "internet_facing", "trusted_access"]),
                _has_any("SensitiveData"),
            ),
            key="Inventories",
            set_=True,
        )

        return FindingsMetrics(
            crit_high_exposed_sensitive=self.count(
                "Alert",
                _and(
                    _in("Category", ALERT_CATEGORIES_ALL),
                    open_status,
                    exposed_with_sensitive,
                    crit_high,
                ),
            ),
            dspm_crit_high=self.count(
                "Alert",
                _and(
                    _in("Category", ["Data protection", "Data at risk"]),
                    open_status,
                    crit_high,
                ),
            ),
            validated_sensitive_data=self.count(
                "SensitiveData",
                _in("ActiveVerificationStatus", ["secret_verified"]),
            ),
            high_impact_attack_paths=self.count(
                "AttackPathInventories",
                _has("AttackPath", _in("ImpactValue", ["High"])),
            ),
            malware_crit_high=self.count(
                "Alert",
                _and(
                    _in("Category", ["Malware"]),
                    open_status,
                    crit_high,
                ),
            ),
        )

    # ---------- Slide 10: AppSec ----------

    def get_appsec_metrics(self) -> AppSecMetrics:
        # AppSec alerts are tagged with the ``source:shiftleft`` label.
        # Slide bullets split by RiskLevel: bullet 1 = critical only,
        # bullet 2 = high only, bullet 3 = crit+high in data-protection
        # categories.
        def appsec_open(risk_levels: list[str]) -> dict:
            return _and(
                _any_match("Labels", _in("Labels", ["source:shiftleft"])),
                _in("Status", ["open", "in_progress"]),
                _in("RiskLevel", risk_levels),
            )

        appsec_critical = appsec_open(["critical"])
        appsec_high = appsec_open(["high"])
        appsec_sensitive_open_crit_high = _and(
            appsec_open(["critical", "high"]),
            _in("Category", ["Data at risk", "Data protection"]),
        )
        return AppSecMetrics(
            critical_alerts=self.count("Alert", appsec_critical),
            repos_with_critical=self.count(
                "Inventory",
                _has("Alert", appsec_critical, key="Alerts", set_=True),
            ),
            high_alerts=self.count("Alert", appsec_high),
            repos_with_high=self.count(
                "Inventory",
                _has("Alert", appsec_high, key="Alerts", set_=True),
            ),
            sensitive_crit_high_alerts=self.count("Alert", appsec_sensitive_open_crit_high),
            repos_with_sensitive_crit_high=self.count(
                "Inventory",
                _has("Alert", appsec_sensitive_open_crit_high, key="Alerts", set_=True),
            ),
            repos_with_deployed_assets=self.count(
                "CodeRepository",
                _any_match("Observations", _in("Observations", ["deployed_assets"])),
                order_by=["-OrcaScore"],
            ),
        )

    # ---------- Slide 8: Compliance ----------

    def get_compliance_metrics(self) -> ComplianceMetrics:
        payload = self._post(COMPLIANCE_FRAMEWORKS_PATH, {})
        data = payload.get("data", {})
        return ComplianceMetrics(
            total_count=int(data.get("total_count", 0)),
            frameworks=[
                FrameworkScore(
                    display_name=fw.get("display_name", ""),
                    avg_score_percent=int(fw.get("avg_score_percent", 0)),
                )
                for fw in data.get("frameworks", [])
            ],
        )


# ---------- Filter DSL helpers ----------

def _in(key: str, values: list) -> dict:
    return {"key": key, "values": values, "type": "str", "operator": "in"}


def _eq(key: str, value, *, type_: str = "str") -> dict:
    return {"key": key, "values": [value], "type": type_, "operator": "eq"}


def _and(*clauses: dict) -> dict:
    return {"operator": "and", "type": "operation", "values": list(clauses)}


def _any_match(key: str, sub_filter: dict) -> dict:
    """List-membership filter: at least one element of ``key`` matches ``sub_filter``."""
    return {
        "key": key,
        "values": [sub_filter],
        "type": "list",
        "operator": "any_match",
    }


def _has(
    model: str,
    with_filter: dict | None = None,
    *,
    key: str | None = None,
    set_: bool = False,
) -> dict:
    """Relationship filter.

    Args:
        model: related model name (e.g. ``Inventory``, ``Alert``).
        with_filter: optional sub-filter on the related records.
        key: relationship key as seen on the parent model. Defaults to
            ``model``. Use when the parent exposes the relation under a
            different name — e.g. Inventory exposes its alerts as
            ``Alerts`` while the related model is ``Alert``.
        set_: True for one-to-many (``type=object_set``), False for
            one-to-one (``type=object``).
    """
    result: dict = {
        "keys": [key or model],
        "models": [model],
        "type": "object_set" if set_ else "object",
        "operator": "has",
    }
    if with_filter is not None:
        result["with"] = with_filter
    return result


def _has_any(model: str, *, key: str | None = None) -> dict:
    """Shortcut for 'has at least one related <model>', no sub-filter."""
    return _has(model, key=key, set_=True)


def _has_alert(risk_level: str) -> dict:
    """Common pattern: an asset with an open/in-progress alert at the given risk level."""
    return _has(
        "Alert",
        _and(
            _in("Status", ["open", "in_progress"]),
            _in("RiskLevel", [risk_level]),
        ),
        key="Alerts",
        set_=True,
    )
