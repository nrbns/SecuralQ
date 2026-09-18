"""Data governance foundations for privacy frameworks (DPDP, GDPR, ISO 27701).

Endpoint agents cannot invent legal purpose/consent/processor context. This
package stores human/integration-declared inventory that continuous control
tests and gap analysis can evidence against.

Not a determination of legal compliance.
"""

from __future__ import annotations

from app.data_governance.service import (
    ensure_schema,
    family_posture,
    get_org_privacy_profile,
    list_data_elements,
    list_data_flows,
    list_processors,
    list_processing_activities,
    list_principal_requests,
    list_retention_policies,
    set_org_privacy_profile,
    upsert_data_element,
    upsert_data_flow,
    upsert_processor,
    upsert_processing_activity,
    upsert_principal_request,
    upsert_retention_policy,
)

__all__ = [
    "ensure_schema",
    "family_posture",
    "get_org_privacy_profile",
    "list_data_elements",
    "list_data_flows",
    "list_processors",
    "list_processing_activities",
    "list_principal_requests",
    "list_retention_policies",
    "set_org_privacy_profile",
    "upsert_data_element",
    "upsert_data_flow",
    "upsert_processor",
    "upsert_processing_activity",
    "upsert_principal_request",
    "upsert_retention_policy",
]
