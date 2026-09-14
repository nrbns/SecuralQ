"""CMMC "Secure Enclave" architecture type -- a self-reported, engagement-level
classification of what CUI-boundary technology approach an organization uses
(e.g. a hosted VDI, an on-prem RDS farm, an MSP-managed GCC High tenant).

This is a different axis from app.cmmc_scoping, which classifies where a
specific ASSET sits relative to the CUI boundary (cui_asset / SPA / CRMA /
specialized / out_of_scope). This module classifies the architecture pattern
the boundary itself is built on, for a whole engagement -- one setting per
client engagement, not per asset -- and feeds into the generated System
Security Plan's environment-scope section so the document reflects what the
organization actually told SecuraIQ rather than staying silent on it.

The category list is informed by common CUI-enclave technology patterns
discussed in the CMMC practitioner community, but the descriptions below are
SecuraIQ's own vendor-neutral summary of each pattern's tradeoffs -- no
vendor names, no endorsement, and nothing lifted from any external source.

Always a user-entered, self-reported choice, never a computed or verified
fact -- callers must not present it as independently confirmed.
"""

from __future__ import annotations

ENCLAVE_ARCH_ORDER = (
    "secure_file_sharing",
    "single_device",
    "commercial_vdi",
    "commercial_rds_cloud",
    "onprem_rds",
    "msp_gcc_high",
)

ENCLAVE_ARCH_LABELS: dict[str, str] = {
    "": "Not set",
    "secure_file_sharing": "Secure file sharing (document-based CUI flow)",
    "single_device": "Single-device enclave (hardened standalone device)",
    "commercial_vdi": "Commercial VDI enclave (hosted virtual desktop)",
    "commercial_rds_cloud": "Commercial RDS/AMI/VM enclave (cloud-hosted remote desktop/server)",
    "onprem_rds": "On-prem RDS enclave (self-hosted remote desktop servers)",
    "msp_gcc_high": "MSP-managed GCC High enclave (managed Microsoft GCC High tenant)",
}

ENCLAVE_ARCH_DESCRIPTIONS: dict[str, str] = {
    "secure_file_sharing": (
        "CUI moves through a dedicated, access-controlled file-sharing platform rather than "
        "living on general endpoints. On its own this is rarely a complete CMMC enclave -- any "
        "endpoint used to reach the platform is still in scope -- but it can anchor one when "
        "paired with network segmentation. Common for flowing CUI down to subcontractors who "
        "only need to exchange documents."
    ),
    "single_device": (
        "A single hardened device (a laptop, or a locked-down router/firewall pairing) is "
        "designated as the only place CUI is handled. Keeps the assessment boundary very small, "
        "which suits organizations with minimal or occasional CUI handling, but doesn't scale "
        "past a handful of users."
    ),
    "commercial_vdi": (
        "CUI is handled inside a hosted, multi-tenant virtual desktop provided by a commercial "
        "vendor, isolating it from the organization's regular endpoints. A common, relatively "
        "fast path for smaller companies or CUI work that's mostly code- or document-centric; "
        "the organization still depends on the vendor's own FedRAMP posture and shared-"
        "responsibility boundary."
    ),
    "commercial_rds_cloud": (
        "Similar goal to a VDI enclave but built on cloud-hosted remote desktop servers, AMIs, "
        "or VMs the organization configures itself in a commercial cloud, rather than a turnkey "
        "VDI product. Gives more control over the environment at the cost of more configuration "
        "and patching responsibility falling on the organization."
    ),
    "onprem_rds": (
        "The enclave is self-hosted on the organization's own on-premises Remote Desktop "
        "Services servers rather than in a cloud provider. A hybrid approach that avoids "
        "depending on a cloud vendor's FedRAMP inheritance, but shifts availability, redundancy, "
        "and disaster-recovery planning entirely onto the organization -- worth weighing against "
        "FedRAMP Moderate/High cloud alternatives for HA/DR needs."
    ),
    "msp_gcc_high": (
        "A managed service provider operates a Microsoft GCC High tenant on the organization's "
        "behalf, handling most of the day-to-day administration of the CUI boundary. Reduces "
        "in-house administrative burden but makes the MSP's own access controls, staffing, and "
        "contractual commitments part of the organization's assessment story."
    ),
}


def normalize_enclave_architecture(value: str | None) -> str:
    t = (value or "").strip().lower().replace(" ", "_").replace("-", "_")
    if t in ENCLAVE_ARCH_LABELS:
        return t
    return ""


def enclave_architecture_label(value: str | None) -> str:
    return ENCLAVE_ARCH_LABELS.get(normalize_enclave_architecture(value), "Not set")


def enclave_architecture_description(value: str | None) -> str:
    return ENCLAVE_ARCH_DESCRIPTIONS.get(normalize_enclave_architecture(value), "")


def list_enclave_architecture_types() -> list[dict[str, str]]:
    return [
        {"id": c, "label": ENCLAVE_ARCH_LABELS[c], "description": ENCLAVE_ARCH_DESCRIPTIONS[c]}
        for c in ENCLAVE_ARCH_ORDER
    ]
