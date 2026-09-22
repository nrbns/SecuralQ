"""USP lab-production surfaces — graph depth, risk narrative, SBOM, vendors, scanners."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field

from app.auth import AuthUser
from app.commercial_api import require_user

router = APIRouter(prefix="/api/usp", tags=["usp-lab"])


@router.get("/status")
async def usp_lab_status(user: Annotated[AuthUser, Depends(require_user)]):
    from app.connectors.vendor_ingest import catalog_status
    from app.sbom import sbom_status
    from app.scanners.product_facades import catalog as scanner_catalog
    from app.security_graph_depth import graph_depth_status
    from app.services.risk_narrative import explain_risk_increase

    return {
        "ok": True,
        "graph": graph_depth_status(user.id),
        "risk_narrative": {
            "lab_production": True,
            "endpoint": "/api/usp/risk/why-increased",
            "sample_direction": explain_risk_increase(user.id).get("direction"),
        },
        "sbom": sbom_status(user.id),
        "vendor_ingest": catalog_status(),
        "product_scanners": scanner_catalog(),
    }


@router.get("/graph/depth")
async def usp_graph_depth(user: Annotated[AuthUser, Depends(require_user)]):
    from app.security_graph_depth import graph_depth_status

    return graph_depth_status(user.id)


@router.get("/risk/why-increased")
async def usp_why_risk_increased(
    user: Annotated[AuthUser, Depends(require_user)],
    use_llm: bool = False,
    limit: int = 8,
):
    from app.services.risk_narrative import explain_risk_increase

    return explain_risk_increase(user.id, limit_findings=limit, use_llm=use_llm)


@router.get("/sbom/status")
async def usp_sbom_status(user: Annotated[AuthUser, Depends(require_user)]):
    from app.sbom import sbom_status

    return sbom_status(user.id)


@router.get("/sbom/export")
async def usp_sbom_export(user: Annotated[AuthUser, Depends(require_user)]):
    from app.sbom import export_sbom_json

    data = export_sbom_json(user.id)
    return Response(
        content=data,
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="securaiq-sbom.cdx.json"'},
    )


@router.get("/vendors")
async def usp_vendors(_user: Annotated[AuthUser, Depends(require_user)]):
    from app.connectors.vendor_ingest import catalog_status

    return catalog_status()


@router.get("/vendors/{vendor}")
async def usp_vendor_one(vendor: str, _user: Annotated[AuthUser, Depends(require_user)]):
    from app.connectors.vendor_ingest import VENDORS, vendor_status

    if vendor.lower() not in VENDORS:
        raise HTTPException(status_code=404, detail="unknown vendor")
    return vendor_status(vendor)


class VendorIngestBody(BaseModel):
    findings: list[dict[str, Any]] = Field(default_factory=list)
    filename: str = "upload.json"


@router.post("/vendors/{vendor}/ingest")
async def usp_vendor_ingest(
    vendor: str,
    body: VendorIngestBody,
    user: Annotated[AuthUser, Depends(require_user)],
):
    from app.connectors.vendor_ingest import VENDORS, ingest_vendor_export

    if vendor.lower() not in VENDORS:
        raise HTTPException(status_code=404, detail="unknown vendor")
    return ingest_vendor_export(
        user.id,
        vendor,
        {"findings": body.findings},
        filename=body.filename,
    )


@router.post("/vendors/{vendor}/ingest-file")
async def usp_vendor_ingest_file(
    vendor: str,
    user: Annotated[AuthUser, Depends(require_user)],
    file: UploadFile = File(...),
):
    import json

    from app.connectors.vendor_ingest import VENDORS, ingest_vendor_export

    if vendor.lower() not in VENDORS:
        raise HTTPException(status_code=404, detail="unknown vendor")
    raw = await file.read()
    try:
        payload = json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"JSON required: {exc}") from exc
    return ingest_vendor_export(
        user.id,
        vendor,
        payload,
        filename=file.filename or "upload.json",
    )


@router.get("/scanners")
async def usp_product_scanners(_user: Annotated[AuthUser, Depends(require_user)]):
    from app.scanners.product_facades import catalog

    return catalog()


@router.get("/scanners/{product_id}")
async def usp_product_scanner_one(
    product_id: str, _user: Annotated[AuthUser, Depends(require_user)]
):
    from app.scanners.product_facades import product_status

    try:
        return product_status(product_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="unknown product scanner") from exc
