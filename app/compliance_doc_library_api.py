"""API: compliance document library — templates, authoring, review/approve.

Approving a document is the one endpoint here with a real side effect: it
writes the document to disk as a real file and creates a real evidence_links
row (see app.services.compliance_doc_library.review_document). Everything
else is plain CRUD on an editable draft.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.auth import AuthUser
from app.commercial_api import require_user
from app.services.compliance_doc_library import (
    create_document,
    delete_document,
    get_document,
    list_documents,
    list_templates,
    review_document,
    submit_for_review,
    update_document,
)

router = APIRouter(prefix="/api/compliance/documents", tags=["compliance-documents"])


class SectionIn(BaseModel):
    heading: str
    prompt: str = ""
    content: str = ""


class DocumentCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    template_id: str = "blank"
    control_id: str = ""
    framework_id: str = ""
    owner: str = ""


class DocumentUpdate(BaseModel):
    title: str | None = None
    control_id: str | None = None
    framework_id: str | None = None
    owner: str | None = None
    sections: list[SectionIn] | None = None


class ReviewDecision(BaseModel):
    decision: str = Field(pattern="^(approve|reject)$")
    reviewer: str = ""
    comments: str = ""


@router.get("/templates")
async def get_templates(user: Annotated[AuthUser, Depends(require_user)]):
    return {"templates": list_templates()}


@router.get("")
async def get_documents(
    user: Annotated[AuthUser, Depends(require_user)],
    control_id: str | None = None,
    status: str | None = None,
):
    return {"documents": list_documents(user.id, control_id=control_id, status=status)}


@router.post("")
async def post_document(req: DocumentCreate, user: Annotated[AuthUser, Depends(require_user)]):
    return create_document(
        user.id,
        title=req.title,
        template_id=req.template_id,
        control_id=req.control_id,
        framework_id=req.framework_id,
        owner=req.owner,
    )


@router.get("/{doc_id}")
async def get_one_document(doc_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    doc = get_document(user.id, doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Not found")
    return doc


@router.patch("/{doc_id}")
async def patch_document(
    doc_id: str, req: DocumentUpdate, user: Annotated[AuthUser, Depends(require_user)]
):
    fields: dict[str, Any] = req.model_dump(exclude_none=True)
    if "sections" in fields:
        fields["sections"] = [s if isinstance(s, dict) else s for s in fields["sections"]]
    doc = update_document(user.id, doc_id, fields)
    if not doc:
        raise HTTPException(status_code=404, detail="Not found")
    return doc


@router.delete("/{doc_id}")
async def delete_one_document(doc_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    if not delete_document(user.id, doc_id):
        raise HTTPException(status_code=404, detail="Not found")
    return {"ok": True}


@router.post("/{doc_id}/submit")
async def post_submit(doc_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    doc = submit_for_review(user.id, doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Not found")
    return doc


@router.post("/{doc_id}/review")
async def post_review(
    doc_id: str, req: ReviewDecision, user: Annotated[AuthUser, Depends(require_user)]
):
    try:
        doc = review_document(
            user.id, doc_id, decision=req.decision, reviewer=req.reviewer, comments=req.comments
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not doc:
        raise HTTPException(status_code=404, detail="Not found")
    return doc
