from __future__ import annotations

from pathlib import Path

import chromadb
from chromadb.config import Settings as ChromaSettings

from app.config import settings
from app.paths import resource_root

KNOWLEDGE_DIR = resource_root() / "data" / "knowledge"


def rag_where_for_org(org_id: str | None) -> dict | None:
    """Chroma metadata filter: global knowledge + optional tenant corpus.

    Global docs use metadata scope=global (shipped knowledge).
    Tenant docs must set org_id on upsert. Without a filter, older DBs that
    lack scope still return everything (backward compatible).
    """
    if not org_id:
        return None
    return {
        "$or": [
            {"scope": {"$eq": "global"}},
            {"org_id": {"$eq": str(org_id)}},
        ]
    }


def assert_no_cross_tenant_hit(chunks: list[dict], org_id: str) -> None:
    """Raise if any chunk metadata belongs to a different org (test helper / audit)."""
    for c in chunks:
        meta = c.get("meta") or {}
        other = meta.get("org_id")
        if other and str(other) != str(org_id):
            raise PermissionError(f"cross-tenant RAG hit: org={other} asked={org_id}")


class RAGEngine:
    def __init__(self) -> None:
        self._embedder = None
        self._client: chromadb.PersistentClient | None = None
        self._collection = None
        self._cached_count: int = 0

    def _ensure_client(self) -> None:
        if self._client is None:
            persist = Path(settings.chroma_persist_dir)
            persist.mkdir(parents=True, exist_ok=True)
            self._client = chromadb.PersistentClient(
                path=str(persist),
                settings=ChromaSettings(anonymized_telemetry=False),
            )
        if self._collection is None:
            assert self._client is not None
            self._collection = self._client.get_or_create_collection(
                name="pentest_knowledge",
                metadata={"hnsw:space": "cosine"},
            )

    def _ensure_ready(self) -> None:
        self._ensure_client()
        if self._embedder is None:
            from sentence_transformers import SentenceTransformer

            self._embedder = SentenceTransformer(settings.embedding_model)

    def _knowledge_files(self, root: Path) -> list[Path]:
        files: list[Path] = []
        for path in sorted(root.glob("**/*")):
            if path.suffix.lower() in {".md", ".txt", ".json"} and path.is_file():
                files.append(path)
        return files

    def ingest_directory(self, directory: Path | None = None, force: bool = False) -> int:
        root = directory or KNOWLEDGE_DIR
        if not root.exists():
            return 0

        self._ensure_client()
        assert self._collection is not None
        files = self._knowledge_files(root)
        if not files:
            return 0

        # Fast path: already indexed — skip embedding model load on startup
        if not force:
            existing = self._collection.count()
            if existing >= len(files) and existing > 0:
                self._cached_count = existing
                return 0

        self._ensure_ready()
        docs: list[str] = []
        ids: list[str] = []
        metas: list[dict] = []

        for path in files:
            text = path.read_text(encoding="utf-8")
            if not text.strip():
                continue
            docs.append(text)
            ids.append(path.stem)
            metas.append({"source": str(path.relative_to(root)), "scope": "global"})

        if not docs:
            return 0

        assert self._embedder is not None
        embeddings = self._embedder.encode(docs, show_progress_bar=False).tolist()
        self._collection.upsert(ids=ids, documents=docs, embeddings=embeddings, metadatas=metas)
        self._cached_count = len(docs)
        return len(docs)

    def document_count(self) -> int:
        if self._cached_count:
            return self._cached_count
        try:
            self._ensure_client()
            if self._collection is None:
                return 0
            count = self._collection.count()
            self._cached_count = count
            return count
        except Exception:
            return 0

    def list_sources(self) -> list[str]:
        self._ensure_client()
        assert self._collection is not None
        if self._collection.count() == 0:
            return []
        result = self._collection.get(include=["metadatas"])
        metas = result.get("metadatas") or []
        return sorted({m.get("source", "") for m in metas if m.get("source")})

    def query(self, question: str, top_k: int = 3, org_id: str | None = None) -> list[str]:
        return [r["text"] for r in self.query_with_sources(question, top_k=top_k, org_id=org_id)]

    def query_with_sources(
        self, question: str, top_k: int = 3, *, org_id: str | None = None
    ) -> list[dict]:
        """Like query(), but keeps the source filename + a similarity score per
        chunk instead of throwing them away — this is what the citations UI /
        confidence indicators need. Previously `query()` discarded chroma's
        metadatas/distances entirely, which is why no citation ever made it
        past this layer.

        When org_id is set, only global knowledge + that org's docs are returned.
        """
        self._ensure_ready()
        assert self._embedder is not None
        assert self._collection is not None

        if self._collection.count() == 0:
            self.ingest_directory(force=True)

        if self._collection.count() == 0:
            return []

        embedding = self._embedder.encode([question], show_progress_bar=False).tolist()
        kwargs: dict = {
            "query_embeddings": embedding,
            "n_results": min(top_k, self._collection.count()),
            "include": ["documents", "metadatas", "distances"],
        }
        where = rag_where_for_org(org_id)
        if where is not None:
            kwargs["where"] = where
        try:
            results = self._collection.query(**kwargs)
        except Exception:
            # Older collections without scope metadata — fall back unfiltered
            if where is not None:
                results = self._collection.query(
                    query_embeddings=embedding,
                    n_results=min(top_k, self._collection.count()),
                    include=["documents", "metadatas", "distances"],
                )
            else:
                raise
        documents = results.get("documents", [[]])[0]
        metadatas = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]

        out = []
        for i, doc in enumerate(documents):
            if not doc:
                continue
            meta = metadatas[i] if i < len(metadatas) else {}
            dist = distances[i] if i < len(distances) else None
            # Cosine distance -> similarity in [0, 1]; clamp for safety since
            # this is an approximate confidence signal, not a calibrated one.
            score = max(0.0, min(1.0, 1.0 - dist)) if isinstance(dist, (int, float)) else None
            # Soft drop foreign-tenant docs if filter was unavailable
            if org_id and (meta or {}).get("org_id") and str(meta.get("org_id")) != str(org_id):
                continue
            out.append(
                {
                    "text": doc,
                    "source": (meta or {}).get("source", "unknown"),
                    "score": round(score, 3) if score is not None else None,
                    "meta": dict(meta or {}),
                }
            )
        return out

    def build_context(
        self, question: str, top_k: int = 3, *, org_id: str | None = None
    ) -> tuple[str, list[dict]]:
        """Returns (context_text_for_the_model, sources_for_the_ui).

        Each retrieved chunk is tagged with a [S1]/[S2]/... marker in the
        context text and the model is instructed to cite them, so a citation
        the model emits can be matched back to `sources` by index.
        """
        chunks = self.query_with_sources(question, top_k=top_k, org_id=org_id)
        if not chunks:
            return "", []

        parts = []
        sources = []
        for i, c in enumerate(chunks, start=1):
            pct = f"{round(c['score'] * 100)}%" if c["score"] is not None else "n/a"
            parts.append(f"[S{i}] (source: {c['source']}, relevance: {pct})\n{c['text']}")
            sources.append({"id": f"S{i}", "source": c["source"], "relevance": c["score"]})

        joined = "\n\n---\n\n".join(parts)
        context = (
            "## Retrieved security knowledge\n"
            "Cite these using their [S1]/[S2]/... tags inline when you use them; "
            "don't present retrieved content as certain if its relevance score is low.\n\n"
            f"{joined}"
        )
        return context, sources


rag_engine = RAGEngine()