"""Ingest knowledge files into ChromaDB for RAG."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def main() -> int:
    try:
        from app.rag import rag_engine

        count = rag_engine.ingest_directory()
        print(f"Ingested {count} documents into RAG index.")
        return 0
    except Exception as exc:
        print(f"RAG ingest skipped: {exc}")
        print("The app still starts — use Re-index in the UI when ready.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
