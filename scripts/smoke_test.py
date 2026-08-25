"""Smoke test for SecuraIQ API."""

from __future__ import annotations

import argparse
import sys

import httpx


def main() -> int:
    parser = argparse.ArgumentParser(description="SecuraIQ smoke test")
    parser.add_argument(
        "--chat",
        action="store_true",
        help="Send a short chat message (slow on HuggingFace CPU)",
    )
    parser.add_argument("--base", default="http://localhost:8080", help="Server base URL")
    args = parser.parse_args()

    base = args.base.rstrip("/")
    with httpx.Client(timeout=60.0) as client:
        health = client.get(f"{base}/api/health").json()
        backend = client.get(f"{base}/api/backend").json()
        status = client.get(f"{base}/api/status").json()
        settings = client.get(f"{base}/api/settings").json()
        try:
            platform = client.get(f"{base}/api/platform").json()
        except Exception as exc:
            print(f"WARN /api/platform slow or unavailable: {exc}")
            platform = {}

    print("health:", health)
    print("backend:", backend)
    print("rag_documents:", status.get("rag_documents"))
    print("settings_keys:", sorted(settings.keys())[:8], "...")
    print("platform:", platform.get("os"), platform.get("lan_urls"))
    proto = health.get("prototype") or {}
    if proto:
        print("prototype:", proto.get("hint") or proto.get("data_persists"))
    rt = health.get("realtime_bus") or {}
    if rt:
        print("realtime:", rt.get("mode"), "subscribers=", rt.get("local_subscribers"))

    if health.get("status") != "ok":
        return 1
    if not health.get("backend"):
        return 1
    options = backend.get("options") or []
    for required in (
        "ollama",
        "openai_compat",
        "hermes",
        "unsloth",
        "huggingface",
        "huggingface_api",
    ):
        if required not in options:
            print(f"missing backend option: {required}")
            return 1
    if "hf_token_set" not in settings:
        print("settings missing hf_token_set")
        return 1
    if platform and not platform.get("os"):
        print("platform missing os")
        return 1

    if args.chat:
        timeout = 600.0 if health.get("backend") == "huggingface" else 120.0
        print(f"\nchat test (timeout={timeout}s)...")
        with httpx.Client(timeout=timeout) as client:
            with client.stream(
                "POST",
                f"{base}/api/chat",
                json={
                    "message": "Reply with exactly: smoke test ok",
                    "history": [],
                    "mode": "default",
                    "use_rag": False,
                },
            ) as response:
                response.raise_for_status()
                text = "".join(response.iter_text())
        print("chat response:", text[:500])
        if not text.strip():
            print("empty chat response")
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
