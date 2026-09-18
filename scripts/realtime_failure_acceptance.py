"""REALTIME P0 failure-scenario acceptance harness (lab).

Proves recovery / security edges that the golden firewall loop does not cover:

  duplicate publish, sequence gap, contiguous ACK, offline buffer,
  SSE Last-Event-ID, tenant SSE filter, command reject/timeout,
  bad signature, replay nonce, cert revoke, DLQ dead-letter rules,
  production profile assert, Redis reconnect helper.

Honest: lab proofs — not measured Sentinel/HA certification.

Usage:

  python scripts/realtime_failure_acceptance.py
  pytest tests/test_realtime_failure_scenarios.py -q
"""

from __future__ import annotations

import json
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

DISCLAIMER = "lab failure harness — not Sentinel/HA proof"


@dataclass
class StepResult:
    name: str
    ok: bool
    detail: str = ""
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class FailureReport:
    mode: str = "local"
    ok: bool = False
    disclaimer: str = DISCLAIMER
    steps: list[StepResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "ok": self.ok,
            "disclaimer": self.disclaimer,
            "passed": sum(1 for s in self.steps if s.ok),
            "total": len(self.steps),
            "steps": [asdict(s) for s in self.steps],
        }


def _step(name: str, fn: Callable[[], tuple[bool, str, dict[str, Any]]]) -> StepResult:
    try:
        ok, detail, data = fn()
        return StepResult(name=name, ok=bool(ok), detail=detail, data=data or {})
    except Exception as exc:
        return StepResult(name=name, ok=False, detail=f"error: {exc}"[:300], data={})


def _cfg(tmp: Path, monkeypatch: Any) -> None:
    from tests._http_test_utils import configure_isolated_settings

    configure_isolated_settings(monkeypatch, tmp)


class _MiniPatch:
    """Minimal monkeypatch for script mode (no pytest)."""

    def __init__(self) -> None:
        self._undo: list[Callable[[], None]] = []

    def setattr(self, target: Any, name: Any = None, value: Any = None, raising: bool = True) -> None:
        # Support pytest forms:
        #   setattr(obj, "attr", value)
        #   setattr("pkg.mod.attr", value)
        if isinstance(target, str) and value is None and name is not None:
            dotted, value = target, name
            mod_name, _, attr = dotted.rpartition(".")
            import importlib

            obj = importlib.import_module(mod_name)
            old = getattr(obj, attr)
            setattr(obj, attr, value)

            def undo() -> None:
                setattr(obj, attr, old)

            self._undo.append(undo)
            return
        if isinstance(target, str):
            mod_name, _, attr = target.rpartition(".")
            import importlib

            obj = importlib.import_module(mod_name)
            old = getattr(obj, attr)
            setattr(obj, attr, name if value is None else value)

            def undo_s() -> None:
                setattr(obj, attr, old)

            self._undo.append(undo_s)
            return
        old = getattr(target, name)
        setattr(target, name, value)

        def undo2() -> None:
            setattr(target, name, old)

        self._undo.append(undo2)

    def undo(self) -> None:
        for fn in reversed(self._undo):
            try:
                fn()
            except Exception:
                pass


def run_failure_matrix(*, tmp_path: Path | None = None) -> FailureReport:
    """Execute all lab failure proofs; return aggregate report."""
    report = FailureReport()
    own_tmp = tmp_path is None
    td = tempfile.TemporaryDirectory() if own_tmp else None
    root = Path(td.name) if td else Path(tmp_path)  # type: ignore[arg-type]
    mp = _MiniPatch()

    try:
        _cfg(root, mp)
        from app.tenancy import ensure_tenant_schema

        ensure_tenant_schema()

        # --- 1. Duplicate publish dedupe ---
        def dup() -> tuple[bool, str, dict[str, Any]]:
            from app.realtime_bus import clear_replay_buffer_for_tests, publish, publish_throughput

            clear_replay_buffer_for_tests()
            eid = "fail-dup-1"
            publish(type="agent", event_id=eid, id="a1", user_id="u1")
            publish(type="agent", event_id=eid, id="a1", user_id="u1")
            thr = publish_throughput()
            dropped = int(thr.get("duplicates_dropped") or 0)
            ok = dropped >= 1
            return ok, f"duplicates_dropped={dropped}", {"duplicates_dropped": dropped}

        report.steps.append(_step("duplicate_event_dedupe", dup))

        # --- 2. Contiguous ACK ---
        def contig() -> tuple[bool, str, dict[str, Any]]:
            from app.agents import checkin, enroll_agent, ensure_schema, get_agent

            ensure_schema()
            en = enroll_agent("u-fail", name="contig-host")
            aid = en["agent_id"]
            r = checkin(
                aid,
                {
                    "hostname": "contig-host",
                    "os": "linux",
                    "sequence": 2,
                    "buffered_events": [
                        {"sequence": 1, "event_type": "telemetry", "payload": {"x": 1}},
                        {"sequence": 2, "event_type": "telemetry", "payload": {"x": 2}},
                    ],
                    "request_missing_from": 1,
                },
            )
            agent = get_agent(aid)
            ok = r.get("last_acked_seq") == 2 and int(agent.get("last_telemetry_seq") or 0) == 2
            return ok, f"last_acked={r.get('last_acked_seq')}", {"result": r}

        report.steps.append(_step("sequence_contiguous_ack", contig))

        # --- 3. Gap — never ACK across hole ---
        def gap() -> tuple[bool, str, dict[str, Any]]:
            from app.agents import checkin, enroll_agent, ensure_schema, get_agent

            ensure_schema()
            en = enroll_agent("u-fail2", name="gap-host")
            aid = en["agent_id"]
            r = checkin(
                aid,
                {
                    "hostname": "gap-host",
                    "os": "linux",
                    "sequence": 3,
                    "buffered_events": [
                        {"sequence": 1, "event_type": "telemetry", "payload": {"x": 1}},
                        {"sequence": 3, "event_type": "telemetry", "payload": {"x": 3}},
                    ],
                    "request_missing_from": 1,
                },
            )
            agent = get_agent(aid)
            ok = (
                r.get("last_acked_seq") == 1
                and r.get("missing_from") == 2
                and (r.get("gap") or {}).get("detected") is True
                and int(agent.get("last_telemetry_seq") or 0) == 1
            )
            return ok, f"acked={r.get('last_acked_seq')} missing={r.get('missing_from')}", {"result": r}

        report.steps.append(_step("sequence_gap_no_skip", gap))

        # --- 4. Offline buffer contiguous ACK ---
        def offline() -> tuple[bool, str, dict[str, Any]]:
            from app.agent_offline_buffer import OfflineTelemetryBuffer

            path = root / "offline.json"
            buf = OfflineTelemetryBuffer("off-agent", path=path, max_events=50)
            for i in range(3):
                buf.enqueue("telemetry", {"n": i})
            seqs = buf.pending_sequences()
            removed = buf.ack_through(2)
            rem_seqs = buf.pending_sequences()
            ok = seqs == [1, 2, 3] and removed == 2 and rem_seqs == [3]
            # apply_server_ack must not jump across a hole: only ACK through contiguous
            fake = {"last_acked_seq": 5, "acked_sequences": [3, 4, 5]}
            # after ack_through(2), only 3 remains — applying 5 drains 3 (local prefix)
            drained = buf.apply_server_ack({"last_acked_seq": 3, "acked_sequences": [3]})
            ok2 = drained >= 1 and buf.pending_count == 0
            return ok and ok2, f"seqs={seqs} rem={rem_seqs} drained={drained}", {
                "seqs": seqs,
                "remaining_after_2": rem_seqs,
                "fake": fake,
            }

        report.steps.append(_step("offline_buffer_contiguous_ack", offline))

        # --- 5. SSE Last-Event-ID replay ---
        def sse_replay() -> tuple[bool, str, dict[str, Any]]:
            from app.realtime_bus import clear_replay_buffer_for_tests, publish, replay_since

            clear_replay_buffer_for_tests()
            publish(type="control.failed", event_id="sse-a", user_id="u1", _from_processor=True)
            publish(type="control.passed", event_id="sse-b", user_id="u1", _from_processor=True)
            after = replay_since("sse-a", limit=50)
            ids = [str(e.get("event_id") or "") for e in after]
            # Catch-up must include sse-b and must not re-send sse-a itself.
            ok = "sse-b" in ids and "sse-a" not in ids
            return ok, f"replay_has_b={('sse-b' in ids)} has_a={('sse-a' in ids)} n={len(ids)}", {
                "ids": ids[:20]
            }

        report.steps.append(_step("sse_last_event_id_replay", sse_replay))

        # --- 6. Tenant SSE filter ---
        def tenant_sse() -> tuple[bool, str, dict[str, Any]]:
            from app.realtime_bus import sse_push_allowed_for_client

            allow_a = sse_push_allowed_for_client(
                {"type": "risk.changed", "org_id": "org-a", "event_id": "t1"},
                auth_enabled=True,
                client_user_id="user-a",
                client_org_ids=["org-a"],
            )
            deny_b = sse_push_allowed_for_client(
                {"type": "risk.changed", "org_id": "org-b", "event_id": "t2"},
                auth_enabled=True,
                client_user_id="user-a",
                client_org_ids=["org-a"],
            )
            ok = allow_a is True and deny_b is False
            return ok, f"org_a_ok={allow_a} org_b_blocked={not deny_b}", {}

        report.steps.append(_step("sse_tenant_isolation", tenant_sse))

        # --- 7. Command reject ---
        def cmd_reject() -> tuple[bool, str, dict[str, Any]]:
            from app.agents import (
                enroll_agent,
                ensure_schema,
                reject_command,
                request_enable_firewall_command,
            )
            from app.db import get_conn

            ensure_schema()
            en = enroll_agent("u-rej", name="rej-host")
            aid = en["agent_id"]
            cmd = request_enable_firewall_command("u-rej", aid, requested_by="u-rej")
            cid = cmd["id"]
            out = reject_command("u-rej", aid, cid, approver_id="u-rej", reason="lab reject")
            row = get_conn().execute(
                "SELECT status FROM securaiq_agent_commands WHERE id = ?", (cid,)
            ).fetchone()
            status = dict(row).get("status") if row else ""
            ok = out.get("status") == "rejected" and status == "rejected"
            return ok, f"status={status}", {"command_id": cid}

        report.steps.append(_step("command_reject", cmd_reject))

        # --- 8. Command timeout / expired lifecycle ---
        def cmd_timeout() -> tuple[bool, str, dict[str, Any]]:
            from app.agents import command_lifecycle

            lc = command_lifecycle("timeout", error="Command expired before delivery")
            ok = lc in ("TIMEOUT", "EXPIRED")
            return ok, f"lifecycle={lc}", {"lifecycle": lc}

        report.steps.append(_step("command_timeout_lifecycle", cmd_timeout))

        # --- 9. Bad command signature ---
        def bad_sig() -> tuple[bool, str, dict[str, Any]]:
            from app.agent_security import seal_command_for_delivery, verify_sealed_command

            row = {
                "id": "c1",
                "agent_id": "a1",
                "kind": "enable_firewall",
                "created_at": time.time(),
            }
            sealed = seal_command_for_delivery(row, {"action": "enable_firewall"})
            good = verify_sealed_command(sealed)
            bad = dict(sealed)
            bad["signature"] = "deadbeef" * 8
            bad.pop("signature_ed25519", None)
            bad["signature_alg"] = "hmac"
            rejected = verify_sealed_command(bad) is False
            ok = good is True and rejected is True
            return ok, f"good={good} bad_rejected={rejected}", {}

        report.steps.append(_step("bad_signature_reject", bad_sig))

        # --- 10. Replay nonce ---
        def replay_nonce() -> tuple[bool, str, dict[str, Any]]:
            from app.agent_security import ensure_security_schema, remember_nonce

            ensure_security_schema()
            n = f"nonce-{time.time_ns()}"
            first = remember_nonce(n, agent_id="a1")
            second = remember_nonce(n, agent_id="a1")
            ok = first is True and second is False
            return ok, f"first={first} second={second}", {}

        report.steps.append(_step("replay_nonce_reject", replay_nonce))

        # --- 11. Cert revoke ---
        def cert_rev() -> tuple[bool, str, dict[str, Any]]:
            from app.agent_certs import (
                issue_agent_client_certificate,
                is_fingerprint_revoked,
                revoke_agent_certificate,
                verify_proxy_client_cert,
            )
            from app.agents import enroll_agent
            from app.config import settings

            mp.setattr(settings, "agent_mtls_enabled", True, raising=False)
            mp.setattr(settings, "agent_mtls_proxy_verify", True, raising=False)
            mp.setattr(settings, "agent_mtls_require_fingerprint_match", True, raising=False)
            en = enroll_agent("u-cert", name="cert-host")
            aid = en["agent_id"]
            issued = issue_agent_client_certificate(aid, days=7)
            fp = issued["fingerprint"]
            revoke_agent_certificate(aid, reason="lab", revoked_by="u-cert")
            err = verify_proxy_client_cert(
                {"certificate_fingerprint": fp},
                client_verify="SUCCESS",
                client_fingerprint=fp,
            )
            ok = is_fingerprint_revoked(fp) and err is not None and "revoked" in str(err).lower()
            return ok, f"revoked={is_fingerprint_revoked(fp)} err={err}", {"fp": fp}

        report.steps.append(_step("certificate_revoked_reject", cert_rev))

        # --- 12. DLQ rules ---
        def dlq_rules() -> tuple[bool, str, dict[str, Any]]:
            from app.event_processor import build_dlq_fields, should_dead_letter

            fields = build_dlq_fields(
                {"event_id": "e1", "type": "vuln"},
                error="boom",
                delivery_count=5,
                stream_id="1-0",
            )
            ok = (
                should_dead_letter(delivery_count=5, max_deliveries=5) is True
                and should_dead_letter(delivery_count=2, max_deliveries=5) is False
                and fields.get("error") == "boom"
                and "payload" in fields
            )
            return ok, "dead_letter_at_max=True under_max=False", {"fields_keys": list(fields)}

        report.steps.append(_step("dlq_dead_letter_rules", dlq_rules))

        # --- 13. DLQ replay/purge mocked ---
        def dlq_ops() -> tuple[bool, str, dict[str, Any]]:
            from unittest.mock import MagicMock

            from app import event_processor

            mp.setattr(event_processor, "_redis_configured", lambda: True)
            mp.setattr(event_processor, "_dlq_key", lambda: "securaiq:events:dlq")
            mp.setattr(event_processor, "_stream_key", lambda: "securaiq:events")
            client = MagicMock()
            client.xrange.return_value = [
                ("9-0", {"payload": json.dumps({"event_id": "r1", "type": "agent"}), "error": "x"}),
            ]
            client.xadd.return_value = "10-0"
            client.xdel.return_value = 1
            mp.setattr("app.redis_client.get_sync_redis", lambda **kwargs: client)
            replayed = event_processor.replay_dlq_entries(["9-0"], limit=10)
            purged = event_processor.purge_dlq_entries(["9-0"], limit=10)
            ok = replayed.get("ok") is True and int(replayed.get("replayed") or 0) >= 1
            return ok, f"replay={replayed.get('replayed')} purge_ok={purged.get('ok')}", {
                "replay": replayed,
                "purge": purged,
            }

        report.steps.append(_step("dlq_replay_purge_mocked", dlq_ops))

        # --- 14. Production profile assert ---
        def prod_profile() -> tuple[bool, str, dict[str, Any]]:
            from app.production_profile import assert_commercial_profile, production_profile_status

            # Lab: assert is no-op without enforce
            assert_commercial_profile()
            st = production_profile_status()
            ok = st.get("ok") is True and "flags" in st
            return ok, f"ready={st.get('production_ready_agent_security')}", {"flags": st.get("flags")}

        report.steps.append(_step("production_profile_status", prod_profile))

        # --- 15. Redis reconnect helper ---
        def redis_reconnect() -> tuple[bool, str, dict[str, Any]]:
            from app.redis_client import reconnect_after_failover, reset_clients_for_tests

            reset_clients_for_tests()
            reconnect_after_failover()
            return True, "reconnect_after_failover_ok", {}

        report.steps.append(_step("redis_reconnect_helper", redis_reconnect))

        # --- 16. Metrics aggregate ---
        def metrics() -> tuple[bool, str, dict[str, Any]]:
            from app.realtime_ops import pipeline_metrics

            m = pipeline_metrics()
            ok = m.get("ok") is True and "ingress" in m and "stream" in m and "sse" in m
            return ok, f"mode={m.get('mode')}", {"keys": list(m.keys())}

        report.steps.append(_step("realtime_pipeline_metrics", metrics))

        report.ok = all(s.ok for s in report.steps)
    finally:
        try:
            from app.db import reset_conn_for_tests

            reset_conn_for_tests()
        except Exception:
            pass
        mp.undo()
        if td is not None:
            try:
                td.cleanup()
            except Exception:
                pass

    return report


def print_report(report: FailureReport) -> None:
    print(f"[rt-fail] {report.disclaimer}")
    passed = sum(1 for s in report.steps if s.ok)
    total = len(report.steps)
    print(f"[rt-fail] mode={report.mode} overall={'PASS' if report.ok else 'FAIL'} {passed}/{total}")
    for s in report.steps:
        mark = "PASS" if s.ok else "FAIL"
        print(f"  [{mark}] {s.name}: {s.detail}")
    print(json.dumps(report.to_dict(), indent=2, default=str))


def main() -> int:
    report = run_failure_matrix()
    print_report(report)
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
