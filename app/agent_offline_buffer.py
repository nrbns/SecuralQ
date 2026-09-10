"""Bounded local offline telemetry buffer for SecuraIQ agents (REALTIME Task D).

Client-side helper intended for packaging into the agent binary later. When the
network fails, events are sequenced and persisted to a local JSON file. On
reconnect the agent flushes missing sequences and drops them after ACK.

This is a lab/scaffolding queue — not a durable HA log. Defaults: max 5000
events and a soft disk-byte cap.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any

DEFAULT_MAX_EVENTS = 5000
DEFAULT_MAX_BYTES = 8 * 1024 * 1024  # 8 MiB soft cap
DEFAULT_FILENAME = "securaiq_offline_telemetry.json"


def default_buffer_path(agent_id: str = "") -> Path:
    """Prefer XDG/data dir; fall back to cwd-relative ``data/``."""
    base = os.environ.get("SECURAIQ_AGENT_DATA_DIR") or os.environ.get("SECURAIQ_DATA_DIR")
    if base:
        root = Path(base)
    else:
        home = Path.home()
        root = home / ".securaiq" / "agent"
    root.mkdir(parents=True, exist_ok=True)
    suffix = f"_{agent_id[:12]}" if agent_id else ""
    return root / f"offline_telemetry{suffix}.json"


class OfflineTelemetryBuffer:
    """Per-agent sequenced event queue with JSON persistence."""

    def __init__(
        self,
        agent_id: str,
        *,
        path: Path | str | None = None,
        max_events: int = DEFAULT_MAX_EVENTS,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> None:
        self.agent_id = str(agent_id or "unknown")
        self.path = Path(path) if path else default_buffer_path(self.agent_id)
        self.max_events = max(1, int(max_events))
        self.max_bytes = max(64 * 1024, int(max_bytes))
        self._lock = threading.RLock()
        self._next_seq = 1
        self._last_acked = 0
        self._events: list[dict[str, Any]] = []
        self._load()

    # ------------------------------------------------------------------ persistence

    def _load(self) -> None:
        if not self.path.is_file():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return
        if not isinstance(raw, dict):
            return
        self._next_seq = max(1, int(raw.get("next_seq") or 1))
        self._last_acked = max(0, int(raw.get("last_acked_seq") or 0))
        events = raw.get("events") or []
        if isinstance(events, list):
            self._events = [e for e in events if isinstance(e, dict) and "sequence" in e]
        self._trim_unlocked()

    def _persist_unlocked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "agent_id": self.agent_id,
            "next_seq": self._next_seq,
            "last_acked_seq": self._last_acked,
            "events": self._events,
            "updated_at": time.time(),
        }
        text = json.dumps(payload, separators=(",", ":"))
        # Soft disk cap: drop oldest until under budget (always keep ≥1 newest if any).
        while len(text.encode("utf-8")) > self.max_bytes and len(self._events) > 1:
            self._events.pop(0)
            payload["events"] = self._events
            text = json.dumps(payload, separators=(",", ":"))
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(self.path)

    def _trim_unlocked(self) -> None:
        if len(self._events) > self.max_events:
            overflow = len(self._events) - self.max_events
            del self._events[:overflow]

    # ------------------------------------------------------------------ API

    @property
    def pending_count(self) -> int:
        with self._lock:
            return len(self._events)

    @property
    def next_sequence(self) -> int:
        with self._lock:
            return self._next_seq

    @property
    def last_acked_seq(self) -> int:
        with self._lock:
            return self._last_acked

    def enqueue(self, event_type: str, payload: dict[str, Any] | None = None) -> int:
        """Assign the next sequence and persist. Returns the sequence number."""
        with self._lock:
            seq = self._next_seq
            self._next_seq += 1
            entry = {
                "sequence": seq,
                "event_type": str(event_type or "telemetry"),
                "payload": payload or {},
                "enqueued_at": time.time(),
            }
            self._events.append(entry)
            self._trim_unlocked()
            self._persist_unlocked()
            return seq

    def peek(self, *, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(e) for e in self._events[: max(1, limit)]]

    def pending_sequences(self) -> list[int]:
        with self._lock:
            return [int(e["sequence"]) for e in self._events]

    def missing_after(self, last_acked: int) -> list[dict[str, Any]]:
        """Events with sequence > last_acked (for reconnect flush)."""
        with self._lock:
            return [dict(e) for e in self._events if int(e.get("sequence") or 0) > int(last_acked)]

    def ack(self, sequences: list[int] | int) -> int:
        """Remove ACKed sequences and advance last_acked. Returns count removed."""
        if isinstance(sequences, int):
            seqs = {int(sequences)}
        else:
            seqs = {int(s) for s in sequences}
        if not seqs:
            return 0
        with self._lock:
            before = len(self._events)
            self._events = [e for e in self._events if int(e.get("sequence") or 0) not in seqs]
            removed = before - len(self._events)
            high = max(seqs)
            if high > self._last_acked:
                self._last_acked = high
            self._persist_unlocked()
            return removed

    def ack_through(self, sequence: int) -> int:
        """ACK all events with sequence <= sequence."""
        seq = int(sequence)
        with self._lock:
            before = len(self._events)
            self._events = [e for e in self._events if int(e.get("sequence") or 0) > seq]
            removed = before - len(self._events)
            if seq > self._last_acked:
                self._last_acked = seq
            self._persist_unlocked()
            return removed

    def build_checkin_extension(
        self,
        *,
        flush_limit: int = 100,
        request_missing: bool = True,
    ) -> dict[str, Any]:
        """Fields to merge into an HTTP check-in body for sequence recovery."""
        with self._lock:
            batch = [dict(e) for e in self._events[: max(1, flush_limit)]]
            out: dict[str, Any] = {
                "sequence": self._next_seq - 1 if self._next_seq > 1 else 0,
                "buffered_events": batch,
            }
            if request_missing and self._last_acked >= 0:
                out["request_missing_from"] = self._last_acked + 1
            return out

    def apply_server_ack(self, response: dict[str, Any] | None) -> int:
        """Consume check-in response ACKs. Returns number of events removed."""
        if not isinstance(response, dict):
            return 0
        removed = 0
        acked = response.get("acked_sequences") or response.get("ack_sequences")
        if isinstance(acked, list) and acked:
            removed += self.ack(acked)
        through = response.get("last_acked_seq")
        if through is not None:
            removed += self.ack_through(int(through))
        return removed


# Host / inventory keys worth re-applying from ACKed offline buffer payloads (RT-05).
HOST_TELEMETRY_KEYS: frozenset[str] = frozenset(
    {
        "firewall_status",
        "defender_status",
        "ssh_config",
        "disk_encryption_status",
        "file_integrity",
        "security_logs",
        "packages",
        "hostname",
        "os",
        "os_version",
        "ip",
        "agent_version",
    }
)


def extract_host_telemetry(payload: dict[str, Any] | None) -> dict[str, Any]:
    """Return only host-telemetry keys present in ``payload``."""
    if not isinstance(payload, dict):
        return {}
    out: dict[str, Any] = {}
    for key in HOST_TELEMETRY_KEYS:
        if key in payload and payload[key] is not None:
            out[key] = payload[key]
    return out


def merge_host_telemetry(
    live: dict[str, Any] | None,
    buffered: dict[str, Any] | None,
) -> dict[str, Any]:
    """Merge newest ACKed host telemetry into live check-in payload (fill gaps)."""
    out = dict(live or {}) if isinstance(live, dict) else {}
    host = extract_host_telemetry(buffered if isinstance(buffered, dict) else None)
    for key, value in host.items():
        cur = out.get(key)
        if cur is None or cur == "" or cur == {} or cur == []:
            out[key] = value
    return out


def process_buffered_events_on_server(
    agent_id: str,
    *,
    sequence: int | None,
    buffered_events: list[dict[str, Any]] | None,
    request_missing_from: int | None,
    last_acked_seq: int,
) -> dict[str, Any]:
    """Server-side helper: ACK contiguous buffered sequences and report gaps.

    Watermark advances only through contiguous sequences — never across holes.
    Returns the newest ACKed host-telemetry payload (if any) so check-in can
    re-apply offline snapshots to inventory / host control evaluation (RT-05).
    """
    last = max(0, int(last_acked_seq or 0))
    acked: list[int] = []
    events = [e for e in (buffered_events or []) if isinstance(e, dict)]
    by_seq: dict[int, dict[str, Any]] = {}
    for e in events:
        if e.get("sequence") is None:
            continue
        try:
            s = int(e["sequence"])
        except (TypeError, ValueError):
            continue
        # Prefer later duplicate with richer payload if present.
        prev = by_seq.get(s)
        if prev is None or (
            isinstance(e.get("payload"), dict)
            and extract_host_telemetry(e.get("payload"))
            and not extract_host_telemetry(prev.get("payload") if isinstance(prev, dict) else None)
        ):
            by_seq[s] = e
    seqs = sorted(by_seq.keys())
    # Sort by sequence and ACK contiguous runs starting at last+1.
    expected = last + 1
    for s in seqs:
        if s < expected:
            continue  # already covered / duplicate
        if s == expected:
            acked.append(s)
            expected = s + 1
            last = s
        else:
            break  # gap — stop contiguous ACK (do not jump)
    if sequence is not None:
        seq_i = int(sequence)
        # Live check-in sequence (no buffer) advances watermark when contiguous.
        if seq_i == last + 1:
            last = seq_i
            if seq_i not in acked:
                acked.append(seq_i)
        elif seq_i > last:
            # Non-contiguous live seq still recorded as high-water only when
            # no buffered gap remains; otherwise leave gap for recovery.
            if not seqs or (acked and max(acked) >= seq_i - 1):
                last = max(last, seq_i)

    missing_from: int | None = None
    gap_detected = False
    # Hole inside the buffered batch (e.g. 1 then 3 while last=0) → stop at 1.
    unacked_in_batch = [s for s in seqs if s > last]
    if unacked_in_batch:
        gap_detected = True
        missing_from = last + 1
    if sequence is not None and int(sequence) > last + 1 and missing_from is None:
        # Live seq jumped ahead of watermark with no contiguous fill.
        gap_detected = True
        missing_from = last + 1
    if request_missing_from is not None:
        req = max(1, int(request_missing_from))
        if req <= last:
            # Client recovery cursor already covered — clear unless batch still has a hole.
            if not unacked_in_batch:
                missing_from = None
                gap_detected = False
        else:
            # Server is behind client claim — ask client to re-flush from last+1.
            missing_from = last + 1
            gap_detected = True

    newest_acked_host_payload: dict[str, Any] = {}
    for s in sorted(acked, reverse=True):
        ev = by_seq.get(s)
        if not ev:
            continue
        pl = ev.get("payload")
        host = extract_host_telemetry(pl if isinstance(pl, dict) else None)
        if host:
            newest_acked_host_payload = host
            break

    gap: dict[str, Any] | None = None
    if gap_detected and missing_from is not None:
        gap = {
            "detected": True,
            "missing_from": missing_from,
            "expected_next": last + 1,
            "last_acked_seq": last,
            "first_unacked_in_batch": min(unacked_in_batch) if unacked_in_batch else None,
            "acked_through": last,
        }

    return {
        "agent_id": agent_id,
        "last_acked_seq": last,
        "acked_sequences": acked,
        "missing_from": missing_from,
        "gap": gap,
        "newest_acked_host_payload": newest_acked_host_payload or None,
        "note": "offline buffer recovery — lab scaffolding, not durable HA",
    }
