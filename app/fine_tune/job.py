"""Background Unsloth / LoRA fine-tune job state for the API."""

from __future__ import annotations

import threading
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal


Status = Literal["idle", "running", "completed", "failed"]


@dataclass
class FinetuneJob:
    status: Status = "idle"
    engine: str = ""
    model: str = ""
    output: str = ""
    epochs: int = 1
    message: str = ""
    log_lines: list[str] = field(default_factory=list)
    started_at: str | None = None
    finished_at: str | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "status": self.status,
                "engine": self.engine,
                "model": self.model,
                "output": self.output,
                "epochs": self.epochs,
                "message": self.message,
                "log": self.log_lines[-80:],
                "started_at": self.started_at,
                "finished_at": self.finished_at,
            }

    def append_log(self, line: str) -> None:
        with self._lock:
            self.log_lines.append(line)
            if len(self.log_lines) > 400:
                self.log_lines = self.log_lines[-400:]

    def start(self, engine: str, model: str, output: str, epochs: int) -> bool:
        with self._lock:
            if self.status == "running":
                return False
            self.status = "running"
            self.engine = engine
            self.model = model
            self.output = output
            self.epochs = epochs
            self.message = "Training started"
            self.log_lines = [f"[{engine}] starting {model} → {output}"]
            self.started_at = datetime.now(timezone.utc).isoformat()
            self.finished_at = None
            return True

    def finish(self, ok: bool, message: str) -> None:
        with self._lock:
            self.status = "completed" if ok else "failed"
            self.message = message
            self.finished_at = datetime.now(timezone.utc).isoformat()
            self.log_lines.append(message)


finetune_job = FinetuneJob()


def launch_unsloth_job(*, model: str, output: str, epochs: int, batch_size: int = 2) -> bool:
    if not finetune_job.start("unsloth", model, output, epochs):
        return False

    def worker() -> None:
        try:
            from app.config import settings
            from app.fine_tune.train_unsloth import run_unsloth_training

            finetune_job.append_log("Loading Unsloth…")
            run_unsloth_training(
                model=model,
                output=output,
                epochs=epochs,
                batch_size=batch_size,
                max_seq_length=settings.unsloth_max_seq_length,
                load_in_4bit=settings.unsloth_load_in_4bit,
            )
            finetune_job.finish(True, f"Training complete. Adapter saved to {output}")
        except Exception as exc:
            finetune_job.append_log(traceback.format_exc()[-2000:])
            finetune_job.finish(False, f"Training failed: {exc}")

    threading.Thread(target=worker, daemon=True, name="unsloth-finetune").start()
    return True
