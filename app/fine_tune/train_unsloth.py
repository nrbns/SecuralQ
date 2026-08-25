"""
Unsloth LoRA fine-tuning for SecuraIQ (ethical security Q&A only).

https://github.com/unslothai/unsloth

Requirements (GPU recommended; Linux/WSL preferred):
  pip install unsloth
  # plus: datasets trl peft accelerate bitsandbytes

Usage:
  python -m app.fine_tune.train_unsloth --epochs 1
  python -m app.fine_tune.train_unsloth --model unsloth/Qwen2.5-0.5B-Instruct-bnb-4bit

Set HF_TOKEN in .env for gated Hugging Face models.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from app.fine_tune.train_lora import DATASET_PATH, format_example


def _apply_hf_token() -> None:
    token = os.environ.get("HF_TOKEN") or os.environ.get("HUGGING_FACE_HUB_TOKEN") or ""
    if not token:
        try:
            from app.config import settings

            token = (settings.hf_token or "").strip()
        except Exception:
            token = ""
    if token:
        os.environ["HF_TOKEN"] = token
        os.environ["HUGGING_FACE_HUB_TOKEN"] = token


def run_unsloth_training(
    model: str,
    output: str,
    epochs: int = 1,
    batch_size: int = 2,
    max_seq_length: int = 2048,
    load_in_4bit: bool = True,
    learning_rate: float = 2e-4,
) -> str:
    """Train with Unsloth FastLanguageModel + TRL SFTTrainer. Returns output dir."""
    _apply_hf_token()

    try:
        import torch
        from datasets import load_dataset
        from trl import SFTTrainer
        from transformers import TrainingArguments
        from unsloth import FastLanguageModel
    except ImportError as exc:
        raise RuntimeError(
            "Unsloth packages missing. Install with:\n"
            "  pip install unsloth\n"
            "  pip install datasets trl peft accelerate bitsandbytes\n"
            "See https://unsloth.ai/docs/get-started/install/pip-install"
        ) from exc

    if not DATASET_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATASET_PATH}")

    print(f"Loading Unsloth model: {model}")
    model_obj, tokenizer = FastLanguageModel.from_pretrained(
        model_name=model,
        max_seq_length=max_seq_length,
        dtype=None,
        load_in_4bit=load_in_4bit,
        token=os.environ.get("HF_TOKEN") or None,
    )

    model_obj = FastLanguageModel.get_peft_model(
        model_obj,
        r=16,
        target_modules=[
            "q_proj",
            "k_proj",
            "v_proj",
            "o_proj",
            "gate_proj",
            "up_proj",
            "down_proj",
        ],
        lora_alpha=16,
        lora_dropout=0,
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=3407,
    )

    dataset = load_dataset("json", data_files=str(DATASET_PATH))
    dataset = dataset.map(format_example)

    Path(output).mkdir(parents=True, exist_ok=True)

    training_args = TrainingArguments(
        output_dir=output,
        per_device_train_batch_size=batch_size,
        gradient_accumulation_steps=4,
        num_train_epochs=epochs,
        learning_rate=learning_rate,
        fp16=torch.cuda.is_available() and not torch.cuda.is_bf16_supported(),
        bf16=torch.cuda.is_available() and torch.cuda.is_bf16_supported(),
        logging_steps=5,
        save_strategy="epoch",
        report_to="none",
        optim="adamw_8bit",
    )

    trainer_kwargs = dict(
        model=model_obj,
        train_dataset=dataset["train"],
        args=training_args,
    )
    # TRL API varies by version
    try:
        trainer = SFTTrainer(
            **trainer_kwargs,
            tokenizer=tokenizer,
            dataset_text_field="text",
            max_seq_length=max_seq_length,
        )
    except TypeError:
        try:
            from trl import SFTConfig

            sft_args = SFTConfig(
                output_dir=output,
                per_device_train_batch_size=batch_size,
                gradient_accumulation_steps=4,
                num_train_epochs=epochs,
                learning_rate=learning_rate,
                fp16=training_args.fp16,
                bf16=training_args.bf16,
                logging_steps=5,
                save_strategy="epoch",
                report_to="none",
                max_seq_length=max_seq_length,
                dataset_text_field="text",
            )
            trainer = SFTTrainer(
                model=model_obj,
                processing_class=tokenizer,
                train_dataset=dataset["train"],
                args=sft_args,
            )
        except Exception:
            trainer = SFTTrainer(
                model=model_obj,
                processing_class=tokenizer,
                train_dataset=dataset["train"],
                args=training_args,
                dataset_text_field="text",
            )

    print("Starting Unsloth training…")
    trainer.train()
    model_obj.save_pretrained(output)
    tokenizer.save_pretrained(output)
    print(f"Saved Unsloth LoRA adapter to {output}")
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description="Fine-tune SecuraIQ with Unsloth")
    parser.add_argument("--model", default=None, help="Base model (Unsloth or HF id)")
    parser.add_argument("--output", default=None)
    parser.add_argument("--epochs", type=int, default=1)
    parser.add_argument("--batch-size", type=int, default=2)
    parser.add_argument("--max-seq-length", type=int, default=None)
    parser.add_argument("--no-4bit", action="store_true")
    args = parser.parse_args()

    from app.config import settings

    model = args.model or settings.unsloth_model
    output = args.output or settings.unsloth_adapter_dir
    max_seq = args.max_seq_length or settings.unsloth_max_seq_length
    load_4bit = settings.unsloth_load_in_4bit and not args.no_4bit

    run_unsloth_training(
        model=model,
        output=output,
        epochs=args.epochs,
        batch_size=args.batch_size,
        max_seq_length=max_seq,
        load_in_4bit=load_4bit,
    )


if __name__ == "__main__":
    main()
