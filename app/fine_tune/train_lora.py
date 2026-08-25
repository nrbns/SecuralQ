"""
LoRA fine-tuning script for SecuraIQ (ethical security Q&A only).

Requirements:
  pip install torch transformers datasets accelerate peft trl bitsandbytes

Usage:
  python -m app.fine_tune.train_lora --model meta-llama/Llama-3-8B-Instruct --epochs 1

You need HuggingFace access for gated models (Llama) and a GPU with enough VRAM.
For smaller GPUs, use: microsoft/Phi-3-mini-4k-instruct
"""

from __future__ import annotations

import argparse
from pathlib import Path

DATASET_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "ethical_pentest_dataset.jsonl"


def format_example(example: dict) -> dict:
    text = (
        f"<|system|>You are SecuraIQ. Authorized security testing only.<|end|>\n"
        f"<|user|>{example['instruction']}<|end|>\n"
        f"<|assistant|>{example['response']}<|end|>"
    )
    return {"text": text}


def main() -> None:
    parser = argparse.ArgumentParser(description="Fine-tune SecuraIQ with LoRA")
    parser.add_argument("--model", default="microsoft/Phi-3-mini-4k-instruct")
    parser.add_argument("--output", default="./models/securaiq-lora")
    parser.add_argument("--epochs", type=int, default=1)
    parser.add_argument("--batch-size", type=int, default=2)
    args = parser.parse_args()

    try:
        import torch
        from datasets import load_dataset
        from peft import LoraConfig, get_peft_model
        from transformers import AutoModelForCausalLM, AutoTokenizer, TrainingArguments, Trainer
    except ImportError as exc:
        raise SystemExit(
            "Missing packages. Run:\n"
            "  pip install torch transformers datasets accelerate peft trl bitsandbytes"
        ) from exc

    if not DATASET_PATH.exists():
        raise SystemExit(f"Dataset not found: {DATASET_PATH}")

    print(f"Loading model: {args.model}")
    tokenizer = AutoTokenizer.from_pretrained(args.model, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    load_kwargs: dict = {"trust_remote_code": True}
    if torch.cuda.is_available():
        load_kwargs["torch_dtype"] = torch.float16
        load_kwargs["device_map"] = "auto"

    model = AutoModelForCausalLM.from_pretrained(args.model, **load_kwargs)

    lora_config = LoraConfig(
        r=16,
        lora_alpha=32,
        target_modules=["q_proj", "v_proj", "k_proj", "o_proj"],
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    dataset = load_dataset("json", data_files=str(DATASET_PATH))
    dataset = dataset.map(format_example)

    def tokenize(batch):
        return tokenizer(
            batch["text"],
            truncation=True,
            max_length=1024,
            padding="max_length",
        )

    tokenized = dataset.map(tokenize, batched=True, remove_columns=dataset["train"].column_names)

    training_args = TrainingArguments(
        output_dir=args.output,
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=4,
        num_train_epochs=args.epochs,
        learning_rate=2e-4,
        fp16=torch.cuda.is_available(),
        logging_steps=10,
        save_strategy="epoch",
        report_to="none",
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized["train"],
        tokenizer=tokenizer,
    )

    print("Starting training…")
    trainer.train()
    trainer.save_model(args.output)
    tokenizer.save_pretrained(args.output)
    print(f"Saved LoRA adapter to {args.output}")


if __name__ == "__main__":
    main()
