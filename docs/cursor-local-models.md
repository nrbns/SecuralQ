# Cursor Local Models



This project supports safe local-model workflows with **Ollama**, **LM Studio**, **Hermes Agent**, **Unsloth**, or direct **Hugging Face Transformers** inference on a Windows / Linux / macOS host. Android and iOS devices use the same web UI over LAN (or localhost via Termux on Android if you host there).



## Option 1: Ollama



1. Install [Ollama](https://ollama.com).



Linux:



```bash

curl -fsSL https://ollama.com/install.sh | sh

```



macOS:



```bash

brew install ollama

```



2. Pull a model:



```bash

ollama pull tinyllama

```



For better quality (larger download): `ollama pull mistral`



3. In `.env`, use:



```env

MODEL_BACKEND=ollama

OLLAMA_BASE_URL=http://localhost:11434

OLLAMA_MODEL=tinyllama

```



4. Start the app:



Windows:



```powershell

.\scripts\start.ps1

```



Linux/macOS:



```bash

bash scripts/start.sh

```



## Option 2: LM Studio



1. Install [LM Studio](https://lmstudio.ai/).

2. Load a local model in LM Studio.

3. Start the local server in **OpenAI-compatible** mode on `http://localhost:1234/v1`.

4. In `.env`, use:



```env

MODEL_BACKEND=openai_compat

OPENAI_COMPAT_BASE_URL=http://localhost:1234/v1

OPENAI_COMPAT_MODEL=local-model

OPENAI_COMPAT_API_KEY=lm-studio

```



Replace `OPENAI_COMPAT_MODEL` with the model name exposed by LM Studio if needed.



## Option 3: Hermes Agent (Nous Research)



1. Install [Hermes Agent](https://github.com/NousResearch/hermes-agent).



Windows:



```powershell

iex (irm https://hermes-agent.nousresearch.com/install.ps1)

```



Linux/macOS/WSL2:



```bash

curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash

```



2. Configure a provider: `hermes setup` or `hermes setup --portal`.



3. Enable the OpenAI-compatible API server in Hermes env (`%LOCALAPPDATA%\hermes\.env` on native Windows, `~/.hermes/.env` elsewhere):



```env

API_SERVER_ENABLED=true

API_SERVER_KEY=change-me-local-dev

API_SERVER_HOST=127.0.0.1

API_SERVER_PORT=8642

```



4. Start the gateway: `hermes gateway`.



5. Point SecuraIQ at Hermes:



Windows:



```powershell

.\scripts\use_hermes.ps1

```



Linux/macOS:



```bash

bash scripts/use_hermes.sh

```



`.env` keys:



```env

MODEL_BACKEND=hermes

HERMES_BASE_URL=http://127.0.0.1:8642/v1

HERMES_MODEL=hermes-agent

HERMES_API_KEY=change-me-local-dev

```



`HERMES_API_KEY` must match Hermes `API_SERVER_KEY`. Chat still flows through SecuraIQ guardrails, modes, and RAG before Hermes.



## Option 4: Unsloth (train + infer)



1. Install [Unsloth](https://github.com/unslothai/unsloth) (GPU + CUDA recommended):



```powershell

.\.venv\Scripts\pip install unsloth

.\.venv\Scripts\pip install datasets trl peft accelerate bitsandbytes

```



2. Switch config:



```powershell

.\scripts\use_unsloth.ps1

```



```bash

bash scripts/use_unsloth.sh

```



3. In `.env` (or **Settings** in the UI):



```env

MODEL_BACKEND=unsloth

HF_TOKEN=hf_your_token_here

UNSLOTH_MODEL=unsloth/Qwen2.5-0.5B-Instruct-bnb-4bit

UNSLOTH_ADAPTER_DIR=./models/securaiq-unsloth

UNSLOTH_MAX_SEQ_LENGTH=2048

UNSLOTH_LOAD_IN_4BIT=true

```



4. Optional train: `python -m app.fine_tune.train_unsloth --epochs 1` or UI Settings → Start Unsloth train.



5. Chat with backend **Unsloth** (Preload recommended).



## Option 5: Direct Hugging Face inference



1. Install optional packages:



Windows:



```powershell

.\.venv\Scripts\pip install torch transformers accelerate

```



Linux/macOS:



```bash

.venv/bin/python -m pip install torch transformers accelerate

```



2. Switch the app config:



Windows:



```powershell

.\scripts\use_huggingface.ps1

```



Linux/macOS:



```bash

bash scripts/use_huggingface.sh

```



3. In `.env`, confirm:



```env

MODEL_BACKEND=huggingface

HF_MODEL=Qwen/Qwen2.5-0.5B-Instruct

```



4. Start the app:



Windows:



```powershell

.\scripts\start.ps1

```



Linux/macOS:



```bash

bash scripts/start.sh

```



This backend runs inference directly in Python. On **CPU-only** machines, use `Qwen/Qwen2.5-0.5B-Instruct` for practical response times.



## Cursor usage



Use Cursor normally while pointing this app at a local backend. Do not modify Cursor binaries or disable safety systems.



Recommended project behavior:



- Use local models for privacy/offline workflows

- Keep prompts scoped to authorized pentests, blue-team work, CTFs, and sandbox analysis

- Prefer `tinyllama` or `mistral` on CPU; `llama3` if you have more RAM

- Prefer code-focused models for scripting help in labs



## Verify the backend



Open:



- `http://localhost:8080/api/health`

- `http://localhost:8080/api/status`



The health response shows the active backend, model, and indexed RAG documents.

