# Prompt Data-Leak Guard — Chrome v0.2.0

Browser-level GenAI DLP for ChatGPT, Gemini and Claude.

## What changed in v0.2.0

- Existing deterministic local scanner remains the first security boundary.
- Added optional contextual detection using a **local Ollama model**.
- Added Unicode normalization / invisible-character cleanup before detection.
- Contextual model results are validated against exact substrings before they can affect sanitization.
- The extension accepts Ollama only on `localhost` / `127.0.0.1`.
- Popup includes a toggle and local model name setting.

## Local LLM setup

Install Ollama locally, then pull a model. A practical default is:

```bash
ollama run qwen3:4b-instruct
```

Ollama exposes its local API on `http://localhost:11434/api` by default.

If the extension cannot access Ollama from the extension origin, configure Ollama CORS to permit Chrome extension origins, for example with `OLLAMA_ORIGINS=chrome-extension://*` before starting Ollama.

## Important privacy boundary

The contextual layer sends the prompt only to the **local Ollama endpoint on the same machine**. It does not call a cloud LLM. The service worker validates that the configured endpoint resolves to localhost/127.0.0.1 and rejects other hosts.

## Recommended demo setup

1. Load this folder as an unpacked Manifest V3 extension.
2. Start Ollama with the selected model.
3. Open the extension popup.
4. Enable **Contextual scan before send**.
5. Click **Test** and confirm the local model is available.
6. Use a prompt with labeled and unlabeled PII, e.g. a person name, home address, employee ID, health information and an API key.
7. Compare deterministic-only vs contextual-enabled results.

## Supported sites

- ChatGPT
- Gemini
- Claude

This build is still an MVP. Site DOMs can change, and a local model can make mistakes. Security-critical known-format secrets remain under deterministic rules; the local model is a supplemental contextual classifier.
