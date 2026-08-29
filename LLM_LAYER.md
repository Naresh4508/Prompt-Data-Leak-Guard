# Contextual LLM Layer — Design

## Why the model exists

Deterministic rules are strong for known formats but weak on context-dependent information such as:

- `Rahul Sharma` as a real person name
- `42 Lake View Road, Chennai` as a residential address
- `EMP-2026-0042` as an employee identifier
- a diagnosis/medical history embedded in prose
- an internal project codename or unreleased business plan

## Hybrid pipeline

1. Unicode/NFKC normalization
2. Deterministic pattern scan
3. Optional local contextual model
4. Exact-substring validation of model findings
5. Merge without overlap
6. Risk policy: allow / sanitize / block

## Model contract

The model returns structured JSON findings with exact text, category, risk, confidence and a short reason. Findings below 0.75 confidence are ignored. Model output is never trusted as an arbitrary text replacement.
