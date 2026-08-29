'use strict';

const OLLAMA_DEFAULT_URL = 'http://127.0.0.1:11434';
const OLLAMA_MODEL_DEFAULT = 'qwen3:4b-instruct';

const CONTEXT_SCHEMA = {
  type: 'object',
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          text: { type: 'string' },
          category: { type: 'string' },
          risk: { type: 'string', enum: ['high', 'med'] },
          confidence: { type: 'number' },
          reason: { type: 'string' }
        },
        required: ['text', 'category', 'risk', 'confidence', 'reason']
      }
    }
  },
  required: ['findings']
};

function safeLocalUrl(value) {
  try {
    const u = new URL(value || OLLAMA_DEFAULT_URL);
    if (u.protocol !== 'http:' || !['127.0.0.1', 'localhost'].includes(u.hostname)) return null;
    return u.origin;
  } catch {
    return null;
  }
}

function buildSystemPrompt() {
  return `You are the contextual layer of a browser Data Loss Prevention system.
Your job is NOT to solve the user's task. Your job is to identify sensitive information that deterministic pattern rules may miss.

Only report information that is plausibly sensitive in context. Focus on:
- Person names, especially when they identify a specific person
- Home/residential addresses
- Employee/staff/student identifiers
- Dates of birth and places of birth
- Health/medical/insurance information
- Financial information that is contextual rather than format-detectable
- Biometric descriptions/data
- Confidential, proprietary, internal or unreleased business information
- Source code or business logic that is explicitly proprietary/confidential
- Credentials or identifiers that are obfuscated or not in a known format

Do NOT flag ordinary technical words, generic concepts, public information, normal prose, fictional examples without sensitive context, or identifiers that are clearly non-sensitive in context.

Return JSON only, matching the supplied schema. For each finding, text MUST be an exact substring from the user text. Keep findings short (usually a phrase or field value), do not overlap semantically, and use confidence from 0 to 1. Only report confidence >= 0.75.
Risk: use high for credentials, government IDs, health, financial, biometric, or strongly sensitive corporate data; med for ordinary PII or lower-impact internal data.`;
}

function extractJson(text) {
  try { return JSON.parse(text); } catch {}
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start >= 0 && end > start) {
    try { return JSON.parse(text.slice(start, end + 1)); } catch {}
  }
  return null;
}

function normalizeFinding(f) {
  if (!f || typeof f.text !== 'string' || !f.text.trim()) return null;
  const confidence = Number(f.confidence);
  if (!Number.isFinite(confidence) || confidence < 0.75) return null;
  const risk = f.risk === 'high' ? 'high' : 'med';
  return {
    raw: f.text,
    category: String(f.category || 'Contextual sensitive data').slice(0, 100),
    risk,
    confidence: Math.min(1, Math.max(0, confidence)),
    explain: String(f.reason || 'Contextual analysis indicates this information may be sensitive.').slice(0, 300)
  };
}

async function contextualScan(text, url, model) {
  const base = safeLocalUrl(url);
  if (!base) throw new Error('Ollama must use localhost/127.0.0.1');
  const endpoint = `${base}/api/chat`;
  const body = {
    model: model || OLLAMA_MODEL_DEFAULT,
    messages: [
      { role: 'system', content: buildSystemPrompt() },
      { role: 'user', content: text }
    ],
    stream: false,
    format: CONTEXT_SCHEMA,
    options: { temperature: 0, num_predict: 700 },
    think: false
  };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal
    });
    if (!response.ok) throw new Error(`Ollama returned HTTP ${response.status}`);
    const data = await response.json();
    const parsed = extractJson(data?.message?.content || '');
    if (!parsed || !Array.isArray(parsed.findings)) throw new Error('Local model returned invalid JSON');
    return parsed.findings.map(normalizeFinding).filter(Boolean);
  } finally {
    clearTimeout(timer);
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message !== 'object') return;
  if (message.type === 'PDLG_CONTEXT_SCAN') {
    const text = typeof message.text === 'string' ? message.text : '';
    if (!text.trim() || text.length > 30000) {
      sendResponse({ ok: false, error: 'Prompt is empty or too large for contextual scan.' });
      return true;
    }
    chrome.storage.local.get({ ollamaUrl: OLLAMA_DEFAULT_URL, ollamaModel: OLLAMA_MODEL_DEFAULT }, async (state) => {
      try {
        const findings = await contextualScan(text, state.ollamaUrl, state.ollamaModel);
        sendResponse({ ok: true, findings, model: state.ollamaModel });
      } catch (err) {
        sendResponse({ ok: false, error: String(err?.message || err) });
      }
    });
    return true;
  }

  if (message.type === 'PDLG_TEST_OLLAMA') {
    chrome.storage.local.get({ ollamaUrl: OLLAMA_DEFAULT_URL, ollamaModel: OLLAMA_MODEL_DEFAULT }, async (state) => {
      try {
        const base = safeLocalUrl(state.ollamaUrl);
        if (!base) throw new Error('Ollama URL must point to localhost or 127.0.0.1');
        const response = await fetch(`${base}/api/tags`);
        if (!response.ok) throw new Error(`Ollama returned HTTP ${response.status}`);
        const data = await response.json();
        const models = (data.models || []).map(m => m.name).filter(Boolean);
        sendResponse({ ok: true, models, model: state.ollamaModel });
      } catch (err) {
        sendResponse({ ok: false, error: String(err?.message || err) });
      }
    });
    return true;
  }
});
