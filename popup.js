const DEFAULTS = {
  enabled: true,
  mode: 'auto_sanitize',
  contextualEnabled: false,
  ollamaUrl: 'http://127.0.0.1:11434',
  ollamaModel: 'qwen3:4b-instruct',
  stats: { scanned: 0, flagged: 0, highRisk: 0, sanitized: 0, blocked: 0 }
};

function render(state) {
  document.getElementById('enabled').checked = !!state.enabled;
  document.getElementById('dot').className = `dot ${state.enabled ? 'on' : ''}`;
  document.getElementById('statusText').textContent = state.enabled ? 'Protection active' : 'Protection off';
  document.getElementById('mode').value = state.mode || 'review';
  document.getElementById('contextualEnabled').checked = !!state.contextualEnabled;
  document.getElementById('ollamaModel').value = state.ollamaModel || DEFAULTS.ollamaModel;
  const stats = { ...DEFAULTS.stats, ...(state.stats || {}) };
  for (const key of Object.keys(DEFAULTS.stats)) {
    const el = document.getElementById(key);
    if (el) el.textContent = stats[key];
  }
}

chrome.storage.local.get(DEFAULTS, render);

document.getElementById('enabled').addEventListener('change', e => {
  chrome.storage.local.set({ enabled: e.target.checked });
});

document.getElementById('mode').addEventListener('change', e => {
  chrome.storage.local.set({ mode: e.target.value });
});

document.getElementById('contextualEnabled').addEventListener('change', e => {
  chrome.storage.local.set({ contextualEnabled: e.target.checked });
});

document.getElementById('ollamaModel').addEventListener('change', e => {
  chrome.storage.local.set({ ollamaModel: e.target.value.trim() || DEFAULTS.ollamaModel });
});

document.getElementById('testOllama').addEventListener('click', () => {
  const status = document.getElementById('llmStatus');
  status.textContent = 'Checking local Ollama…';
  chrome.runtime.sendMessage({ type: 'PDLG_TEST_OLLAMA' }, response => {
    if (chrome.runtime.lastError || !response?.ok) {
      status.textContent = `Ollama unavailable: ${response?.error || chrome.runtime.lastError?.message || 'unknown error'}`;
      return;
    }
    const names = response.models || [];
    const selected = response.model || DEFAULTS.ollamaModel;
    status.textContent = names.length
      ? `Connected • ${names.length} local model(s) • selected: ${selected}`
      : 'Connected • no local models installed';
  });
});

chrome.storage.onChanged.addListener(() => chrome.storage.local.get(DEFAULTS, render));
