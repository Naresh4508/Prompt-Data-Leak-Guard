(function () {
  'use strict';

  const DEFAULTS = {
    enabled: true,
    mode: 'auto_sanitize',
    stats: { scanned: 0, flagged: 0, highRisk: 0, sanitized: 0, blocked: 0 }
  };

  const HOST = location.hostname;
  const ADAPTERS = {
    chatgpt: {
      match: /(^|\.)chatgpt\.com$|(^|\.)chat\.openai\.com$/,
      editors: ['#prompt-textarea', 'div.ProseMirror[contenteditable="true"]', 'textarea[data-id="root"]', '[role="textbox"][contenteditable="true"]'],
      sends: ['#composer-submit-button', 'button[data-testid="send-button"]', 'button[aria-label="Send prompt"]', 'form button[type="submit"]']
    },
    gemini: {
      match: /(^|\.)gemini\.google\.com$/,
      editors: ['div.ql-editor[contenteditable="true"]', 'rich-textarea [contenteditable="true"]', '[aria-label="Enter a prompt here"]', '[contenteditable="true"][role="textbox"]'],
      sends: ['button[aria-label="Send message"]', 'button[aria-label*="Send" i]', 'button.send-button', '.send-button']
    },
    claude: {
      match: /(^|\.)claude\.ai$/,
      editors: ['div.ProseMirror[contenteditable="true"]', 'fieldset div[contenteditable="true"]', '[contenteditable="true"][role="textbox"]'],
      sends: ['button[aria-label="Send message"]', 'button[aria-label="Send Message"]', 'button[data-testid="chat-input-send"]', 'fieldset button:last-of-type']
    }
  };

  function adapterForHost() {
    return Object.values(ADAPTERS).find(a => a.match.test(HOST)) || null;
  }
  const ADAPTER = adapterForHost();
  if (!ADAPTER) return;

  let settings = { ...DEFAULTS };
  let bypassOnce = false;
  const inputCache = new WeakMap();

  function isEditable(el) {
    if (!el || !(el instanceof HTMLElement)) return false;
    return el.tagName === 'TEXTAREA' || el.tagName === 'INPUT' || el.isContentEditable === true || el.getAttribute('contenteditable') === 'true';
  }

  function visible(el) {
    if (!el) return false;
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== 'hidden';
  }

  function getEditor(preferred = null) {
    if (preferred && isEditable(preferred) && visible(preferred)) return preferred;
    for (const selector of ADAPTER.editors) {
      const el = document.querySelector(selector);
      if (el && isEditable(el) && visible(el)) return el;
    }
    const candidates = [...document.querySelectorAll('textarea,input[type="text"],[contenteditable="true"],[role="textbox"]')]
      .filter(isEditable).filter(visible);
    return candidates.at(-1) || null;
  }

  function getSendButton(preferredRoot = null) {
    for (const selector of ADAPTER.sends) {
      const el = (preferredRoot || document).querySelector?.(selector);
      if (el && visible(el) && !el.disabled && el.getAttribute('aria-disabled') !== 'true') return el;
    }
    return null;
  }

  function normalizeForDetection(text) {
    return String(text)
      .normalize('NFKC')
      .replace(/[\u200B-\u200D\u2060\uFEFF]/g, '')
      .replace(/[\u00A0]/g, ' ');
  }

  function mergeContextualFindings(text, deterministic, contextual) {
    const out = [...deterministic];
    for (const f of (contextual || [])) {
      const raw = String(f.raw || '');
      if (!raw || raw.length > 300 || f.confidence < 0.75) continue;
      let start = text.indexOf(raw);
      if (start < 0) continue;
      while (start >= 0) {
        const end = start + raw.length;
        const overlaps = out.some(m => start < m.end && end > m.start);
        if (!overlaps) {
          out.push({ start, end, raw, rule: {
            cat: f.category || 'Contextual sensitive data',
            risk: f.risk === 'high' ? 'high' : 'med',
            explain: `${f.explain || 'Contextual local-model analysis indicates this may be sensitive.'} Confidence ${(f.confidence * 100).toFixed(0)}%.`,
            placeholder: f.risk === 'high' ? '[CONTEXTUAL_SENSITIVE_REDACTED]' : '[PII_REDACTED]'
          }, contextual: true });
          break;
        }
        start = text.indexOf(raw, start + 1);
      }
    }
    out.sort((a,b) => a.start - b.start || (b.end-b.start) - (a.end-a.start));
    return out;
  }

  async function runContextualScan(text) {
    return await new Promise(resolve => {
      chrome.runtime.sendMessage({ type: 'PDLG_CONTEXT_SCAN', text }, response => {
        if (chrome.runtime.lastError || !response?.ok) {
          resolve({ ok: false, error: response?.error || chrome.runtime.lastError?.message || 'Local model unavailable', findings: [] });
          return;
        }
        resolve({ ok: true, findings: response.findings || [], model: response.model });
      });
    });
  }

  function getText(el) {
    if (!el) return '';
    if (el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement) return el.value || '';
    return (el.innerText || el.textContent || '').trim();
  }

  function emitInput(el, value) {
    try { el.dispatchEvent(new InputEvent('input', { bubbles: true, composed: true, inputType: 'insertText', data: value })); }
    catch { el.dispatchEvent(new Event('input', { bubbles: true, composed: true })); }
    try { el.dispatchEvent(new Event('change', { bubbles: true, composed: true })); } catch {}
  }

  function setInputValue(el, value) {
    if (!el) return false;
    try {
      el.focus({ preventScroll: true });
      if (el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement) {
        const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
        const desc = Object.getOwnPropertyDescriptor(proto, 'value');
        if (desc?.set) desc.set.call(el, value); else el.value = value;
        emitInput(el, value);
        return getText(el) === String(value).trim();
      }

      // Prefer a real editing operation; this is understood by ProseMirror/Tiptap/Quill-style editors.
      const sel = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(el);
      sel.removeAllRanges();
      sel.addRange(range);

      let changed = false;
      if (typeof document.execCommand === 'function') {
        changed = document.execCommand('insertText', false, value);
      }
      if (!changed) {
        range.deleteContents();
        const textNode = document.createTextNode(value);
        range.insertNode(textNode);
        range.setStartAfter(textNode);
        range.collapse(true);
        sel.removeAllRanges();
        sel.addRange(range);
      }
      emitInput(el, value);
      return normalize(getText(el)) === normalize(String(value));
    } catch {
      return false;
    }
  }

  function normalize(s) { return String(s).replace(/\r\n?/g, '\n').trim(); }

  function updateStats(patch) {
    chrome.storage.local.get({ stats: DEFAULTS.stats }, ({ stats }) => {
      const next = {
        scanned: (stats.scanned || 0) + (patch.scanned || 0),
        flagged: (stats.flagged || 0) + (patch.flagged || 0),
        highRisk: (stats.highRisk || 0) + (patch.highRisk || 0),
        sanitized: (stats.sanitized || 0) + (patch.sanitized || 0),
        blocked: (stats.blocked || 0) + (patch.blocked || 0)
      };
      chrome.storage.local.set({ stats: next });
    });
  }

  function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
  function removeUI() { document.getElementById('pdlg-overlay')?.remove(); document.getElementById('pdlg-toast')?.remove(); }

  function makeOverlay(el, matches, safeText, hardBlock = false) {
    removeUI();
    const overlay = document.createElement('div');
    overlay.id = 'pdlg-overlay';
    const high = matches.filter(m => m.rule.risk === 'high').length;
    const med = matches.length - high;
    const findings = matches.slice(0, 7).map(m => `<div class="pdlg-finding"><span>${esc(m.rule.cat)}</span><b class="${m.rule.risk === 'high' ? 'high' : 'med'}">${m.rule.risk === 'high' ? 'HIGH' : 'MEDIUM'}</b></div>`).join('');
    overlay.innerHTML = `<div class="pdlg-modal" role="dialog" aria-modal="true">
      <div class="pdlg-kicker">PROMPT DATA-LEAK GUARD</div>
      <h2>${hardBlock ? 'Prompt blocked' : 'Sensitive data detected'}</h2>
      <p class="pdlg-lead">${matches.length} span(s) found locally. The original prompt has not been sent by the extension.</p>
      <div class="pdlg-statline"><span><b>${high}</b> high risk</span><span><b>${med}</b> medium risk</span></div>
      <div class="pdlg-findings">${findings}</div>
      <div class="pdlg-preview"><div class="pdlg-preview-label">SAFE REWRITE</div><pre>${esc(safeText)}</pre></div>
      <div class="pdlg-modal-actions"><button id="pdlg-cancel" class="pdlg-btn">Cancel</button><button id="pdlg-sanitize" class="pdlg-btn primary">Sanitize &amp; Send</button></div>
      <div class="pdlg-foot">Local scan • raw prompt is not sent to the extension or an external service</div>
    </div>`;
    document.documentElement.appendChild(overlay);

    overlay.querySelector('#pdlg-cancel').addEventListener('click', () => removeUI());
    overlay.querySelector('#pdlg-sanitize').addEventListener('click', () => {
      const current = getText(el);
      const currentMatches = window.PDLGScanner.scan(current);
      const currentSafe = window.PDLGScanner.rewritePlainText(current, currentMatches);
      if (!setInputValue(el, currentSafe)) {
        showToast('Could not safely update this editor. Use Copy safe version and paste manually.', 'warn');
        return;
      }
      updateStats({ sanitized: 1 });
      removeUI();
      bypassOnce = true;
      setTimeout(() => triggerSend(el), 120);
    });
  }

  function showToast(message, kind='warn') {
    document.getElementById('pdlg-toast')?.remove();
    const t = document.createElement('div'); t.id='pdlg-toast'; t.className=`pdlg-toast ${kind}`; t.innerHTML=message;
    document.documentElement.appendChild(t);
    setTimeout(()=>t.remove(), 3500);
  }

  async function processSend(el, source) {
    if (!settings.enabled || bypassOnce) return true;
    const textRaw = getText(el);
    if (!textRaw.trim()) return true;

    const text = normalizeForDetection(textRaw);
    const matches = window.PDLGScanner.scan(text);

    // Scan locally first. The contextual model is an optional LOCAL supplement.
    if (settings.contextualEnabled && !bypassOnce) {
      showToast('<strong>◌ Local contextual scan</strong><div>Checking ambiguous sensitive content on this device…</div>', 'warn');
      const contextual = await runContextualScan(text);
      if (contextual.ok) {
        const merged = mergeContextualFindings(text, matches, contextual.findings);
        return finalizeSend(el, textRaw, text, merged, source, true);
      }
      showToast('<strong>⚠ Contextual layer unavailable</strong><div>Continuing with deterministic local rules.</div>', 'warn');
    }
    return finalizeSend(el, textRaw, text, matches, source, false);
  }

  function finalizeSend(el, originalText, normalizedText, matches, source, usedContext) {
    updateStats({ scanned: 1, flagged: matches.length, highRisk: matches.filter(m=>m.rule.risk==='high').length });
    if (!matches.length) return true;

    const safeText = window.PDLGScanner.rewritePlainText(normalizedText, matches);
    if (settings.mode === 'auto_sanitize') {
      if (!setInputValue(el, safeText)) {
        makeOverlay(el, matches, safeText);
        return false;
      }
      updateStats({ sanitized: 1 });
      bypassOnce = true;
      setTimeout(() => triggerSend(el), 120);
      showToast(`<strong>✓ Sanitized locally</strong><div>${matches.length} sensitive span(s) removed${usedContext ? ' • contextual layer used' : ''} before sending.</div>`, 'safe');
      return false;
    }

    const hardBlock = settings.mode === 'block';
    makeOverlay(el, matches, safeText, hardBlock);
    if (hardBlock) updateStats({ blocked: 1 });
    return false;
  }

  function triggerSend(el) {
    const button = getSendButton(el?.closest('form') || null);
    if (button) { bypassOnce = true; button.click(); return; }
    bypassOnce = true;
    const ev = new KeyboardEvent('keydown', { key: 'Enter', code: 'Enter', bubbles: true, cancelable: true });
    el.dispatchEvent(ev);
  }

  function isOurSendButton(target) {
    if (!(target instanceof Element)) return false;
    return ADAPTER.sends.some(selector => target.closest(selector));
  }

  // Capture both click and Enter. Restrict button matching to known site selectors so we don't break unrelated UI.
  document.addEventListener('click', e => {
    if (bypassOnce) { bypassOnce = false; return; }
    if (!isOurSendButton(e.target)) return;
    const button = e.target.closest('button,[role="button"],input[type="submit"]');
    const form = button?.closest('form') || null;
    const el = getEditor(form?.querySelector?.(ADAPTER.editors.join(',')) || null);
    if (!el) return;
    e.preventDefault(); e.stopImmediatePropagation();
    processSend(el, 'click').then(allow => { if (allow) { bypassOnce = true; triggerSend(el); } });
  }, true);

  document.addEventListener('keydown', e => {
    if (bypassOnce) { bypassOnce = false; return; }
    if (e.key !== 'Enter' || e.shiftKey || e.ctrlKey || e.metaKey || e.altKey) return;
    const active = e.target instanceof Element && isEditable(e.target) ? e.target : null;
    const el = getEditor(active);
    if (!el || active && !isEditable(active)) return;
    e.preventDefault(); e.stopImmediatePropagation();
    processSend(el, 'enter').then(allow => { if (allow) { bypassOnce = true; triggerSend(el); } });
  }, true);

  // Form-based apps (including some transitional ChatGPT builds).
  document.addEventListener('submit', e => {
    if (bypassOnce) { bypassOnce = false; return; }
    const form = e.target instanceof HTMLFormElement ? e.target : null;
    const el = getEditor(form?.querySelector?.(ADAPTER.editors.join(',')) || null);
    if (!el) return;
    e.preventDefault(); e.stopImmediatePropagation();
    processSend(el, 'submit').then(allow => { if (allow) { bypassOnce = true; triggerSend(el); } });
  }, true);

  document.addEventListener('input', e => {
    if (!settings.enabled || !isEditable(e.target)) return;
    const el = e.target;
    const text = getText(el);
    if (inputCache.get(el) === text) return;
    inputCache.set(el, text);
    const matches = window.PDLGScanner.scan(text);
    if (!matches.length) return;
    const high = matches.filter(m => m.rule.risk === 'high').length;
    showToast(`<strong>⚠ ${matches.length} sensitive span(s)</strong><div>${high} high risk • local scan</div>`, 'warn');
  }, true);

  chrome.storage.local.get({ ...DEFAULTS, contextualEnabled: false }, state => { settings = { ...DEFAULTS, contextualEnabled: !!state.contextualEnabled, ...state, stats: { ...DEFAULTS.stats, ...(state.stats || {}) } }; });
  chrome.storage.onChanged.addListener(changes => {
    if (changes.enabled) settings.enabled = !!changes.enabled.newValue;
    if (changes.mode) settings.mode = changes.mode.newValue || settings.mode;
    if (changes.contextualEnabled) settings.contextualEnabled = !!changes.contextualEnabled.newValue;
  });
})();
