// Small shared helpers for the front door and the police dashboard (no framework, no build step).
import { icon } from './icons.js';

export const store = {
  get(k, d) { try { return localStorage.getItem(k) ?? d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* private mode */ } }
};
export const lang = { cur: store.get('veto.lang', (navigator.language || '').startsWith('ar') ? 'ar' : 'en') };
export function setLang(l) {
  lang.cur = l; store.set('veto.lang', l);
  document.documentElement.lang = l;
  document.documentElement.dir = l === 'ar' ? 'rtl' : 'ltr';
}
/** Pick the current language from an { en, ar } pair (or pass a plain string through). */
export const L = o => (o == null ? '' : typeof o === 'string' ? o : o[lang.cur] ?? o.en ?? '');

export function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else if (k === 'value') el.value = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat(Infinity)) if (c != null && c !== false) el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return el;
}
export const ic = name => icon(name);
export const fmtDate = s => (s ? new Date(s).toLocaleString(lang.cur === 'ar' ? 'ar-AE' : 'en-GB', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }) : '');
export const fmtNum = n => Number(n).toLocaleString(lang.cur === 'ar' ? 'ar-AE' : 'en-GB');

let toastTimer = null;
export function toast(text) {
  document.querySelector('.toast')?.remove();
  const t = h('div', { class: 'toast', role: 'status' }, text);
  document.body.append(t);
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.remove(), 3200);
}
