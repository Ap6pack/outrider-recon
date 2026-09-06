'use strict';
/*
 * Runtime regression check for outrider/web_static/app.js.
 *
 * `node --check` only catches syntax errors, so a helper that is *called* but
 * never *defined* (a ReferenceError at render time) shipped undetected — the
 * portal loaded, listed engagements, then threw "labelInput is not defined" the
 * moment any engagement view built a form. This harness loads app.js under a
 * minimal DOM stub, asserts every helper factory is defined, and actually runs
 * the render paths that build forms, so a missing runtime function fails CI.
 *
 * Dependency-free on purpose (no jsdom): CI runs offline and only guarantees a
 * Node binary. Run: `node tools/web_js_runtime_check.js`.
 */
const fs = require('fs');
const vm = require('vm');
const path = require('path');

const APP_JS = process.argv[2] || path.join(__dirname, '..', 'outrider', 'web_static', 'app.js');

// ---- Minimal DOM stub -------------------------------------------------------
function makeEl(tag) {
  return {
    tagName: String(tag || '').toUpperCase(),
    children: [],
    dataset: {},
    style: {},
    classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
    get firstChild() { return this.children[0] || null; },
    append(...nodes) { for (const n of nodes) if (n != null) this.children.push(n); },
    appendChild(n) { this.children.push(n); return n; },
    removeChild(n) { const i = this.children.indexOf(n); if (i >= 0) this.children.splice(i, 1); return n; },
    addEventListener() {},
    removeEventListener() {},
    setAttribute() {},
    removeAttribute() {},
    querySelector() { return null; },
    querySelectorAll() { return []; },
    focus() {},
    scrollIntoView() {},
  };
}

const byId = {};
globalThis.document = {
  getElementById(id) { return byId[id] || (byId[id] = makeEl('div')); },
  createElement(tag) { return makeEl(tag); },
  createTextNode(value) { return { nodeValue: String(value) }; },
  addEventListener() {},
};
globalThis.window = globalThis;
// Never resolves: keeps the app's bootstrap (loadSession/loadRuns) pending so it
// has no side effects during the synchronous checks below.
globalThis.fetch = function () { return new Promise(function () {}); };

// ---- Load app.js and expose its top-level helpers ---------------------------
const EXPORTS = [
  'text', 'button', 'kv', 'option', 'badge', 'card', 'records', 'labelInput', 'postTransition',
  'renderProgress', 'renderMilestones', 'renderScopeReview', 'renderGuidedAction', 'renderTransitionForm',
  'showImport', 'loadImportSources', 'createImport', 'materializeEngagement',
  'syncImportScope', 'syncImportTargetFromSource', 'applyImportSuggestion',
];
// ---- Assertions -------------------------------------------------------------
function fail(msg) { console.error('web js runtime check FAILED: ' + msg); process.exit(1); }
function isNode(x) { return x && typeof x === 'object' && Array.isArray(x.children); }
function expectNode(label, x) { if (!isNode(x)) fail(label + ' did not return a DOM node'); }

const src = fs.readFileSync(APP_JS, 'utf8')
  + '\n;globalThis.__webHelpers = { ' + EXPORTS.join(', ') + ' };\n';
try {
  vm.runInThisContext(src, { filename: 'app.js' });
} catch (err) {
  // A ReferenceError here means a helper is called/exported but never defined.
  fail('app.js failed to load (a called helper is likely undefined): ' + ((err && err.message) || err));
}

const H = globalThis.__webHelpers;

for (const name of EXPORTS) {
  if (typeof H[name] !== 'function') fail('helper is not defined: ' + name + '()');
}

try {
  // Pure DOM builders (the ones that were missing) must run and return a node.
  expectNode('labelInput', H.labelInput('Actor', document.createElement('input')));
  expectNode('badge', H.badge('allow'));
  expectNode('card', H.card('Current state', 'initialized'));
  expectNode('records(list)', H.records([{ a: 1 }, { b: 2 }]));
  expectNode('records([])', H.records([]));
  expectNode('kv', H.kv({ x: 1, y: null }));
  expectNode('renderProgress', H.renderProgress([{ label: 'Scope', status: 'current' }, { label: 'Discovery', status: 'pending' }]));
  expectNode('renderMilestones', H.renderMilestones({ scope_valid: true, verified_evidence_count: 0, request_count: 0, result_count: 0, unpromoted_candidate_count: 0, finding_count: 0 }));

  // The exact reported break: the guided "Review Scope" / transition forms.
  expectNode('renderScopeReview', H.renderScopeReview({ actor: 'op', target: 'example.com' }));
  expectNode('renderGuidedAction(review_scope)', H.renderGuidedAction({ actor: 'op', next_action: { id: 'review_scope', label: 'Review Scope', description: '' } }));
  expectNode('renderGuidedAction(transition)', H.renderGuidedAction({ actor: 'op', next_action: { id: 'begin_discovery', kind: 'transition', label: 'Begin Discovery', description: '' } }));

  // State-transition form exercises card() + labelInput() + option().
  expectNode('renderTransitionForm', H.renderTransitionForm({ current_state: 'initialized', allowed_transitions: [{ new_state: 'scoped', reason_required: false }] }));

  // Import flow: showImport toggles panels and kicks loadImportSources (fetch is stubbed pending).
  H.showImport();

  // Smart-prefill behavior: setting the target auto-fills in-scope as target + *.target.
  document.getElementById('import-target-domain').value = 'ex.com';
  H.syncImportScope();
  const scopeVal = document.getElementById('import-scope-in').value;
  if (scopeVal !== 'ex.com\n*.ex.com') fail('syncImportScope did not auto-fill scope (got: ' + JSON.stringify(scopeVal) + ')');
} catch (err) {
  fail((err && err.message) || String(err));
}

console.log('web js runtime check: OK (' + EXPORTS.length + ' helpers defined; form render paths ran without ReferenceError)');
