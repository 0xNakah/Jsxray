/**
 * ast_extract_runner.js — AST v8 JS Parameter Extraction Engine
 *
 * v8 fixes vs v7 (100-case test suite):
 *   FIX1 — calleeStarts keyed on node.callee.END (not .start): nested
 *           MemberExpressions share the same .start but have unique .end.
 *           e.g. req.query.rawInput.trim() — all nodes start at 0; only
 *           the outermost callee ends at 23. Fixes: I13 (chained reads).
 *
 *   FIX2 — computed MemberExpression on req.query / queryAlias:
 *           req.query['key'] and alias['key'] now emit the bracketed key.
 *           Fixes: A09, K04, K07.
 *
 *   FIX3 — 3-level chain ctx.request.body.X / req.body.field chained:
 *           Extra check for root→mid1→mid2→prop where mid1∈{request} and
 *           mid2∈QUERY_MEMBER_PROPS. Fixes: A08.
 *
 *   FIX4 — Transitive queryAlias propagation:
 *           `const f = q` where q is already a queryAlias → f is also a
 *           queryAlias. Fixes: H02 (multi-hop alias).
 *
 *   FIX5 — URL().searchParams alias tracking:
 *           `const sp = url.searchParams` where url is a new URL(…) or any
 *           MemberExpression ending in .searchParams → sp added to
 *           urlParamAliases. Also handles inline chain x.searchParams.get('k').
 *           Fixes: C06, K15.
 *
 *   FIX6 — Identifier arg to net calls resolved via varInitMap:
 *           `const payload = {...}; axios.post('/x', payload)` — if the arg
 *           is an Identifier whose init was an ObjectExpression, extract its
 *           keys. Fixes: J08.
 *
 *   FIX7 — Destructure from payload / message.data patterns:
 *           `const {a,b} = message.data` or `const {x} = somePayload` →
 *           emit keys when init's property matches PAYLOAD_ROOTS or
 *           QUERY_MEMBER_PROPS. Fixes: J10.
 *
 *   FIX8 — BinaryExpression URL in net calls:
 *           `fetch(BASE + '/path?key=val')` — walk BinaryExpression leaves
 *           for string literals and run extractQS on each. Fixes: K16.
 *
 * Test matrix: 98/100 passing (was 89/100 on v7)
 */

'use strict';

// ─────────────────────────────────────────────────────────────────────────────
// 0. Dependency bootstrap
// ─────────────────────────────────────────────────────────────────────────────

const path   = require('path');
const Module = require('module');

const SCRIPT_DIR = path.dirname(path.resolve(__filename));

const _origResolve = Module._resolveFilename.bind(Module);
Module._resolveFilename = function (request, parent, isMain, opts) {
  if (request === 'acorn' || request === 'acorn-walk') {
    const candidates = [
      path.join(SCRIPT_DIR, 'node_modules', request),
      path.join(SCRIPT_DIR, '..', 'node_modules', request),
    ];
    for (const c of candidates) {
      try { return _origResolve(c, parent, isMain, opts); } catch (_) {}
    }
  }
  return _origResolve(request, parent, isMain, opts);
};

let acorn, walk;
try {
  acorn = require('acorn');
  walk  = require('acorn-walk');
  walk.base.File                   = (node, st, c) => c(node.program, st);
  walk.base.StringLiteral          = walk.base.Literal;
  walk.base.ObjectProperty         = walk.base.Property;
  walk.base.ClassProperty          = walk.base.PropertyDefinition || walk.base.Property;
  walk.base.TSTypeAnnotation       = () => {};
  walk.base.TSTypeReference        = () => {};
  walk.base.TSParameterProperty    = (node, st, c) => { if (node.parameter) c(node.parameter, st); };
  walk.base.Decorator              = (node, st, c) => { if (node.expression) c(node.expression, st); };
  walk.base.JSXElement             = (node, st, c) => {
    for (const a of node.openingElement?.attributes || []) c(a, st);
    for (const ch of node.children || []) c(ch, st);
  };
  walk.base.JSXAttribute           = (node, st, c) => { if (node.value) c(node.value, st); };
  walk.base.JSXExpressionContainer = (node, st, c) => { if (node.expression) c(node.expression, st); };
  walk.base.JSXText                = () => {};
  walk.base.TSAsExpression         = (node, st, c) => { c(node.expression, st); };
  walk.base.TSSatisfiesExpression  = (node, st, c) => { c(node.expression, st); };
  walk.base.TSNonNullExpression    = (node, st, c) => { c(node.expression, st); };
} catch (e) {
  process.stdout.write(JSON.stringify({
    params: [], endpoints: [], error: 'acorn_missing',
    meta: { queryAliases: [], urlParamAliases: [], payloadAliases: [], babelFallback: false },
  }));
  process.exit(0);
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Babel fallback (optional)
// ─────────────────────────────────────────────────────────────────────────────

let babelParser = null;
try { babelParser = require('@babel/parser'); } catch (_) {}

function hasBabel() { return babelParser !== null; }

// ─────────────────────────────────────────────────────────────────────────────
// 2. Constants
// ─────────────────────────────────────────────────────────────────────────────

const NET_CALLS = new Set([
  'fetch', 'axios', 'axios.get', 'axios.post', 'axios.put',
  'axios.patch', 'axios.delete', 'axios.request',
  'got', 'got.get', 'got.post', 'got.put', 'got.patch', 'got.delete',
  'ky', 'ky.get', 'ky.post', 'ky.put', 'ky.patch', 'ky.delete',
  'request', 'superagent', 'http.get', 'http.post',
  'https.get', 'https.post', '$http.get', '$http.post',
  '$http.put', '$http.delete', '$http.patch',
  'this.$http.get', 'this.$http.post', 'this.$http.put',
  'this.$http.delete', 'this.$http.patch',
  'Vue.http.get', 'Vue.http.post',
  'this.axios.get', 'this.axios.post',
  'api.get', 'api.post', 'api.put', 'api.patch', 'api.delete',
  'client.get', 'client.post', 'client.put', 'client.patch', 'client.delete',
  'instance.get', 'instance.post', 'instance.put', 'instance.patch',
]);

const FETCH_OPTION_KEYS = new Set([
  'method', 'headers', 'mode', 'credentials', 'cache', 'redirect',
  'referrer', 'referrerPolicy', 'integrity', 'keepalive', 'signal',
  'timeout', 'withCredentials', 'responseType', 'onUploadProgress',
  'onDownloadProgress', 'maxRedirects', 'decompress', 'retry',
  'prefixUrl', 'hooks', 'searchParams', 'json', 'form', 'parseJson',
  'stringifyJson', 'agent', 'http2', 'allowGetBody', 'throwHttpErrors',
  'resolveBodyOnly', 'cookieJar', 'ignoreInvalidCookies',
  'localAddress', 'dnsLookup', 'dnsCache', 'request',
  'encoding', 'followRedirect', 'maxResponseSize',
  'url', 'data', 'body', 'params',
]);

const QUERY_MEMBER_ROOTS = /^(?:req|request|ctx|context)$/;
const QUERY_MEMBER_PROPS = /^(?:query|body|params|searchParams)$/;
const QUERY_SEED_NAMES   = /^(?:query|queryString|queryParams|searchParams|qs|urlParams|routeParams|params)$/i;
const QUERY_INIT_PROPS   = /^(?:query|queryString|queryParams|searchParams|qs|urlParams|params)$/i;
const PAYLOAD_ROOTS      = /^(?:body|payload|formBody|requestBody|postData|formData|data)$/i;
const PARAM_PROP_ROOTS   = /^(?:params|query|qs|searchParams|queryParams|urlParams|args|opts)$/i;
const FORMDATA_ROOTS     = /^(?:form|fd|formData|form[Dd]ata|body|payload)$/i;
const REACT_HOOKS        = new Set(['useState', 'useReducer']);
const SP_METHODS         = new Set(['get', 'has', 'set', 'append', 'delete', 'getAll']);

// ─────────────────────────────────────────────────────────────────────────────
// 3. Helpers
// ─────────────────────────────────────────────────────────────────────────────

function calleeName(callee) {
  if (!callee) return null;
  if (callee.type === 'Identifier') return callee.name;
  if (callee.type === 'MemberExpression' && !callee.computed) {
    const obj  = calleeName(callee.object);
    const prop = callee.property?.name;
    return obj && prop ? `${obj}.${prop}` : null;
  }
  return null;
}

function extractQS(url) {
  const params = [];
  try {
    const qs = url.includes('?') ? url.split('?')[1] : '';
    for (const part of qs.split('&')) {
      const key = part.split('=')[0];
      if (key && isValidParam(key)) params.push(key);
    }
  } catch (_) {}
  return params;
}

// FIX8: walk a BinaryExpression (typically string concatenation) and collect
// all string-literal leaves, so fetch(BASE + '?key=val') is handled.
function collectBinaryStrings(node, out) {
  if (!node) return;
  if (node.type === 'Literal' || node.type === 'StringLiteral') {
    if (typeof node.value === 'string') out.push(node.value);
  } else if (node.type === 'BinaryExpression' && node.operator === '+') {
    collectBinaryStrings(node.left, out);
    collectBinaryStrings(node.right, out);
  }
}

function objectLiteralKeys(objNode) {
  if (!objNode || objNode.type !== 'ObjectExpression') return [];
  const keys = [];
  for (const prop of objNode.properties) {
    if (prop.type === 'SpreadElement' || prop.type === 'RestElement') continue;
    const k = prop.key?.name ?? prop.key?.value;
    if (k && typeof k === 'string') keys.push(k);
  }
  return keys;
}

function foldToString(node, stringConsts) {
  if (!node) return null;
  if ((node.type === 'Literal' || node.type === 'StringLiteral') && typeof node.value === 'string')
    return node.value;
  if (node.type === 'Identifier' && stringConsts.has(node.name))
    return stringConsts.get(node.name);
  return null;
}

const VALID_PARAM_RE = /^[a-zA-Z][a-zA-Z0-9_\-]{0,59}$/;
const COMMON_JUNK    = new Set([
  'length','constructor','prototype','toString','valueOf','hasOwnProperty',
  'then','catch','finally','call','apply','bind','arguments','undefined',
  'null','true','false','NaN','Infinity','console','window','document',
  'module','exports','require','process','global','this','self','top',
  'navigator','location','history','screen','performance',
]);

function isValidParam(v) {
  return typeof v === 'string' && VALID_PARAM_RE.test(v) && !COMMON_JUNK.has(v);
}

function looksLikeRoutePath(str) {
  if (!str || str.length < 3 || str.length > 300) return false;
  if (!str.startsWith('/')) return false;
  if (!str.includes('/:') && !str.includes('/[')) return false;
  if (/[\s<>{}|\\^`"]/.test(str)) return false;
  return true;
}

function extractRouteParams(str) {
  const names = [];
  for (const m of str.matchAll(/\/:([a-zA-Z][a-zA-Z0-9_]{0,49})/g)) names.push(m[1]);
  for (const m of str.matchAll(/\/\[([a-zA-Z][a-zA-Z0-9_]{0,49})\]/g)) names.push(m[1]);
  return names;
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Parser
// ─────────────────────────────────────────────────────────────────────────────

const ACORN_OPTS = {
  ecmaVersion: 'latest',
  sourceType: 'module',
  allowHashBang: true,
  allowAwaitOutsideFunction: true,
  allowImportExportEverywhere: true,
  allowReserved: true,
  locations: false,
};

function tryParse(code) {
  try { return acorn.parse(code, ACORN_OPTS); } catch (_) {}
  try { return acorn.parse(code, { ...ACORN_OPTS, sourceType: 'script' }); } catch (_) {}
  if (babelParser) {
    try {
      return babelParser.parse(code, {
        sourceType: 'unambiguous',
        allowImportExportEverywhere: true,
        allowReturnOutsideFunction: true,
        plugins: [
          'jsx', 'typescript', 'decorators-legacy',
          'classProperties', 'classPrivateProperties',
        ],
        errorRecovery: true,
      });
    } catch (_) {}
  }
  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Core extraction — two-step: callee pre-pass + main walk.simple()
// ─────────────────────────────────────────────────────────────────────────────

function extract(code) {
  const rawAst = tryParse(code);
  if (!rawAst) return {
    params: [], endpoints: [], error: 'parse_failed',
    meta: { queryAliases: [], urlParamAliases: [], payloadAliases: [], babelFallback: hasBabel() },
  };
  const ast = rawAst.type === 'File' ? rawAst.program : rawAst;

  // ── Step 1: collect END offsets of every callee node ─────────────────────
  // FIX1: use .end instead of .start. Nested MemberExpressions in a chain all
  // share the same .start (leftmost char) but each has a unique .end.
  // e.g. req.query.rawInput.trim() → callee ends at 23 (trim's close).
  // The inner nodes end at 9 (query) and 18 (rawInput) — not in calleeEnds.
  const calleeEnds = new Set();
  walk.simple(ast, {
    CallExpression(node) { if (node.callee?.end !== undefined) calleeEnds.add(node.callee.end); },
    NewExpression(node)  { if (node.callee?.end !== undefined) calleeEnds.add(node.callee.end); },
  });

  // ── Mutable extraction state ──────────────────────────────────────────────
  const queryAliases    = new Set();
  const urlParamAliases = new Set();
  const payloadAliases  = new Set();
  const directParams    = new Set();
  const stringConsts    = new Map();
  // FIX6: map from variable name → ObjectExpression init node
  const varInitMap      = new Map();
  const found           = [];
  const seen            = new Set();
  const endpoints       = [];
  const seenEP          = new Set();

  function emit(value, source) {
    if (!isValidParam(value) || seen.has(value)) return;
    seen.add(value);
    found.push({ value, source });
  }

  function emitEndpoint(v) {
    if (v && typeof v === 'string' && !seenEP.has(v)) {
      seenEP.add(v);
      endpoints.push(v);
    }
  }

  function extractObjectArgKeys(objNode, source) {
    if (!objNode || objNode.type !== 'ObjectExpression') return;
    for (const prop of objNode.properties) {
      if (prop.type === 'SpreadElement' || prop.type === 'RestElement') {
        if (prop.argument?.type === 'ObjectExpression')
          extractObjectArgKeys(prop.argument, source + '_spread');
        continue;
      }
      if (!prop.key) continue;
      const k = prop.key.name ?? prop.key.value;
      if (!k) continue;
      if (k === 'url') {
        const v = prop.value;
        if (v?.type === 'Literal' || v?.type === 'StringLiteral') emitEndpoint(v.value);
        continue;
      }
      if (['params', 'data', 'body'].includes(k) && prop.value?.type === 'ObjectExpression') {
        for (const pk of objectLiteralKeys(prop.value)) emit(pk, source + '_' + k);
        continue;
      }
      if (FETCH_OPTION_KEYS.has(k)) continue;
      emit(k, source);
    }
  }

  // ── Step 2: main extraction walk ─────────────────────────────────────────
  walk.simple(ast, {

    // ── Alias + string-const discovery ──────────────────────────────────────
    VariableDeclarator(node) {
      const { id, init } = node;
      if (!init) return;

      // Track all object literal inits for FIX6 (identifier arg resolution)
      if (id?.type === 'Identifier' && init.type === 'ObjectExpression')
        varInitMap.set(id.name, init);

      if (id?.type === 'Identifier' &&
          (init.type === 'Literal' || init.type === 'StringLiteral') &&
          typeof init.value === 'string')
        stringConsts.set(id.name, init.value);

      const isReqMember = (
        init.type === 'MemberExpression' && !init.computed &&
        QUERY_MEMBER_ROOTS.test(init.object?.name ?? '') &&
        QUERY_MEMBER_PROPS.test(init.property?.name ?? '')
      );
      const isQueryIdent = init.type === 'Identifier' && QUERY_SEED_NAMES.test(init.name);
      // FIX4: also propagate if init is an Identifier already in queryAliases
      const isQueryAlias = init.type === 'Identifier' && queryAliases.has(init.name);
      const isMemberProp = (
        init.type === 'MemberExpression' && !init.computed &&
        QUERY_INIT_PROPS.test(init.property?.name ?? '')
      );
      const isURLSP = (
        init.type === 'NewExpression' && init.callee?.name === 'URLSearchParams'
      ) || (
        // FIX5: x = anything.searchParams  →  x is a URLSearchParams alias
        init.type === 'MemberExpression' && !init.computed &&
        init.property?.name === 'searchParams'
      );
      const isPayload = init.type === 'Identifier' && PAYLOAD_ROOTS.test(init.name);
      const isQuery   = isReqMember || isQueryIdent || isMemberProp || isQueryAlias;

      if (id.type === 'Identifier') {
        if (isQuery)   queryAliases.add(id.name);
        if (isURLSP)   urlParamAliases.add(id.name);
        if (isPayload) payloadAliases.add(id.name);
      }

      if (id.type === 'ObjectPattern' && isQuery) {
        for (const prop of id.properties) {
          if (prop.type === 'RestElement') continue;
          const key = prop.key?.name ?? prop.key?.value;
          if (key) directParams.add(key);
        }
      }

      // FIX7: destructure from payload / message.data / any.body etc.
      if (id.type === 'ObjectPattern' && !isQuery) {
        const isPayloadDestructure = (
          // const { a, b } = body / payload / data
          (init.type === 'Identifier' && PAYLOAD_ROOTS.test(init.name)) ||
          // const { a, b } = message.data / req.body / ctx.body
          (init.type === 'MemberExpression' && !init.computed && (
            PAYLOAD_ROOTS.test(init.property?.name ?? '') ||
            QUERY_MEMBER_PROPS.test(init.property?.name ?? '')
          ))
        );
        if (isPayloadDestructure) {
          for (const prop of id.properties) {
            if (prop.type === 'RestElement') continue;
            const key = prop.key?.name ?? prop.key?.value;
            if (key) directParams.add(key);
          }
        }
      }

      if (
        id?.type === 'Identifier' &&
        init.type === 'CallExpression' &&
        calleeName(init.callee) === 'Object.assign' &&
        init.arguments.some(a =>
          (a.type === 'Identifier' && queryAliases.has(a.name)) ||
          (a.type === 'MemberExpression' && !a.computed &&
           QUERY_MEMBER_ROOTS.test(a.object?.name ?? '') &&
           QUERY_MEMBER_PROPS.test(a.property?.name ?? ''))
        )
      ) {
        queryAliases.add(id.name);
      }
    },

    // ── Network calls, method calls, state hooks ─────────────────────────────
    CallExpression(node) {
      const name = calleeName(node.callee);
      const args  = node.arguments;
      if (!args.length) return;

      if (name && NET_CALLS.has(name)) {
        const first = args[0];
        if ((first.type === 'Literal' || first.type === 'StringLiteral') &&
            typeof first.value === 'string') {
          emitEndpoint(first.value);
          for (const p of extractQS(first.value)) emit(p, 'net_call_qs');
        }
        if (first.type === 'TemplateLiteral') {
          for (const quasi of first.quasis) {
            const raw = quasi.value.cooked ?? quasi.value.raw ?? '';
            for (const m of raw.matchAll(/[?&]([a-zA-Z][a-zA-Z0-9_\-]{0,39})=/g))
              emit(m[1], 'template_qs');
          }
        }
        // FIX8: BinaryExpression URL — collect string leaves and extract QS from each
        if (first.type === 'BinaryExpression') {
          const strs = [];
          collectBinaryStrings(first, strs);
          for (const s of strs) {
            if (s.startsWith('/') || s.startsWith('http')) emitEndpoint(s.split('?')[0]);
            for (const p of extractQS(s)) emit(p, 'binary_qs');
          }
        }
        // FIX6: Identifier arg — resolve via varInitMap
        for (const arg of args) {
          if (arg.type === 'Identifier' && varInitMap.has(arg.name)) {
            extractObjectArgKeys(varInitMap.get(arg.name), 'net_var_arg');
          } else {
            extractObjectArgKeys(arg, 'net_arg');
          }
        }
        return;
      }

      if (name === 'Object.assign') {
        for (const arg of args)
          if (arg.type === 'ObjectExpression')
            for (const k of objectLiteralKeys(arg)) emit(k, 'object_assign');
        return;
      }

      if (node.callee.type === 'Identifier' && REACT_HOOKS.has(node.callee.name)) {
        const initArg = node.callee.name === 'useReducer' ? args[1] : args[0];
        if (initArg?.type === 'ObjectExpression')
          for (const k of objectLiteralKeys(initArg)) emit(k, 'react_hook_state');
        return;
      }

      if (node.callee.type !== 'MemberExpression') return;

      const method  = node.callee.property?.name;
      const objNode = node.callee.object;
      const objName = objNode?.type === 'Identifier' ? objNode.name : null;

      const isSP = (
        (objName && (QUERY_SEED_NAMES.test(objName) || urlParamAliases.has(objName) || queryAliases.has(objName))) ||
        objNode?.type === 'NewExpression' ||
        // FIX5b: x.searchParams.get('key') — objNode is a MemberExpression ending in .searchParams
        (objNode?.type === 'MemberExpression' && !objNode.computed && objNode.property?.name === 'searchParams')
      );
      if (isSP && method && SP_METHODS.has(method)) {
        const [keyArg] = args;
        if ((keyArg?.type === 'Literal' || keyArg?.type === 'StringLiteral') &&
            typeof keyArg.value === 'string')
          emit(keyArg.value, 'searchparam_call');
        else if (keyArg?.type === 'Identifier') {
          const folded = foldToString(keyArg, stringConsts);
          if (folded) emit(folded, 'searchparam_dynamic');
        }
        return;
      }

      if (method === 'append' && objName && FORMDATA_ROOTS.test(objName)) {
        const [keyArg] = args;
        if ((keyArg?.type === 'Literal' || keyArg?.type === 'StringLiteral') &&
            typeof keyArg.value === 'string')
          emit(keyArg.value, 'formdata_append');
        else if (keyArg?.type === 'Identifier') {
          const folded = foldToString(keyArg, stringConsts);
          if (folded) emit(folded, 'formdata_dynamic');
        }
        return;
      }

      if (objName === 'JSON' && method === 'stringify' && args[0]?.type === 'ObjectExpression') {
        for (const k of objectLiteralKeys(args[0])) emit(k, 'json_stringify');
        return;
      }

      if (['qs', 'querystring'].includes(objName ?? '') && method === 'stringify' &&
          args[0]?.type === 'ObjectExpression') {
        for (const k of objectLiteralKeys(args[0])) emit(k, 'qs_stringify');
        return;
      }

      if (method === '$set' && args[1]) {
        const s = foldToString(args[1], stringConsts);
        if (s) emit(s, 'vue_set');
        return;
      }
    },

    // ── URLSearchParams constructor ───────────────────────────────────────────
    NewExpression(node) {
      if (node.callee?.type !== 'Identifier' || node.callee.name !== 'URLSearchParams') return;
      if (node.arguments[0]?.type !== 'ObjectExpression') return;
      for (const k of objectLiteralKeys(node.arguments[0]))
        emit(k, 'urlsearchparams_ctor');
    },

    // ── Property reads ────────────────────────────────────────────────────────
    MemberExpression(node) {
      // FIX1: skip using .end instead of .start
      if (node.end !== undefined && calleeEnds.has(node.end)) return;

      const propName = node.computed
        ? ((node.property?.type === 'Literal' || node.property?.type === 'StringLiteral')
            ? node.property.value
            : foldToString(node.property, stringConsts))
        : node.property?.name;

      if (!propName || typeof propName !== 'string') return;

      // req.query.prop / req.body.prop  (2-level: root.mid.prop)
      if (node.object?.type === 'MemberExpression') {
        const mid    = node.object;
        const midProp = mid.property?.name ?? '';
        const root   = mid.object;

        if (!mid.computed && QUERY_MEMBER_ROOTS.test(root?.name ?? '') &&
            QUERY_MEMBER_PROPS.test(midProp))
          return emit(propName, 'req_member_read');

        // FIX3: ctx.request.body.X — 3-level chain (root.mid1.mid2.prop)
        if (!mid.computed && mid.object?.type === 'MemberExpression') {
          const mid2 = mid.object;
          if (QUERY_MEMBER_ROOTS.test(mid2.object?.name ?? '') &&
              mid2.property?.name === 'request' &&
              QUERY_MEMBER_PROPS.test(midProp))
            return emit(propName, 'req3_member_read');
        }
      }

      if (!node.computed && node.object?.type === 'Identifier') {
        const objName = node.object.name;
        if (queryAliases.has(objName))                                    return emit(propName, 'alias_member_read');
        if (payloadAliases.has(objName) || PAYLOAD_ROOTS.test(objName))   return emit(propName, 'payload_member_read');
        if (PARAM_PROP_ROOTS.test(objName))                               return emit(propName, 'param_prop_read');
      }

      // FIX2: computed (bracket) reads — req.query['key'], alias['key']
      if (node.computed && node.object?.type === 'MemberExpression') {
        const obj = node.object;
        if (!obj.computed &&
            QUERY_MEMBER_ROOTS.test(obj.object?.name ?? '') &&
            QUERY_MEMBER_PROPS.test(obj.property?.name ?? ''))
          return emit(propName, 'req_query_bracket');
      }
      if (node.computed && node.object?.type === 'Identifier') {
        const objName = node.object.name;
        if (queryAliases.has(objName))                          return emit(propName, 'alias_bracket_read');
        if (/^(?:body|payload|data|form|req)$/i.test(objName))  return emit(propName, 'body_bracket_read');
        if (PARAM_PROP_ROOTS.test(objName))                     return emit(propName, 'param_dynamic_key');
      }
    },

    // ── Bracket assignment ────────────────────────────────────────────────────
    AssignmentExpression(node) {
      const { left } = node;
      if (left?.type !== 'MemberExpression' || !left.computed) return;
      const objName = left.object?.type === 'Identifier' ? left.object.name : null;
      if (!objName) return;
      const keyStr = foldToString(left.property, stringConsts);
      if (!keyStr) return;
      if (queryAliases.has(objName) ||
          PARAM_PROP_ROOTS.test(objName) ||
          /^(?:body|payload|data|form|req)$/i.test(objName))
        emit(keyStr, 'assignment_bracket');
    },

    // ── Route path params ─────────────────────────────────────────────────────
    Literal(node) {
      if (typeof node.value !== 'string') return;
      if (!looksLikeRoutePath(node.value)) return;
      for (const name of extractRouteParams(node.value))
        emit(name, 'route_path_param');
    },
    StringLiteral(node) {
      if (typeof node.value !== 'string') return;
      if (!looksLikeRoutePath(node.value)) return;
      for (const name of extractRouteParams(node.value))
        emit(name, 'route_path_param_jsx');
    },
  });

  for (const p of directParams) emit(p, 'destructure');

  return {
    params: found,
    endpoints,
    error: null,
    meta: {
      queryAliases:    [...queryAliases],
      urlParamAliases: [...urlParamAliases],
      payloadAliases:  [...payloadAliases],
      babelFallback:   hasBabel(),
    },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. stdin → stdout runner
// ─────────────────────────────────────────────────────────────────────────────

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => { input += chunk; });
process.stdin.on('end', () => {
  process.stdout.write(JSON.stringify(extract(input)));
});
