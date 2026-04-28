/**
 * ast_extract_runner.js — AST v7 JS Parameter Extraction Engine
 *
 * Reads raw JS source from stdin, writes JSON to stdout:
 *   { params: [{value, source}], endpoints: [], error: null }
 *
 * v7 changes vs v6 (single-pass):
 *   - Pre-pass callee offset Set replaces broken WeakSet same-pass approach
 *     → prevents method names (get/append/stringify) leaking as params
 *   - FORMDATA_ROOTS regex broadened (formData/fd/body aliases all matched)
 *   - VALID_PARAM_RE relaxed to {0,59} — single-char params (q, a) now valid
 *   - useReducer: now inspects args[1] for initial state object
 *   - axios({url,data}): 'url' suppressed from param output; extracted as endpoint
 *   - Early returns after stringify/SP/FormData handlers stop fallthrough leaks
 *   - Walker extended for Babel JSX/TS node types (Decorator, JSXElement,
 *     TSAsExpression, TSNonNullExpression, etc.)
 *   - Test matrix: 57/58 passing
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
  // Extend walker for both Acorn and Babel AST node types
  walk.base.File                  = (node, st, c) => c(node.program, st);
  walk.base.StringLiteral         = walk.base.Literal;
  walk.base.ObjectProperty        = walk.base.Property;
  walk.base.ClassProperty         = walk.base.PropertyDefinition || walk.base.Property;
  walk.base.TSTypeAnnotation      = () => {};
  walk.base.TSTypeReference       = () => {};
  walk.base.TSParameterProperty   = (node, st, c) => { if (node.parameter) c(node.parameter, st); };
  walk.base.Decorator             = (node, st, c) => { if (node.expression) c(node.expression, st); };
  walk.base.JSXElement            = (node, st, c) => {
    for (const a of node.openingElement?.attributes || []) c(a, st);
    for (const ch of node.children || []) c(ch, st);
  };
  walk.base.JSXAttribute          = (node, st, c) => { if (node.value) c(node.value, st); };
  walk.base.JSXExpressionContainer = (node, st, c) => { if (node.expression) c(node.expression, st); };
  walk.base.JSXText               = () => {};
  walk.base.TSAsExpression        = (node, st, c) => { c(node.expression, st); };
  walk.base.TSSatisfiesExpression = (node, st, c) => { c(node.expression, st); };
  walk.base.TSNonNullExpression   = (node, st, c) => { c(node.expression, st); };
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

// Suppress these keys when flattening top-level net-call config objects;
// 'url', 'data', 'body', 'params' are recursed into instead.
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
  // also suppress at top level — children are recursed into separately
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

// Relaxed to {0,59}: single-char params (q, a, p) are valid
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

  // ── Step 1: collect start offsets of every callee node ───────────────────
  // This lightweight pre-pass lets MemberExpression skip callee nodes without
  // relying on a WeakSet that can only be populated after the same-pass
  // CallExpression fires — which was the v6 bug.
  const calleeStarts = new Set();
  walk.simple(ast, {
    CallExpression(node) { if (node.callee?.start !== undefined) calleeStarts.add(node.callee.start); },
    NewExpression(node)  { if (node.callee?.start !== undefined) calleeStarts.add(node.callee.start); },
  });

  // ── Mutable extraction state ──────────────────────────────────────────────
  const queryAliases    = new Set();
  const urlParamAliases = new Set();
  const payloadAliases  = new Set();
  const directParams    = new Set();
  const stringConsts    = new Map();
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

  // Flatten top-level object keys for net-call config objects,
  // recursing into sub-keys: params / data / body.
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
        continue; // never emit 'url' as a param
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
      const isMemberProp = (
        init.type === 'MemberExpression' && !init.computed &&
        QUERY_INIT_PROPS.test(init.property?.name ?? '')
      );
      const isURLSP   = init.type === 'NewExpression' && init.callee?.name === 'URLSearchParams';
      const isPayload = init.type === 'Identifier' && PAYLOAD_ROOTS.test(init.name);
      const isQuery   = isReqMember || isQueryIdent || isMemberProp;

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

      // Network calls
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
        for (const arg of args) extractObjectArgKeys(arg, 'net_arg');
        return;
      }

      // Object.assign
      if (name === 'Object.assign') {
        for (const arg of args)
          if (arg.type === 'ObjectExpression')
            for (const k of objectLiteralKeys(arg)) emit(k, 'object_assign');
        return;
      }

      // React hooks: useState(init) / useReducer(reducer, init)
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

      // URLSearchParams / query alias: .get / .set / .append / .has
      const isSP = (
        (objName && (QUERY_SEED_NAMES.test(objName) || urlParamAliases.has(objName) || queryAliases.has(objName))) ||
        objNode?.type === 'NewExpression'
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
        return; // prevent fallthrough to generic member-read path
      }

      // FormData.append — broadened FORMDATA_ROOTS covers formData/fd/body
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

      // JSON.stringify({ … })
      if (objName === 'JSON' && method === 'stringify' && args[0]?.type === 'ObjectExpression') {
        for (const k of objectLiteralKeys(args[0])) emit(k, 'json_stringify');
        return;
      }

      // qs.stringify / querystring.stringify
      if (['qs', 'querystring'].includes(objName ?? '') && method === 'stringify' &&
          args[0]?.type === 'ObjectExpression') {
        for (const k of objectLiteralKeys(args[0])) emit(k, 'qs_stringify');
        return;
      }

      // Vue.$set(obj, 'key', val)
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
      // Skip callee nodes — their start offset was recorded in the pre-pass.
      if (node.start !== undefined && calleeStarts.has(node.start)) return;

      const propName = node.computed
        ? ((node.property?.type === 'Literal' || node.property?.type === 'StringLiteral')
            ? node.property.value
            : foldToString(node.property, stringConsts))
        : node.property?.name;

      if (!propName || typeof propName !== 'string') return;

      // req.query.prop / req.body.prop
      if (!node.computed && node.object?.type === 'MemberExpression' && !node.object.computed) {
        const root = node.object.object;
        const mid  = node.object.property;
        if (root?.type === 'Identifier' &&
            QUERY_MEMBER_ROOTS.test(root.name) &&
            QUERY_MEMBER_PROPS.test(mid?.name))
          return emit(propName, 'req_member_read');
      }

      if (!node.computed && node.object?.type === 'Identifier') {
        const objName = node.object.name;
        if (queryAliases.has(objName))                                    return emit(propName, 'alias_member_read');
        if (payloadAliases.has(objName) || PAYLOAD_ROOTS.test(objName))   return emit(propName, 'payload_member_read');
        if (PARAM_PROP_ROOTS.test(objName))                               return emit(propName, 'param_prop_read');
      }

      if (node.computed && node.object?.type === 'Identifier') {
        const objName = node.object.name;
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

    // ── Route path params: '/users/:id'  '/dashboard/[projectId]' ─────────────
    Literal(node) {
      if (typeof node.value !== 'string') return;
      if (!looksLikeRoutePath(node.value)) return;
      for (const name of extractRouteParams(node.value))
        emit(name, 'route_path_param');
    },
    StringLiteral(node) { // Babel AST
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
