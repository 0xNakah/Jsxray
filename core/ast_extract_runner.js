/**
 * ast_extract_runner.js — AST v6 JS Parameter Extraction Engine
 *
 * Reads raw JS source from stdin, writes JSON to stdout:
 *   { params: [{value, source}], endpoints: [], error: null }
 *
 * v6 changes vs v5:
 *   - Single walk.simple() pass (was 3 passes: buildAliasMap + callSitePositions + extraction)
 *   - callSitePositions Set replaced with a WeakSet populated inside CallExpression visitor
 *   - Babel root normalisation: File → File.program before walking
 *   - Walker extended for Babel node types: StringLiteral, ObjectProperty
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
  // Extend walker for Babel-parsed AST node types so both Acorn and Babel
  // trees can be traversed without crashing.
  walk.base.File           = (node, st, c) => c(node.program, st);
  walk.base.StringLiteral  = walk.base.Literal;
  walk.base.ObjectProperty = walk.base.Property;
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
]);

const QUERY_MEMBER_ROOTS = /^(?:req|request|ctx|context)$/;
const QUERY_MEMBER_PROPS = /^(?:query|body|params|searchParams)$/;
const QUERY_SEED_NAMES   = /^(?:query|queryString|queryParams|searchParams|qs|urlParams|routeParams|params)$/i;
const QUERY_INIT_PROPS   = /^(?:query|queryString|queryParams|searchParams|qs|urlParams|params)$/i;
const PAYLOAD_ROOTS      = /^(?:body|payload|formBody|requestBody|postData|formData|data)$/i;
const PARAM_PROP_ROOTS   = /^(?:params|query|qs|searchParams|queryParams|urlParams|args|opts)$/i;
const REACT_STATE_HOOKS  = new Set(['useState', 'useReducer']);
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
    if (prop.type === 'SpreadElement') continue;
    const k = prop.key?.name ?? prop.key?.value;
    if (k && typeof k === 'string') keys.push(k);
  }
  return keys;
}

function foldToString(node, stringConsts) {
  if (!node) return null;
  if (node.type === 'Literal'       && typeof node.value === 'string') return node.value;
  if (node.type === 'StringLiteral' && typeof node.value === 'string') return node.value;
  if (node.type === 'Identifier' && stringConsts.has(node.name)) return stringConsts.get(node.name);
  return null;
}

const VALID_PARAM_RE = /^[a-zA-Z][a-zA-Z0-9_\-]{1,59}$/;
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
  if (str.length < 3 || str.length > 300) return false;
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
        plugins: ['jsx', 'typescript', 'decorators-legacy', 'classProperties'],
        errorRecovery: true,
      });
    } catch (_) {}
  }
  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Core extraction  —  single walk.simple() pass
// ─────────────────────────────────────────────────────────────────────────────

function extract(code) {
  const rawAst = tryParse(code);
  if (!rawAst) return {
    params: [], endpoints: [], error: 'parse_failed',
    meta: { queryAliases: [], urlParamAliases: [], payloadAliases: [], babelFallback: hasBabel() },
  };
  // Normalise: Babel returns a File wrapper, Acorn returns Program directly.
  const ast = rawAst.type === 'File' ? rawAst.program : rawAst;

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
  // WeakSet replaces the old callSitePositions prepass:
  // each CallExpression visitor registers its callee node here so
  // MemberExpression can skip callee nodes without a prior full-tree walk.
  const calleeNodes     = new WeakSet();

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
      if (prop.type === 'SpreadElement') {
        if (prop.argument?.type === 'ObjectExpression')
          extractObjectArgKeys(prop.argument, source + '_spread');
        continue;
      }
      if (!prop.key) continue;
      const k = prop.key.name ?? prop.key.value;
      if (!k) continue;
      if (['params', 'data', 'body'].includes(k) && prop.value?.type === 'ObjectExpression') {
        for (const pk of objectLiteralKeys(prop.value)) emit(pk, source + '_body');
      } else if (!FETCH_OPTION_KEYS.has(k)) {
        emit(k, source);
      }
      if (k === 'url' && prop.value?.type === 'Literal') emitEndpoint(prop.value.value);
    }
  }

  // ── Single pass ───────────────────────────────────────────────────────────
  walk.simple(ast, {

    // ── Alias + string-const discovery (was buildAliasMap) ──────────────────
    VariableDeclarator(node) {
      const { id, init } = node;
      if (!init) return;

      if (id?.type === 'Identifier' && init.type === 'Literal' && typeof init.value === 'string') {
        stringConsts.set(id.name, init.value);
      }

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

      // Object.assign(…, req.query, …) or Object.assign(…, existingAlias, …)
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
      // Register callee so MemberExpression visitor can skip it (replaces
      // the old callSitePositions prepass).
      if (node.callee) calleeNodes.add(node.callee);

      const name = calleeName(node.callee);
      const args = node.arguments;
      if (!args.length) return;

      if (name && NET_CALLS.has(name)) {
        const first = args[0];
        if (first.type === 'Literal' && typeof first.value === 'string') {
          emitEndpoint(first.value);
          for (const p of extractQS(first.value)) emit(p, 'net_call_qs');
        }
        if (first.type === 'TemplateLiteral') {
          for (const quasi of first.quasis) {
            const raw = quasi.value.cooked ?? quasi.value.raw ?? '';
            for (const m of raw.matchAll(/[?&]([a-zA-Z][a-zA-Z0-9_\-]{1,39})=/g))
              emit(m[1], 'template_qs');
          }
        }
        for (const arg of args) extractObjectArgKeys(arg, 'net_arg');
      }

      if (name === 'Object.assign')
        for (const arg of args)
          if (arg.type === 'ObjectExpression')
            for (const k of objectLiteralKeys(arg)) emit(k, 'object_assign');

      if (node.callee.type === 'Identifier' && REACT_STATE_HOOKS.has(node.callee.name)) {
        if (args[0]?.type === 'ObjectExpression')
          for (const k of objectLiteralKeys(args[0])) emit(k, 'react_state');
      }

      if (node.callee.type !== 'MemberExpression') return;

      const method  = node.callee.property?.name;
      const objNode = node.callee.object;
      const objName = objNode?.type === 'Identifier' ? objNode.name : null;

      // URLSearchParams / query alias .get/.set/.append
      const isSP = (
        (objName && (QUERY_SEED_NAMES.test(objName) || urlParamAliases.has(objName))) ||
        objNode?.type === 'NewExpression' ||
        (objName && queryAliases.has(objName))
      );
      if (isSP && method && SP_METHODS.has(method)) {
        const [keyArg] = args;
        if (keyArg?.type === 'Literal' && typeof keyArg.value === 'string')
          emit(keyArg.value, 'searchparam_call');
        else if (keyArg?.type === 'Identifier') {
          const folded = foldToString(keyArg, stringConsts);
          if (folded) emit(folded, 'searchparam_dynamic');
        }
      }

      // FormData.append
      if (method === 'append' && /^(?:form|fd|formData|body|payload)$/i.test(objName ?? '')) {
        const [keyArg] = args;
        if (keyArg?.type === 'Literal' && typeof keyArg.value === 'string')
          emit(keyArg.value, 'formdata_append');
        else if (keyArg?.type === 'Identifier') {
          const folded = foldToString(keyArg, stringConsts);
          if (folded) emit(folded, 'formdata_dynamic');
        }
      }

      // JSON.stringify({ … })
      if (objName === 'JSON' && method === 'stringify' && args[0]?.type === 'ObjectExpression')
        for (const k of objectLiteralKeys(args[0])) emit(k, 'json_stringify');

      // qs.stringify / querystring.stringify
      if (['qs', 'querystring'].includes(objName ?? '') && method === 'stringify' &&
          args[0]?.type === 'ObjectExpression')
        for (const k of objectLiteralKeys(args[0])) emit(k, 'qs_stringify');

      // Vue.$set(obj, 'key', val)
      if (method === '$set' && args[1]?.type === 'Literal' && typeof args[1].value === 'string')
        emit(args[1].value, 'vue_set');
    },

    // ── URLSearchParams constructor: new URLSearchParams({ key: val }) ────────
    NewExpression(node) {
      if (node.callee?.type !== 'Identifier' || node.callee.name !== 'URLSearchParams') return;
      if (node.arguments[0]?.type !== 'ObjectExpression') return;
      for (const k of objectLiteralKeys(node.arguments[0]))
        emit(k, 'urlsearchparams_ctor');
    },

    // ── Property reads: req.query.x, alias.x, payload.x, body['x'] ───────────
    MemberExpression(node) {
      // Skip nodes that are the callee of a CallExpression — these were
      // registered by the CallExpression visitor above, replacing the old
      // dedicated callSitePositions prepass.
      if (calleeNodes.has(node)) return;

      const propName = node.computed
        ? (node.property?.type === 'Literal'
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
        if (queryAliases.has(objName)) return emit(propName, 'alias_member_read');
        if (payloadAliases.has(objName) || PAYLOAD_ROOTS.test(objName))
          return emit(propName, 'payload_member_read');
        if (PARAM_PROP_ROOTS.test(objName)) return emit(propName, 'param_prop_read');
      }

      if (node.computed && node.object?.type === 'Identifier') {
        const objName = node.object.name;
        if (/^(?:body|payload|data|form|req)$/i.test(objName))
          return emit(propName, 'body_bracket_read');
        if (PARAM_PROP_ROOTS.test(objName))
          return emit(propName, 'param_dynamic_key');
      }
    },

    // ── Bracket assignment: params['key'] = val ───────────────────────────────
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

    // Babel StringLiteral — emitted for JSX/TS-parsed trees
    StringLiteral(node) {
      if (typeof node.value !== 'string') return;
      if (!looksLikeRoutePath(node.value)) return;
      for (const name of extractRouteParams(node.value))
        emit(name, 'route_path_param_jsx');
    },
  });

  // Flush destructured params collected during VariableDeclarator visits
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
  const result = extract(input);
  process.stdout.write(JSON.stringify(result));
});
