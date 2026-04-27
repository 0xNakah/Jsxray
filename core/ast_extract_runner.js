/**
 * ast_extract_runner.js — AST v5 JS Parameter Extraction Engine
 *
 * Reads raw JS source from stdin, writes JSON to stdout:
 *   { params: [{value, confidence, source}], endpoints: [], error: null }
 *
 * Requires: acorn, acorn-walk  (npm install -g acorn acorn-walk)
 * Optional: @babel/parser     (npm install -g @babel/parser)
 *           Enables TypeScript, JSX, and error-recovery on minified bundles.
 *
 * Blind-spot fixes (v5.1):
 *   - Object.assign({}, { key: val }) param extraction
 *   - Spread object literal keys: fetch('/a', { ...opts, body: { secret: x } })
 *   - React useState initial object keys
 *   - Vue this.$http / this.$axios call detection
 *   - Dynamic computed string keys via string-constant folding
 *   - @babel/parser fallback for TS/JSX/minified parse failures
 *   - isValidParam floor raised to 2 chars (with q/s/v/t/id whitelist)
 *
 * v5.2:
 *   - Route path param extraction: /:param and /[param] patterns in string literals
 *     Covers Express, React Router, Next.js, Vue Router, and generic path strings.
 */

'use strict';

// ── Parser setup: acorn primary, babel fallback ───────────────────────────────

const acorn = require('acorn');
const walk  = require('acorn-walk');

let babelParser = null;
try { babelParser = require('@babel/parser'); } catch (_) {}

// ── Constants ─────────────────────────────────────────────────────────────────

const NET_CALLS = new Set([
  'fetch',
  'axios', 'axios.get', 'axios.post', 'axios.put', 'axios.delete', 'axios.patch',
  'got', 'got.get', 'got.post',
  'ky', 'ky.get', 'ky.post',
  'superagent', 'request',
  'http.get', 'http.post', 'https.get', 'https.post',
  '$.get', '$.post', '$.ajax',
  // Vue instance methods
  'this.$http.get', 'this.$http.post', 'this.$http.put', 'this.$http.delete',
  'this.$axios.get', 'this.$axios.post', 'this.$axios.put', 'this.$axios.delete',
]);

const FETCH_OPTION_KEYS = new Set([
  'method', 'headers', 'credentials', 'cache', 'mode', 'redirect', 'referrer',
  'referrerPolicy', 'integrity', 'keepalive', 'signal', 'window', 'url', 'baseURL',
  'responseType', 'timeout', 'auth', 'proxy', 'decompress',
  'onUploadProgress', 'onDownloadProgress', 'adapter', 'validateStatus',
  'transformRequest', 'transformResponse', 'withCredentials',
  'xsrfCookieName', 'xsrfHeaderName', 'maxRedirects', 'maxContentLength',
  'httpAgent', 'httpsAgent', 'cancelToken', 'socket', 'dispatcher', 'duplex',
  'params', 'data', 'body',
]);

const QUERY_MEMBER_ROOTS = /^(?:req|request|ctx|context)$/;
const QUERY_MEMBER_PROPS = /^(?:query|body|params|searchParams)$/;
const QUERY_SEED_NAMES   = /^(?:params|searchParams|query|urlParams|queryParams|searchparams|querystring)$/i;
const QUERY_INIT_PROPS   = /^(?:query|params|searchParams|body)$/i;
const PARAM_PROP_ROOTS   = /^(?:params|query|qs|searchParams|queryParams|urlParams|args|opts)$/i;
const PAYLOAD_ROOTS      = /^(?:payload|body|formBody|requestBody|postData|formValues|formFields)$/i;

// React hooks that accept an initial-state object whose keys are param names
const REACT_STATE_HOOKS = new Set(['useState', 'useReducer', 'useFormik', 'useForm']);

// Single-char params that are genuinely common and should pass the length floor
const SINGLE_CHAR_WHITELIST = new Set(['q', 's', 'v', 't', 'p', 'n', 'id']);

const JS_BUILTINS = new Set([
  'appendChild', 'removeChild', 'replaceChild', 'insertBefore', 'cloneNode',
  'innerHTML', 'outerHTML', 'innerText', 'textContent', 'nodeValue',
  'addEventListener', 'removeEventListener', 'dispatchEvent',
  'getAttribute', 'setAttribute', 'removeAttribute', 'hasAttribute',
  'querySelector', 'querySelectorAll', 'getElementById',
  'getElementsByClassName', 'getElementsByTagName',
  'classList', 'className', 'style', 'dataset',
  'getBoundingClientRect', 'getComputedStyle', 'scrollIntoView', 'scrollTo',
  'scrollTop', 'scrollLeft', 'offsetTop', 'offsetLeft', 'offsetWidth', 'offsetHeight',
  'clientWidth', 'clientHeight', 'naturalWidth', 'naturalHeight',
  'setTimeout', 'setInterval', 'clearTimeout', 'clearInterval',
  'requestAnimationFrame', 'cancelAnimationFrame',
  'preventDefault', 'stopPropagation', 'stopImmediatePropagation',
  'toString', 'valueOf', 'hasOwnProperty', 'isPrototypeOf', 'propertyIsEnumerable',
  'constructor', 'prototype', '__proto__',
  'JSON', 'Math', 'Object', 'Array', 'String', 'Number', 'Boolean', 'Symbol',
  'Promise', 'fetch', 'XMLHttpRequest', 'FormData', 'URLSearchParams', 'URL',
  'console', 'window', 'document', 'navigator', 'location', 'history',
  'localStorage', 'sessionStorage', 'indexedDB', 'crypto', 'performance',
  'handleClick', 'handleSubmit', 'handleChange', 'handleBlur', 'handleFocus',
  'handleKeyDown', 'handleKeyUp', 'handleMouseEnter', 'handleMouseLeave',
  'handleReset', 'handleToggle', 'handleSelect', 'handleDrop', 'handleDrag',
  'isLoading', 'isError', 'isActive', 'isDisabled', 'isVisible', 'isOpen', 'isMounted',
  'setLoading', 'setError', 'setActive', 'setVisible', 'setOpen', 'setData',
  'componentDidMount', 'componentDidUpdate', 'componentWillUnmount',
  'useEffect', 'useState', 'useRef', 'useMemo', 'useCallback', 'useContext', 'useReducer',
  'render', 'create', 'update', 'destroy', 'remove', 'reset', 'clear', 'close', 'open', 'toggle',
  'stringify', 'parse', 'assign', 'freeze', 'seal', 'keys', 'values', 'entries', 'fromEntries',
  'push', 'pop', 'shift', 'unshift', 'splice', 'slice', 'filter', 'map', 'reduce', 'reduceRight',
  'forEach', 'find', 'findIndex', 'includes', 'some', 'every', 'sort', 'reverse', 'flat', 'flatMap',
  'join', 'split', 'trim', 'trimStart', 'trimEnd', 'replace', 'replaceAll', 'match', 'matchAll',
  'test', 'exec', 'startsWith', 'endsWith', 'padStart', 'padEnd', 'repeat', 'charAt', 'charCodeAt',
  'then', 'catch', 'finally', 'resolve', 'reject', 'all', 'race', 'any', 'allSettled',
  'encode', 'decode', 'encodeURIComponent', 'decodeURIComponent', 'encodeURI', 'decodeURI',
  'emit', 'on', 'off', 'once', 'removeListener', 'addListener', 'prependListener',
  'error', 'warn', 'log', 'info', 'debug', 'table', 'group', 'groupEnd', 'time', 'timeEnd',
  'after', 'before', 'append', 'prepend', 'contains', 'matches', 'closest',
  'isActive', 'limitVal', 'pageNum', 'searchTerm', 'currentPage', 'activeTab', 'referrer',
  'isLoaded', 'hasError', 'showModal', 'hideModal', 'toggleMenu', 'nextPage', 'prevPage',
  'get', 'set', 'has', 'delete', 'getAll', 'append',
]);

// ── Route path param patterns ─────────────────────────────────────────────────
//
// Matches any string literal that looks like a URL path with named segments:
//   Express / React Router / Vue Router:  /:param_name
//   Next.js / Nuxt (file-based):          /[param_name]  or  /[[param_name]]
//
// Guard: the string must start with / or contain at least one / before the
// param token, so we don't fire on arbitrary strings that happen to contain
// a colon (e.g. "http://host", CSS "color: red").

const ROUTE_PATH_RE     = /\/:([ a-zA-Z_][a-zA-Z0-9_]{1,59})/g;  // /:param
const NEXT_BRACKET_RE   = /\/\[\[?([a-zA-Z_][a-zA-Z0-9_]{1,59})\]\]?/g; // /[param] or /[[param]]

/**
 * Return true when a string literal value looks like it could be a route path.
 * Must start with / OR contain a segment separator before a : or [ token.
 * Filters out http(s):// URLs and CSS-like strings.
 */
function looksLikeRoutePath(str) {
  if (!str || typeof str !== 'string') return false;
  if (str.length > 300) return false;
  // Must contain a slash before any : or [ param token
  if (!/\/(?::|\[)/.test(str)) return false;
  // Reject full URLs — they are handled by the endpoint extractor
  if (/^https?:\/\//.test(str)) return false;
  return true;
}

/**
 * extractRouteParams — pull /:name and /[name] segments from a path string.
 * Returns an array of param name strings.
 */
function extractRouteParams(str) {
  const names = [];
  let m;
  // Reset lastIndex before each use (regexes are stateful with /g flag)
  ROUTE_PATH_RE.lastIndex = 0;
  while ((m = ROUTE_PATH_RE.exec(str)) !== null) {
    names.push(m[1]);
  }
  NEXT_BRACKET_RE.lastIndex = 0;
  while ((m = NEXT_BRACKET_RE.exec(str)) !== null) {
    names.push(m[1]);
  }
  return names;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function calleeName(node) {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'MemberExpression') {
    const obj  = calleeName(node.object);
    const prop = node.property?.type === 'Identifier' ? node.property.name : null;
    if (obj && prop) return obj + '.' + prop;
  }
  return null;
}

function extractQS(urlStr) {
  if (!urlStr || typeof urlStr !== 'string') return [];
  try {
    const u = new URL(urlStr.startsWith('http') ? urlStr : 'http://x' + urlStr);
    return [...u.searchParams.keys()];
  } catch {
    return [];
  }
}

function objectLiteralKeys(objNode) {
  if (!objNode || objNode.type !== 'ObjectExpression') return [];
  const keys = [];
  for (const prop of objNode.properties) {
    if (prop.type === 'SpreadElement') {
      if (prop.argument?.type === 'ObjectExpression') {
        keys.push(...objectLiteralKeys(prop.argument));
      }
      continue;
    }
    if (!prop.key) continue;
    const k = prop.key.name || prop.key.value;
    if (k) keys.push(k);
  }
  return keys;
}

function foldToString(node, stringConsts) {
  if (!node) return null;
  if (node.type === 'Literal' && typeof node.value === 'string') return node.value;
  if (node.type === 'Identifier' && stringConsts.has(node.name)) return stringConsts.get(node.name);
  return null;
}

function isValidParam(name) {
  if (!name || typeof name !== 'string') return false;
  if (name.length > 60) return false;
  if (name.length === 1 && !SINGLE_CHAR_WHITELIST.has(name)) return false;
  if (name.length < 1) return false;
  if (!/^[a-zA-Z][a-zA-Z0-9_\-]*$/.test(name)) return false;
  if (JS_BUILTINS.has(name)) return false;
  if (FETCH_OPTION_KEYS.has(name)) return false;
  return true;
}

// ── Parser ────────────────────────────────────────────────────────────────────

function tryParse(code) {
  for (const sourceType of ['module', 'script']) {
    try {
      return acorn.parse(code, { ecmaVersion: 2022, sourceType });
    } catch (_) {}
  }
  if (babelParser) {
    try {
      return babelParser.parse(code, {
        sourceType: 'unambiguous',
        plugins: ['typescript', 'jsx', 'decorators-legacy'],
        errorRecovery: true,
      });
    } catch (_) {}
  }
  return null;
}

// ── Pass 1: build alias maps + collect string constants ───────────────────────

function buildAliasMap(ast) {
  const queryAliases    = new Set();
  const urlParamAliases = new Set();
  const payloadAliases  = new Set();
  const directParams    = new Set();
  const stringConsts    = new Map();

  walk.simple(ast, {
    VariableDeclarator(node) {
      if (!node.init) return;
      const init = node.init;

      if (
        node.id?.type === 'Identifier' &&
        init.type === 'Literal' &&
        typeof init.value === 'string'
      ) {
        stringConsts.set(node.id.name, init.value);
      }

      const isReqMember = (
        init.type === 'MemberExpression' && !init.computed &&
        QUERY_MEMBER_ROOTS.test(init.object?.name || '') &&
        QUERY_MEMBER_PROPS.test(init.property?.name || '')
      );
      const isQueryIdent  = init.type === 'Identifier' && QUERY_SEED_NAMES.test(init.name);
      const isMemberProp  = (
        init.type === 'MemberExpression' && !init.computed &&
        QUERY_INIT_PROPS.test(init.property?.name || '')
      );
      const isURLSP = (
        init.type === 'NewExpression' &&
        init.callee?.type === 'Identifier' &&
        init.callee.name === 'URLSearchParams'
      );
      const isPayload = init.type === 'Identifier' && PAYLOAD_ROOTS.test(init.name);
      const isQuery   = isReqMember || isQueryIdent || isMemberProp;

      if (node.id.type === 'Identifier') {
        if (isQuery)   queryAliases.add(node.id.name);
        if (isURLSP)   urlParamAliases.add(node.id.name);
        if (isPayload) payloadAliases.add(node.id.name);
      }

      if (node.id.type === 'ObjectPattern' && isQuery) {
        for (const prop of node.id.properties) {
          if (prop.type === 'RestElement') continue;
          const key = prop.key?.name || prop.key?.value;
          if (key) directParams.add(key);
        }
      }

      if (
        node.id?.type === 'Identifier' &&
        init.type === 'CallExpression' &&
        calleeName(init.callee) === 'Object.assign'
      ) {
        for (const arg of init.arguments) {
          if (arg.type === 'Identifier' && queryAliases.has(arg.name)) {
            queryAliases.add(node.id.name);
            break;
          }
        }
      }
    },
  });

  return { queryAliases, urlParamAliases, payloadAliases, directParams, stringConsts };
}

// ── Pass 2: extract params ────────────────────────────────────────────────────

function extract(code) {
  const ast = tryParse(code);
  if (!ast) return { params: [], endpoints: [], error: 'parse_failed' };

  const { queryAliases, urlParamAliases, payloadAliases, directParams, stringConsts } =
    buildAliasMap(ast);

  const callSitePositions = new Set();
  walk.simple(ast, {
    CallExpression(n) { callSitePositions.add(n.callee.start); },
  });

  const found      = [];
  const seen       = new Set();
  const endpoints  = [];
  const seenEP     = new Set();

  function emit(value, confidence, source) {
    if (!isValidParam(value)) return;
    if (seen.has(value)) return;
    seen.add(value);
    found.push({ value, confidence, source });
  }

  function emitEndpoint(v) {
    if (v && typeof v === 'string' && !seenEP.has(v)) {
      seenEP.add(v);
      endpoints.push(v);
    }
  }

  function extractObjectArgKeys(objNode, source, confidence) {
    if (!objNode || objNode.type !== 'ObjectExpression') return;
    for (const prop of objNode.properties) {
      if (prop.type === 'SpreadElement') {
        if (prop.argument?.type === 'ObjectExpression') {
          extractObjectArgKeys(prop.argument, source + '_spread', confidence);
        }
        continue;
      }
      if (!prop.key) continue;
      const k = prop.key.name || prop.key.value;
      if (!k) continue;
      if (['params', 'data', 'body'].includes(k) && prop.value?.type === 'ObjectExpression') {
        for (const pk of objectLiteralKeys(prop.value)) emit(pk, 'HIGH', source + '_body');
      } else if (!FETCH_OPTION_KEYS.has(k)) {
        emit(k, confidence, source);
      }
      if (k === 'url' && prop.value?.type === 'Literal') emitEndpoint(prop.value.value);
    }
  }

  const SP_METHODS = new Set(['get', 'set', 'append', 'has', 'delete', 'getAll']);

  walk.simple(ast, {

    // ── CallExpression ────────────────────────────────────────────────────────
    CallExpression(node) {
      const name = calleeName(node.callee);
      const args = node.arguments;

      if (name && NET_CALLS.has(name) && args.length) {
        const first = args[0];

        if (first.type === 'Literal' && typeof first.value === 'string') {
          emitEndpoint(first.value);
          for (const p of extractQS(first.value)) emit(p, 'HIGH', 'net_call_qs');
        }

        if (first.type === 'TemplateLiteral') {
          for (const quasi of first.quasis) {
            const raw = quasi.value.cooked || quasi.value.raw || '';
            for (const m of raw.matchAll(/[?&]([a-zA-Z][a-zA-Z0-9_\-]{1,39})=/g)) {
              emit(m[1], 'MED', 'template_qs');
            }
          }
        }

        for (const arg of args) {
          extractObjectArgKeys(arg, 'net_arg', 'HIGH');
        }
      }

      if (name === 'Object.assign') {
        for (const arg of args) {
          if (arg.type !== 'ObjectExpression') continue;
          for (const k of objectLiteralKeys(arg)) emit(k, 'MED', 'object_assign');
        }
      }

      if (
        node.callee.type === 'Identifier' &&
        REACT_STATE_HOOKS.has(node.callee.name) &&
        args[0]?.type === 'ObjectExpression'
      ) {
        for (const k of objectLiteralKeys(args[0])) emit(k, 'MED', 'react_state');
      }

      if (node.callee.type === 'MemberExpression') {
        const method  = node.callee.property?.name;
        const objNode = node.callee.object;
        const objName = objNode?.type === 'Identifier' ? objNode.name : null;

        const isSP     = objName && (QUERY_SEED_NAMES.test(objName) || urlParamAliases.has(objName));
        const isSPNew  = objNode?.type === 'NewExpression';
        const isQAlias = objName && queryAliases.has(objName);

        if ((isSP || isSPNew || isQAlias) && method && SP_METHODS.has(method)) {
          if (args[0]?.type === 'Literal' && typeof args[0].value === 'string') {
            emit(args[0].value, 'HIGH', 'searchparam_call');
          }
          if (args[0]?.type === 'Identifier') {
            const folded = foldToString(args[0], stringConsts);
            if (folded) emit(folded, 'MED', 'searchparam_dynamic');
          }
        }

        if (
          method === 'append' &&
          objName && /^(?:form|fd|formData|body|payload)$/i.test(objName)
        ) {
          if (args[0]?.type === 'Literal' && typeof args[0].value === 'string') {
            emit(args[0].value, 'HIGH', 'formdata_append');
          }
          if (args[0]?.type === 'Identifier') {
            const folded = foldToString(args[0], stringConsts);
            if (folded) emit(folded, 'MED', 'formdata_dynamic');
          }
        }

        if (objNode?.type === 'Identifier' && objNode.name === 'JSON' && method === 'stringify') {
          if (args[0]?.type === 'ObjectExpression') {
            for (const k of objectLiteralKeys(args[0])) emit(k, 'HIGH', 'json_stringify');
          }
        }

        if (
          objNode?.type === 'Identifier' &&
          ['qs', 'querystring'].includes(objNode.name) &&
          method === 'stringify' &&
          args[0]?.type === 'ObjectExpression'
        ) {
          for (const k of objectLiteralKeys(args[0])) emit(k, 'HIGH', 'qs_stringify');
        }

        if (
          method === '$set' &&
          args.length >= 2 &&
          args[1]?.type === 'Literal' &&
          typeof args[1].value === 'string'
        ) {
          emit(args[1].value, 'MED', 'vue_set');
        }
      }
    },

    // ── MemberExpression ──────────────────────────────────────────────────────
    MemberExpression(node) {
      const propName = node.computed
        ? (
            node.property?.type === 'Literal'
              ? node.property.value
              : foldToString(node.property, stringConsts)
          )
        : node.property?.name;

      if (!propName || typeof propName !== 'string') return;
      if (callSitePositions.has(node.start)) return;

      if (!node.computed && node.object?.type === 'MemberExpression' && !node.object.computed) {
        const root = node.object.object;
        const mid  = node.object.property;
        if (
          root?.type === 'Identifier' &&
          QUERY_MEMBER_ROOTS.test(root.name) &&
          QUERY_MEMBER_PROPS.test(mid?.name)
        ) {
          return emit(propName, 'HIGH', 'req_member_read');
        }
      }

      if (!node.computed && node.object?.type === 'Identifier') {
        const objName = node.object.name;
        if (queryAliases.has(objName))   return emit(propName, 'HIGH', 'alias_member_read');
        if (payloadAliases.has(objName)) return emit(propName, 'HIGH', 'payload_member_read');
        if (PARAM_PROP_ROOTS.test(objName)) return emit(propName, 'HIGH', 'param_prop_read');
      }

      if (
        node.computed &&
        node.object?.type === 'Identifier' &&
        /^(?:body|payload|data|form|req)$/i.test(node.object.name)
      ) {
        return emit(propName, 'HIGH', 'body_bracket_read');
      }

      if (
        node.computed &&
        node.object?.type === 'Identifier' &&
        PARAM_PROP_ROOTS.test(node.object.name)
      ) {
        return emit(propName, 'MED', 'param_dynamic_key');
      }
    },

    // ── AssignmentExpression: params['key'] = val ─────────────────────────────
    AssignmentExpression(node) {
      const left = node.left;
      if (left?.type !== 'MemberExpression') return;
      if (!left.computed) return;

      const objName = left.object?.type === 'Identifier' ? left.object.name : null;
      if (!objName) return;

      const keyStr = foldToString(left.property, stringConsts);
      if (!keyStr) return;

      if (
        queryAliases.has(objName) ||
        PARAM_PROP_ROOTS.test(objName) ||
        /^(?:body|payload|data|form|req)$/i.test(objName)
      ) {
        emit(keyStr, 'MED', 'assignment_bracket');
      }
    },

    // ── Literal: route path params /:param and /[param] ───────────────────────
    //
    // Walk every string literal in the AST. If it looks like a route path
    // (contains /: or /[ before a segment name), extract the param names.
    //
    // Covers:
    //   Express / React Router / Vue Router  →  '/users/:user_id/posts/:post_id'
    //   Next.js / Nuxt file-based routing     →  '/dashboard/[projectId]/settings'
    //   Generic path strings                  →  '/api/v1/orders/:order_id/items/:item_id'
    Literal(node) {
      if (typeof node.value !== 'string') return;
      if (!looksLikeRoutePath(node.value)) return;
      for (const name of extractRouteParams(node.value)) {
        emit(name, 'MED', 'route_path_param');
      }
    },

  });

  for (const p of directParams) emit(p, 'HIGH', 'destructure');

  return {
    params: found,
    endpoints,
    error: null,
    meta: {
      queryAliases:    [...queryAliases],
      urlParamAliases: [...urlParamAliases],
      payloadAliases:  [...payloadAliases],
      babelFallback:   babelParser !== null,
    },
  };
}

// ── Entry point ───────────────────────────────────────────────────────────────

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => { input += chunk; });
process.stdin.on('end', () => {
  process.stdout.write(JSON.stringify(extract(input), null, 2));
});
