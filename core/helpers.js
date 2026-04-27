'use strict';

const { FETCH_OPTION_KEYS, SINGLE_CHAR_WHITELIST, JS_BUILTINS } = require('./constants');

// ── Route path extraction ─────────────────────────────────────────────────────
//
//   Express / React Router / Vue Router  →  /users/:user_id
//   Next.js / Nuxt                       →  /dashboard/[projectId] or /[[slug]]

const ROUTE_COLON_RE   = /\/:([a-zA-Z_][a-zA-Z0-9_]{1,59})/g;
const ROUTE_BRACKET_RE = /\/\[{1,2}([a-zA-Z_][a-zA-Z0-9_]{1,59})\]{1,2}/g;

function looksLikeRoutePath(str) {
  if (!str || typeof str !== 'string' || str.length > 300) return false;
  if (!str.includes('/:') && !str.includes('/[')) return false;
  if (str.startsWith('http://') || str.startsWith('https://')) return false;
  return true;
}

function extractRouteParams(str) {
  const names = [];
  let m;
  ROUTE_COLON_RE.lastIndex   = 0;
  ROUTE_BRACKET_RE.lastIndex = 0;
  while ((m = ROUTE_COLON_RE.exec(str))   !== null) names.push(m[1]);
  while ((m = ROUTE_BRACKET_RE.exec(str)) !== null) names.push(m[1]);
  return names;
}

// ── AST traversal helpers ─────────────────────────────────────────────────────

/**
 * Recursively resolve a callee node to a dotted name string.
 * Handles: Identifier, MemberExpression, ThisExpression.
 *   this.$http.post  →  "this.$http.post"
 *   axios.get        →  "axios.get"
 */
function calleeName(node) {
  if (!node) return null;
  if (node.type === 'Identifier')       return node.name;
  if (node.type === 'ThisExpression')   return 'this';
  if (node.type === 'MemberExpression') {
    const obj  = calleeName(node.object);
    const prop = node.property?.type === 'Identifier' ? node.property.name : null;
    if (obj && prop) return `${obj}.${prop}`;
  }
  return null;
}

/**
 * Parse query-string keys out of a URL string.
 * e.g. "/api?user_id=1&token=abc"  →  ["user_id", "token"]
 */
function extractQS(urlStr) {
  if (!urlStr || typeof urlStr !== 'string') return [];
  try {
    const base = urlStr.startsWith('http') ? urlStr : `http://x${urlStr}`;
    return [...new URL(base).searchParams.keys()];
  } catch {
    return [];
  }
}

/**
 * Collect all key names from an ObjectExpression node.
 * Recurses one level into spread arguments that are also object literals.
 */
function objectLiteralKeys(objNode) {
  if (!objNode || objNode.type !== 'ObjectExpression') return [];
  const keys = [];
  for (const prop of objNode.properties) {
    if (prop.type === 'SpreadElement') {
      if (prop.argument?.type === 'ObjectExpression')
        keys.push(...objectLiteralKeys(prop.argument));
      continue;
    }
    const k = prop.key?.name ?? prop.key?.value;
    if (k) keys.push(k);
  }
  return keys;
}

/**
 * Attempt to resolve a node to a string constant at parse time.
 * Handles:  Literal("foo")  or  Identifier(name) where name is in stringConsts.
 */
function foldToString(node, stringConsts) {
  if (!node) return null;
  if (node.type === 'Literal'    && typeof node.value === 'string') return node.value;
  if (node.type === 'Identifier' && stringConsts.has(node.name))    return stringConsts.get(node.name);
  return null;
}

/**
 * Return true when a candidate string is plausibly an HTTP param name.
 *
 * Rules:
 *   - 1–60 chars
 *   - Must start with a letter, contain only [a-zA-Z0-9_-]
 *   - Single-char names allowed only for known shorthands (q, s, t, …)
 *   - Must not be a JS built-in or a fetch option key
 */
function isValidParam(name) {
  if (!name || typeof name !== 'string')        return false;
  if (name.length > 60)                         return false;
  if (!/^[a-zA-Z][a-zA-Z0-9_\-]*$/.test(name)) return false;
  if (name.length === 1 && !SINGLE_CHAR_WHITELIST.has(name)) return false;
  if (JS_BUILTINS.has(name))                    return false;
  if (FETCH_OPTION_KEYS.has(name))              return false;
  return true;
}

module.exports = {
  looksLikeRoutePath, extractRouteParams,
  calleeName, extractQS, objectLiteralKeys, foldToString, isValidParam,
};
