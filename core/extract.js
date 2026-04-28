'use strict';

const walk = require('acorn-walk');

const {
  NET_CALLS, FETCH_OPTION_KEYS,
  QUERY_MEMBER_ROOTS, QUERY_MEMBER_PROPS, QUERY_SEED_NAMES,
  QUERY_INIT_PROPS, PARAM_PROP_ROOTS, PAYLOAD_ROOTS,
  REACT_STATE_HOOKS, SP_METHODS,
} = require('./constants');

const {
  calleeName, extractQS, objectLiteralKeys, foldToString,
  isValidParam, looksLikeRoutePath, extractRouteParams,
} = require('./helpers');

const { tryParse, hasBabel } = require('./parser');

// ── Pass 1: build alias maps ──────────────────────────────────────────────────
//
// Walk the AST once to collect:
//   queryAliases    — variable names bound to req.query / ctx.query / etc.
//   urlParamAliases — variable names bound to new URLSearchParams()
//   payloadAliases  — variable names bound to req.body / payload / etc.
//   directParams    — param names destructured directly from a query source
//   stringConsts    — const/let string literals (for dynamic key folding)

function buildAliasMap(ast) {
  const queryAliases    = new Set();
  const urlParamAliases = new Set();
  const payloadAliases  = new Set();
  const directParams    = new Set();
  const stringConsts    = new Map();

  walk.simple(ast, {
    VariableDeclarator(node) {
      const { id, init } = node;
      if (!init) return;

      // Track  const KEY = 'literal'  for later dynamic key folding
      if (id?.type === 'Identifier' && init.type === 'Literal' && typeof init.value === 'string') {
        stringConsts.set(id.name, init.value);
      }

      // Classify the right-hand side
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
      const isPayload = init.type === 'Identifier'   && PAYLOAD_ROOTS.test(init.name);
      const isQuery   = isReqMember || isQueryIdent || isMemberProp;

      // Simple binding  →  add to the appropriate alias set
      if (id.type === 'Identifier') {
        if (isQuery)   queryAliases.add(id.name);
        if (isURLSP)   urlParamAliases.add(id.name);
        if (isPayload) payloadAliases.add(id.name);
      }

      // Destructure  →  keys land directly as confirmed param names
      if (id.type === 'ObjectPattern' && isQuery) {
        for (const prop of id.properties) {
          if (prop.type === 'RestElement') continue;
          const key = prop.key?.name ?? prop.key?.value;
          if (key) directParams.add(key);
        }
      }

      // FIX 1 — Object.assign(…, req.query, …) or Object.assign(…, existingAlias, …)
      // Previously only matched Identifier args already in queryAliases.
      // Now also matches MemberExpression args like req.query directly.
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
  });

  return { queryAliases, urlParamAliases, payloadAliases, directParams, stringConsts };
}

// ── Pass 2: extract params ────────────────────────────────────────────────────

function extract(code) {
  const ast = tryParse(code);
  if (!ast) return { params: [], endpoints: [], error: 'parse_failed' };

  const { queryAliases, urlParamAliases, payloadAliases, directParams, stringConsts } =
    buildAliasMap(ast);

  // Track callee start positions so MemberExpression doesn't double-count call sites
  const callSitePositions = new Set();
  walk.simple(ast, { CallExpression(n) { callSitePositions.add(n.callee.start); } });

  const found     = [];
  const seen      = new Set();
  const endpoints = [];
  const seenEP    = new Set();

  function emit(value, confidence, source) {
    if (!isValidParam(value) || seen.has(value)) return;
    seen.add(value);
    found.push({ value, confidence, source });
  }

  function emitEndpoint(v) {
    if (v && typeof v === 'string' && !seenEP.has(v)) {
      seenEP.add(v);
      endpoints.push(v);
    }
  }

  // Walk an options object passed to a network call.
  // Keys that are "params", "data", or "body" are unwrapped one level.
  function walkOptionsObject(objNode, source, confidence) {
    if (!objNode || objNode.type !== 'ObjectExpression') return;

    for (const prop of objNode.properties) {
      if (prop.type === 'SpreadElement') {
        if (prop.argument?.type === 'ObjectExpression')
          walkOptionsObject(prop.argument, `${source}_spread`, confidence);
        continue;
      }
      if (!prop.key) continue;

      const k = prop.key.name ?? prop.key.value;
      if (!k) continue;

      if (['params', 'data', 'body'].includes(k) && prop.value?.type === 'ObjectExpression') {
        for (const pk of objectLiteralKeys(prop.value)) emit(pk, 'HIGH', `${source}_body`);
      } else if (!FETCH_OPTION_KEYS.has(k)) {
        emit(k, confidence, source);
      }

      if (k === 'url' && prop.value?.type === 'Literal') emitEndpoint(prop.value.value);
    }
  }

  // ── Helpers for specific call patterns ────────────────────────────────────

  function handleNetCall(node) {
    const args  = node.arguments;
    const first = args[0];

    if (first.type === 'Literal' && typeof first.value === 'string') {
      emitEndpoint(first.value);
      for (const p of extractQS(first.value)) emit(p, 'HIGH', 'net_call_qs');
    }

    if (first.type === 'TemplateLiteral') {
      for (const quasi of first.quasis) {
        const raw = quasi.value.cooked ?? quasi.value.raw ?? '';
        for (const m of raw.matchAll(/[?&]([a-zA-Z][a-zA-Z0-9_\-]{1,39})=/g))
          emit(m[1], 'MED', 'template_qs');
      }
    }

    for (const arg of args) walkOptionsObject(arg, 'net_arg', 'HIGH');
  }

  function handleSPMethod(node) {
    const method  = node.callee.property?.name;
    const objNode = node.callee.object;
    const objName = objNode?.type === 'Identifier' ? objNode.name : null;

    const isSP = (
      (objName && (QUERY_SEED_NAMES.test(objName) || urlParamAliases.has(objName))) ||
      objNode?.type === 'NewExpression' ||
      (objName && queryAliases.has(objName))
    );
    if (!isSP || !method || !SP_METHODS.has(method)) return;

    const [keyArg] = node.arguments;
    if (keyArg?.type === 'Literal' && typeof keyArg.value === 'string')
      emit(keyArg.value, 'HIGH', 'searchparam_call');
    else if (keyArg?.type === 'Identifier') {
      const folded = foldToString(keyArg, stringConsts);
      if (folded) emit(folded, 'MED', 'searchparam_dynamic');
    }
  }

  function handleFormDataAppend(node) {
    const objName = node.callee.object?.name ?? '';
    if (!/^(?:form|fd|formData|body|payload)$/i.test(objName)) return;
    const [keyArg] = node.arguments;
    if (keyArg?.type === 'Literal' && typeof keyArg.value === 'string')
      emit(keyArg.value, 'HIGH', 'formdata_append');
    else if (keyArg?.type === 'Identifier') {
      const folded = foldToString(keyArg, stringConsts);
      if (folded) emit(folded, 'MED', 'formdata_dynamic');
    }
  }

  // ── Main AST walk ─────────────────────────────────────────────────────────

  walk.simple(ast, {

    CallExpression(node) {
      const name = calleeName(node.callee);
      const args = node.arguments;

      if (name && NET_CALLS.has(name) && args.length)
        handleNetCall(node);

      if (name === 'Object.assign')
        for (const arg of args)
          if (arg.type === 'ObjectExpression')
            for (const k of objectLiteralKeys(arg)) emit(k, 'MED', 'object_assign');

      if (node.callee.type === 'Identifier' && REACT_STATE_HOOKS.has(node.callee.name)) {
        if (args[0]?.type === 'ObjectExpression')
          for (const k of objectLiteralKeys(args[0])) emit(k, 'MED', 'react_state');
        if (args[1]?.type === 'ObjectExpression')  // useReducer(reducer, initState)
          for (const k of objectLiteralKeys(args[1])) emit(k, 'MED', 'react_state');
      }

      if (node.callee.type !== 'MemberExpression') return;

      const method = node.callee.property?.name;

      handleSPMethod(node);

      if (method === 'append') handleFormDataAppend(node);

      if (node.callee.object?.name === 'JSON' && method === 'stringify')
        if (args[0]?.type === 'ObjectExpression')
          for (const k of objectLiteralKeys(args[0])) emit(k, 'HIGH', 'json_stringify');

      if (['qs', 'querystring'].includes(node.callee.object?.name) && method === 'stringify')
        if (args[0]?.type === 'ObjectExpression')
          for (const k of objectLiteralKeys(args[0])) emit(k, 'HIGH', 'qs_stringify');

      if (method === '$set' && args[1]?.type === 'Literal' && typeof args[1].value === 'string')
        emit(args[1].value, 'MED', 'vue_set');
    },

    // new URLSearchParams({ key: val, … })
    NewExpression(node) {
      if (node.callee?.type !== 'Identifier' || node.callee.name !== 'URLSearchParams') return;
      if (node.arguments[0]?.type !== 'ObjectExpression') return;
      for (const k of objectLiteralKeys(node.arguments[0]))
        emit(k, 'HIGH', 'urlsearchparams_ctor');
    },

    MemberExpression(node) {
      if (callSitePositions.has(node.start)) return;

      const propName = node.computed
        ? (node.property?.type === 'Literal'
            ? node.property.value
            : foldToString(node.property, stringConsts))
        : node.property?.name;

      if (!propName || typeof propName !== 'string') return;

      // req.query.prop  /  req.body.prop
      if (!node.computed && node.object?.type === 'MemberExpression' && !node.object.computed) {
        const root = node.object.object;
        const mid  = node.object.property;
        if (
          root?.type === 'Identifier' &&
          QUERY_MEMBER_ROOTS.test(root.name) &&
          QUERY_MEMBER_PROPS.test(mid?.name)
        ) return emit(propName, 'HIGH', 'req_member_read');
      }

      if (!node.computed && node.object?.type === 'Identifier') {
        const objName = node.object.name;
        if (queryAliases.has(objName))      return emit(propName, 'HIGH', 'alias_member_read');
        // FIX 2 — payload/body/data as function parameter (never registered via VariableDeclarator)
        // Previously only payloadAliases (built from var declarations) was checked.
        // Now also match the name directly against PAYLOAD_ROOTS so function params are covered.
        if (payloadAliases.has(objName) || PAYLOAD_ROOTS.test(objName))
          return emit(propName, 'HIGH', 'payload_member_read');
        if (PARAM_PROP_ROOTS.test(objName)) return emit(propName, 'HIGH', 'param_prop_read');
      }

      // body['key']  /  payload['key']  (computed bracket read)
      if (node.computed && node.object?.type === 'Identifier') {
        const objName = node.object.name;
        if (/^(?:body|payload|data|form|req)$/i.test(objName))
          return emit(propName, 'HIGH', 'body_bracket_read');
        if (PARAM_PROP_ROOTS.test(objName))
          return emit(propName, 'MED', 'param_dynamic_key');
      }
    },

    // params['key'] = val
    AssignmentExpression(node) {
      const { left } = node;
      if (left?.type !== 'MemberExpression' || !left.computed) return;

      const objName = left.object?.type === 'Identifier' ? left.object.name : null;
      if (!objName) return;

      const keyStr = foldToString(left.property, stringConsts);
      if (!keyStr) return;

      if (
        queryAliases.has(objName) ||
        PARAM_PROP_ROOTS.test(objName) ||
        /^(?:body|payload|data|form|req)$/i.test(objName)
      ) emit(keyStr, 'MED', 'assignment_bracket');
    },

    // Route path params:  '/users/:id'  '/dashboard/[projectId]'
    // Handles both acorn Literal nodes and Babel StringLiteral nodes (from JSX parsing)
    Literal(node) {
      if (typeof node.value !== 'string') return;
      if (!looksLikeRoutePath(node.value)) return;
      for (const name of extractRouteParams(node.value))
        emit(name, 'MED', 'route_path_param');
    },

    // FIX 3 — Babel StringLiteral (emitted instead of Literal when @babel/parser handles JSX)
    // Covers: <Route path="/users/:id" />  <Link to="/posts/:slug" />
    StringLiteral(node) {
      if (typeof node.value !== 'string') return;
      if (!looksLikeRoutePath(node.value)) return;
      for (const name of extractRouteParams(node.value))
        emit(name, 'MED', 'route_path_param_jsx');
    },

  });

  // Flush destructured params collected in Pass 1
  for (const p of directParams) emit(p, 'HIGH', 'destructure');

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

module.exports = { extract };
