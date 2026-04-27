'use strict';

// Network call method names recognised as HTTP request initiators
const NET_CALLS = new Set([
  'fetch',
  'axios', 'axios.get', 'axios.post', 'axios.put', 'axios.delete', 'axios.patch',
  'got',   'got.get',   'got.post',
  'ky',    'ky.get',    'ky.post',
  'superagent', 'request',
  'http.get',  'http.post',
  'https.get', 'https.post',
  '$.get', '$.post', '$.ajax',
  // Vue instance HTTP helpers
  'this.$http.get',   'this.$http.post',   'this.$http.put',   'this.$http.delete',
  'this.$axios.get',  'this.$axios.post',  'this.$axios.put',  'this.$axios.delete',
]);

// Keys on the options object passed to fetch/axios that are config, not params
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

// Patterns for recognising alias sources in Pass 1
const QUERY_MEMBER_ROOTS = /^(?:req|request|ctx|context)$/;
const QUERY_MEMBER_PROPS = /^(?:query|body|params|searchParams)$/;
const QUERY_SEED_NAMES   = /^(?:params|searchParams|query|urlParams|queryParams|searchparams|querystring)$/i;
const QUERY_INIT_PROPS   = /^(?:query|params|searchParams|body)$/i;
const PARAM_PROP_ROOTS   = /^(?:params|query|qs|searchParams|queryParams|urlParams|args|opts)$/i;
const PAYLOAD_ROOTS      = /^(?:payload|body|formBody|requestBody|postData|formValues|formFields)$/i;

// React/form hooks whose first (or second) argument is an initial-state object
const REACT_STATE_HOOKS  = new Set(['useState', 'useReducer', 'useFormik', 'useForm']);

// URLSearchParams / FormData mutation methods
const SP_METHODS         = new Set(['get', 'set', 'append', 'has', 'delete', 'getAll']);

// Single-char names that are real params (bypass the 1-char floor)
const SINGLE_CHAR_WHITELIST = new Set(['q', 's', 'v', 't', 'p', 'n', 'id']);

// DOM / JS builtins — never valid param names
const JS_BUILTINS = new Set([
  // DOM traversal & mutation
  'appendChild', 'removeChild', 'replaceChild', 'insertBefore', 'cloneNode',
  'innerHTML', 'outerHTML', 'innerText', 'textContent', 'nodeValue',
  // Events
  'addEventListener', 'removeEventListener', 'dispatchEvent',
  // DOM query
  'getAttribute', 'setAttribute', 'removeAttribute', 'hasAttribute',
  'querySelector', 'querySelectorAll', 'getElementById',
  'getElementsByClassName', 'getElementsByTagName',
  // Element props
  'classList', 'className', 'style', 'dataset',
  'getBoundingClientRect', 'getComputedStyle', 'scrollIntoView', 'scrollTo',
  'scrollTop', 'scrollLeft', 'offsetTop', 'offsetLeft', 'offsetWidth', 'offsetHeight',
  'clientWidth', 'clientHeight', 'naturalWidth', 'naturalHeight',
  // Timers & animation
  'setTimeout', 'setInterval', 'clearTimeout', 'clearInterval',
  'requestAnimationFrame', 'cancelAnimationFrame',
  // Event object
  'preventDefault', 'stopPropagation', 'stopImmediatePropagation',
  // Object proto
  'toString', 'valueOf', 'hasOwnProperty', 'isPrototypeOf', 'propertyIsEnumerable',
  'constructor', 'prototype', '__proto__',
  // Global constructors & namespaces
  'JSON', 'Math', 'Object', 'Array', 'String', 'Number', 'Boolean', 'Symbol',
  'Promise', 'fetch', 'XMLHttpRequest', 'FormData', 'URLSearchParams', 'URL',
  'console', 'window', 'document', 'navigator', 'location', 'history',
  'localStorage', 'sessionStorage', 'indexedDB', 'crypto', 'performance',
  // Common React event handlers
  'handleClick', 'handleSubmit', 'handleChange', 'handleBlur', 'handleFocus',
  'handleKeyDown', 'handleKeyUp', 'handleMouseEnter', 'handleMouseLeave',
  'handleReset', 'handleToggle', 'handleSelect', 'handleDrop', 'handleDrag',
  // Common boolean / state flags
  'isLoading', 'isError', 'isActive', 'isDisabled', 'isVisible', 'isOpen', 'isMounted',
  'setLoading', 'setError', 'setActive', 'setVisible', 'setOpen', 'setData',
  // React lifecycle
  'componentDidMount', 'componentDidUpdate', 'componentWillUnmount',
  'useEffect', 'useState', 'useRef', 'useMemo', 'useCallback', 'useContext', 'useReducer',
  // Generic CRUD verbs
  'render', 'create', 'update', 'destroy', 'remove', 'reset', 'clear', 'close', 'open', 'toggle',
  // Object / Array methods
  'stringify', 'parse', 'assign', 'freeze', 'seal', 'keys', 'values', 'entries', 'fromEntries',
  'push', 'pop', 'shift', 'unshift', 'splice', 'slice', 'filter', 'map', 'reduce', 'reduceRight',
  'forEach', 'find', 'findIndex', 'includes', 'some', 'every', 'sort', 'reverse', 'flat', 'flatMap',
  // String methods
  'join', 'split', 'trim', 'trimStart', 'trimEnd', 'replace', 'replaceAll', 'match', 'matchAll',
  'test', 'exec', 'startsWith', 'endsWith', 'padStart', 'padEnd', 'repeat', 'charAt', 'charCodeAt',
  // Promise
  'then', 'catch', 'finally', 'resolve', 'reject', 'all', 'race', 'any', 'allSettled',
  // URI
  'encode', 'decode', 'encodeURIComponent', 'decodeURIComponent', 'encodeURI', 'decodeURI',
  // EventEmitter
  'emit', 'on', 'off', 'once', 'removeListener', 'addListener', 'prependListener',
  // console
  'error', 'warn', 'log', 'info', 'debug', 'table', 'group', 'groupEnd', 'time', 'timeEnd',
  // DOM helpers
  'after', 'before', 'append', 'prepend', 'contains', 'matches', 'closest',
  // Common UI state names that look like params but aren't
  'isLoaded', 'hasError', 'showModal', 'hideModal', 'toggleMenu', 'nextPage', 'prevPage',
  // Map / Set methods
  'get', 'set', 'has', 'delete', 'getAll', 'append',
]);

module.exports = {
  NET_CALLS, FETCH_OPTION_KEYS,
  QUERY_MEMBER_ROOTS, QUERY_MEMBER_PROPS, QUERY_SEED_NAMES,
  QUERY_INIT_PROPS, PARAM_PROP_ROOTS, PAYLOAD_ROOTS,
  REACT_STATE_HOOKS, SP_METHODS, SINGLE_CHAR_WHITELIST, JS_BUILTINS,
};
