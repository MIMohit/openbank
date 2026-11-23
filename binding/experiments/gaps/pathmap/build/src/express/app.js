'use strict'
// Bench API executor: Express 4 (CONTRACT section 3).
// Middleware order: log (records raw method/target, writes JSONL on 'finish')
//   -> body parsers -> method-override (only OVERRIDE=on) -> routes -> /api/v2 Router mount -> 404
const express = require('express')
const methodOverride = require('method-override')
const http = require('http')
const fs = require('fs')
const viewmac = require('./viewmac') // defence D-B (binding/harness/defence/express/viewmac.js)

const FRAMEWORK = process.env.FRAMEWORK_TAG || 'express'
const OVERRIDE = (process.env.OVERRIDE || 'off').toLowerCase() === 'on'
// ROUTES=v2 (default off) adds the richer v1 route space (W15 ext-routes). Off => :latest behaviour.
const ROUTES = (process.env.ROUTES || 'off').toLowerCase()
const VERIFY_MODE = (process.env.VERIFY_MODE || 'off').toLowerCase()
const VERIFIER_URL = new URL(process.env.VERIFIER_URL || 'http://verifier:9100/authz/orig')
const LOG_PATH = process.env.LOG_PATH || '/logs/executor.jsonl'
const TRUST_PREFIXES = ['x-forwarded-', 'x-original-', 'x-verified-', 'x-client-cert',
  'client-cert', 'x-forwarded-client-cert', 'x-auth-']
if (!['off', 'origin-raw', 'origin-routed'].includes(VERIFY_MODE)) { console.error('bad VERIFY_MODE'); process.exit(2) }
const DEFENCE = (process.env.DEFENCE || (VERIFY_MODE === 'off' ? 'db' : 'off')).toLowerCase()
const VIEW_MAC_KEY = Buffer.from(process.env.VIEW_MAC_KEY || '', 'utf8')
if (!['off', 'db'].includes(DEFENCE)) { console.error('bad DEFENCE'); process.exit(2) }
if (DEFENCE === 'db' && !VIEW_MAC_KEY.length) { console.error('DEFENCE=db requires VIEW_MAC_KEY'); process.exit(2) }
const DEFENCE_PATH_MAP = process.env.DEFENCE_PATH_MAP || ''
const DEFENCE_WILDCARDS = new Set((process.env.DEFENCE_WILDCARDS || 'path').split(',').filter(Boolean))
function pathmapRules () { return DEFENCE_PATH_MAP ? viewmac.loadRules(DEFENCE_PATH_MAP) : null }

function jtiFromDpop (v) {
  if (typeof v !== 'string' || !v) return null
  try {
    const parts = v.trim().split('.')
    if (parts.length !== 3) return null
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'))
    return (claims && typeof claims.jti === 'string') ? claims.jti : null
  } catch (e) { return null }
}

function canonicalPath (template, params) {
  let out = template
  for (const [k, v] of Object.entries(params)) {
    // encodeURIComponent leaves A-Z a-z 0-9 - _ . ! ~ * ' ( ) ; we additionally keep sub-delims/:@
    const enc = encodeURIComponent(String(v)).replace(/%(24|26|2B|2C|3B|3D|3A|40)/g, (m) => decodeURIComponent(m))
    out = out.replace('{' + k + '}', enc)
  }
  return out
}

function writeLog (rec) {
  const line = JSON.stringify(rec)
  process.stdout.write(line + '\n')
  try { fs.appendFileSync(LOG_PATH, line + '\n') } catch (e) { /* no /logs mount */ }
}

function callVerifier (method, uri, host, headers) {
  return new Promise((resolve) => {
    const h = { 'X-Original-Method': method, 'X-Original-URI': uri, 'X-Original-Host': host }
    if (headers.authorization !== undefined) h.Authorization = headers.authorization
    if (headers.dpop !== undefined) h.DPoP = headers.dpop
    const req = http.request({
      hostname: VERIFIER_URL.hostname, port: VERIFIER_URL.port || 80,
      path: VERIFIER_URL.pathname + VERIFIER_URL.search, method: 'GET', headers: h, timeout: 3000
    }, (res) => { res.resume(); resolve(res.statusCode >= 200 && res.statusCode < 300) })
    req.on('timeout', () => { req.destroy(); resolve(false) })
    req.on('error', () => resolve(false)) // fail closed
    req.end()
  })
}

const app = express()
app.disable('x-powered-by')
app.set('etag', false)

// --- logging (outermost). req.url is the raw request-target as received by Node's parser.
app.use((req, res, next) => {
  const rawTarget = req.url
  const rawMethod = req.method
  const trust = {}
  // rawHeaders preserves duplicates and order; Node's req.headers would also join x-* with ', '
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    const k = req.rawHeaders[i].toLowerCase()
    if (TRUST_PREFIXES.some((p) => k.startsWith(p))) {
      trust[k] = (k in trust) ? trust[k] + ', ' + req.rawHeaders[i + 1] : req.rawHeaders[i + 1]
    }
  }
  req.bh = { op_id: 'NOT_FOUND', route_template: null, path_params: {}, denied: false, rawTarget, rawMethod }
  res.on('finish', () => {
    const q = rawTarget.indexOf('?')
    writeLog({
      ts: new Date().toISOString(),
      framework: FRAMEWORK,
      jti: jtiFromDpop(req.headers.dpop),
      op_id: req.bh.op_id,
      route_template: req.bh.route_template,
      raw_method: rawMethod,
      effective_method: req.method,
      raw_target: rawTarget,
      path_params: req.bh.path_params,
      query: q === -1 ? '' : rawTarget.slice(q + 1),
      trust_headers: trust,
      denied: req.bh.denied,
      status: res.statusCode
    })
  })
  next()
})

// Body parsers: JSON for the bench API; urlencoded is needed for method-override's documented
// req.body._method getter.
app.use(express.json({ strict: false }))
app.use(express.urlencoded({ extended: false }))
// Malformed JSON must not short-circuit graphql dispatch: treat as no body.
app.use((err, req, res, next) => { if (err && err.type === 'entity.parse.failed') { req.body = undefined; return next() } next(err) })

if (OVERRIDE) {
  // method-override 3.0.0 (expressjs/method-override). Default options: only POST is examined.
  // Later middleware wins when several sources are present.
  app.use(methodOverride('X-HTTP-Method-Override')) // header getter (README "override using a header")
  app.use(methodOverride('_method')) //                query getter (createQueryGetter in index.js)
  app.use(methodOverride(function (req, res) { //      README "custom logic" example: urlencoded body _method
    if (req.body && typeof req.body === 'object' && '_method' in req.body) {
      const method = req.body._method
      delete req.body._method
      return method
    }
  }))
}

async function respond (req, res, opId, template, params) {
  Object.assign(req.bh, { op_id: opId, route_template: template, path_params: params })
  if (DEFENCE === 'db') { // D-B: X-Verified-View must match the view this executor dispatched on
    const r = viewmac.check(VIEW_MAC_KEY, viewmac.rawValues(req, viewmac.HEADER), viewmac.rawValues(req, 'dpop'), req.method, template, params, pathmapRules(), DEFENCE_WILDCARDS)
    if (!r.ok) {
      req.bh.denied = true
      res.set('WWW-Authenticate', 'DPoP error="invalid_token"')
      return res.status(401).json({ op_id: opId, framework: FRAMEWORK, denied: true, reason: r.reason })
    }
  }
  if (VERIFY_MODE !== 'off') {
    let vm, vu
    if (VERIFY_MODE === 'origin-raw') { vm = req.bh.rawMethod; vu = req.bh.rawTarget } else {
      const _r = pathmapRules(); vm = req.method
      vu = _r === null ? canonicalPath(template, params) : viewmac.toPublic(viewmac.substitutePm(template, params, DEFENCE_WILDCARDS), _r)
    }
    const ok = await callVerifier(vm, vu, req.headers.host || '', req.headers)
    if (!ok) {
      req.bh.denied = true
      return res.status(401).json({ op_id: opId, framework: FRAMEWORK, denied: true })
    }
  }
  res.status(200).json({ op_id: opId, framework: FRAMEWORK, method: req.method, path_params: params })
}

const p = (req) => Object.assign({}, req.params)
app.get('/api/v1/accounts', (req, res) => respond(req, res, 'listAccounts', '/api/v1/accounts', {}))
app.get('/api/v1/accounts/:id', (req, res) => respond(req, res, 'getAccount', '/api/v1/accounts/{id}', p(req)))
app.put('/api/v1/accounts/:id', (req, res) => respond(req, res, 'updateAccount', '/api/v1/accounts/{id}', p(req)))
app.delete('/api/v1/accounts/:id', (req, res) => respond(req, res, 'deleteAccount', '/api/v1/accounts/{id}', p(req)))
app.post('/api/v1/accounts/:id/actions', (req, res) => {
  // Express "query parser" = "extended" (qs): ?op=a&op=b gives an array; anything not exactly
  // freeze/close (including arrays) -> unknown.
  const op = req.query.op
  const sub = (op === 'freeze' || op === 'close') ? op : 'unknown'
  respond(req, res, 'accountAction.' + sub, '/api/v1/accounts/{id}/actions', p(req))
})
app.post('/api/v1/transfers', (req, res) => respond(req, res, 'createTransfer', '/api/v1/transfers', {}))
app.post('/api/v1/graphql', (req, res) => {
  const name = (req.body && typeof req.body === 'object' && !Array.isArray(req.body)) ? req.body.operationName : undefined
  const sub = (name === 'getProfile' || name === 'deleteProfile') ? name : 'unknown'
  respond(req, res, 'graphql.' + sub, '/api/v1/graphql', {})
})
app.get('/api/v1/me', (req, res) => respond(req, res, 'me', '/api/v1/me', {}))
app.get('/api/v1/admin/users', (req, res) => respond(req, res, 'adminListUsers', '/api/v1/admin/users', {}))
app.delete('/api/v1/admin/users/:id', (req, res) => respond(req, res, 'adminDeleteUser', '/api/v1/admin/users/{id}', p(req)))
app.get('/api/v1/health', (req, res) => respond(req, res, 'health', '/api/v1/health', {}))
app.get('/api/v1/public/:file', (req, res) => respond(req, res, 'publicFile', '/api/v1/public/{file}', p(req)))

if (ROUTES === 'v2') {
  // POST sharing the /accounts/:id path with GET/PUT/DELETE (method-override defaults to POST-only).
  app.post('/api/v1/accounts/:id', (req, res) => respond(req, res, 'postAccount', '/api/v1/accounts/{id}', p(req)))
  // Nested same-method route.
  app.get('/api/v1/accounts/:id/statements', (req, res) => respond(req, res, 'getStatements', '/api/v1/accounts/{id}/statements', p(req)))
  app.delete('/api/v1/accounts/:id/statements/:sid', (req, res) => respond(req, res, 'deleteStatement', '/api/v1/accounts/{id}/statements/{sid}', p(req)))
  // Catch-all: path-to-regexp 0.1.x named wildcard captures the remainder (incl. '/') into :path.
  app.get('/api/v1/files/:path(.*)', (req, res) => respond(req, res, 'catchAllFile', '/api/v1/files/{path}', p(req)))
}

// Prefix mount: an express.Router mounted at /api/v2.
const v2 = express.Router()
v2.get('/accounts/:id', (req, res) => respond(req, res, 'getAccountV2', '/api/v2/accounts/{id}', p(req)))
app.use('/api/v2', v2)

// Unmatched (path or method) -> 404 NOT_FOUND
app.use((req, res) => res.status(404).json({ op_id: 'NOT_FOUND', framework: FRAMEWORK }))
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => res.status(err.status || 500).json({ error: String(err.message || err) }))

app.listen(Number(process.env.PORT || 8080), '0.0.0.0')
