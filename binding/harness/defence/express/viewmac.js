'use strict'
// Defence D-B, executor side: view-binding MAC check (CONTRACT sections 8 and 10). No dependencies.
// The verifier emits  X-Verified-View: v1;b64url(HMAC-SHA256(K, jti\nUPPER(method)\ncanon_path\njkt)).
// The executor recomputes it over ITS OWN view: req.method after method-override and the matched
// route template with req.params substituted, RFC 3986-normalised. 401 on missing/mismatch.
const crypto = require('crypto')

const HEADER = 'x-verified-view'
const UNRESERVED = /^[A-Za-z0-9\-._~]$/
const VALUE = /^v1;[A-Za-z0-9_-]{43}$/

function removeDotSegments (path) { // RFC 3986 section 5.2.4
  let inp = path
  const out = []
  while (inp.length) {
    if (inp.startsWith('../')) inp = inp.slice(3)
    else if (inp.startsWith('./')) inp = inp.slice(2)
    else if (inp.startsWith('/./')) inp = '/' + inp.slice(3)
    else if (inp === '/.') inp = '/'
    else if (inp.startsWith('/../')) { inp = '/' + inp.slice(4); out.pop() } else if (inp === '/..') { inp = '/'; out.pop() } else if (inp === '.' || inp === '..') inp = ''
    else {
      const i = inp.indexOf('/', 1)
      const seg = i === -1 ? inp : inp.slice(0, i)
      inp = i === -1 ? '' : inp.slice(i)
      out.push(seg)
    }
  }
  return out.join('')
}

function normalisePct (s) {
  return s.replace(/%([0-9A-Fa-f]{2})/g, (m, hx) => {
    const ch = String.fromCharCode(parseInt(hx, 16))
    return UNRESERVED.test(ch) ? ch : '%' + hx.toUpperCase()
  })
}

function canonPath (uri) {
  let path
  if (!uri.startsWith('/') && /^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(uri)) {
    path = /^[^:/?#]+:\/\/[^/?#]*([^?#]*)/.exec(uri)[1]
  } else {
    path = uri.split(/[?#]/, 1)[0]
  }
  return removeDotSegments(normalisePct(path)) || '/'
}

// Same encoder as the executors' D-A (python quote safe="-._~!$&'()*+,;=:@")
function encSegment (v) {
  return encodeURIComponent(String(v))
    .replace(/[!'()*]/g, (c) => c) // already literal in encodeURIComponent
    .replace(/%(24|26|2B|2C|3B|3D|3A|40)/g, (m) => decodeURIComponent(m))
}

function substitute (template, params) {
  let out = template
  for (const [k, v] of Object.entries(params)) out = out.split('{' + k + '}').join(encSegment(v))
  return out
}

const b64u = (buf) => Buffer.from(buf).toString('base64url')
const PLAIN = /^[\x20-\x21\x23-\x5b\x5d-\x7e]*$/ // JSON-safe without escaping

function thumbprint (jwk) {
  if (!jwk || typeof jwk !== 'object') return null
  const members = { EC: ['crv', 'kty', 'x', 'y'], RSA: ['e', 'kty', 'n'], OKP: ['crv', 'kty', 'x'] }[jwk.kty]
  if (!members || !members.every((m) => typeof jwk[m] === 'string' && PLAIN.test(jwk[m]))) return null
  const json = '{' + members.map((m) => JSON.stringify(m) + ':' + JSON.stringify(jwk[m])).join(',') + '}'
  return b64u(crypto.createHash('sha256').update(json, 'utf8').digest())
}

function dpopBinding (dpop) {
  try {
    const parts = dpop.trim().split('.')
    if (parts.length !== 3) return null
    const hdr = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'))
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'))
    const jti = claims && typeof claims === 'object' ? claims.jti : undefined
    const jkt = hdr && typeof hdr === 'object' ? thumbprint(hdr.jwk) : null
    if (typeof jti !== 'string' || !jkt) return null
    return [jti, jkt]
  } catch (e) { return null }
}

function mac (key, jti, method, path, jkt) {
  const msg = [jti, method.toUpperCase(), canonPath(path), jkt].join('\n')
  return 'v1;' + b64u(crypto.createHmac('sha256', key).update(msg, 'utf8').digest())
}

/** viewValues/dpopValues: every received value of X-Verified-View / DPoP, in order. */
function check (key, viewValues, dpopValues, method, template, params) {
  if (!key || !key.length) throw new Error('DEFENCE=db requires a non-empty VIEW_MAC_KEY')
  if (viewValues.length === 0) return { ok: false, reason: 'view_mac_missing', path: null }
  if (viewValues.length > 1) return { ok: false, reason: 'view_mac_multiple', path: null }
  const got = viewValues[0].replace(/^[ \t]+|[ \t]+$/g, '')
  if (!VALUE.test(got)) return { ok: false, reason: 'view_mac_malformed', path: null }
  if (dpopValues.length !== 1) return { ok: false, reason: 'view_mac_no_dpop', path: null }
  const binding = dpopBinding(dpopValues[0])
  if (!binding) return { ok: false, reason: 'view_mac_no_dpop', path: null }
  if (Object.values(params).some((v) => String(v) === '.' || String(v) === '..')) {
    return { ok: false, reason: 'view_param_dot_segment', path: null }
  }
  let path
  try { path = canonPath(substitute(template, params)) } catch (e) { return { ok: false, reason: 'view_unencodable', path: null } }
  const want = Buffer.from(mac(key, binding[0], method, path, binding[1]), 'utf8')
  const gotB = Buffer.from(got, 'utf8')
  // lengths are public (fixed by the VALUE regex); timingSafeEqual needs equal lengths
  const ok = want.length === gotB.length && crypto.timingSafeEqual(want, gotB)
  return { ok, reason: ok ? 'ok' : 'view_mac_mismatch', path }
}

function rawValues (req, name) {
  const out = []
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    if (req.rawHeaders[i].toLowerCase() === name) out.push(req.rawHeaders[i + 1])
  }
  return out
}

/** Full matched template in {name} form, e.g. req.baseUrl '/api/v2' + route '/accounts/:id'. */
function routeTemplate (req) {
  if (!req.route || typeof req.route.path !== 'string') return null
  return (req.baseUrl + req.route.path).replace(/:([A-Za-z0-9_]+)/g, '{$1}')
}

/**
 * Express middleware. Mount it per route or per router *after* methodOverride so that req.route,
 * req.params and the effective req.method are known, e.g.
 *   app.get('/api/v1/accounts/:id', viewMac(key), handler)
 * (app.use()/router.use() middleware runs before route matching, so req.route is unset there.)
 */
function viewMac (key, opts = {}) {
  const keyBuf = Buffer.from(key || '', 'utf8')
  if (!keyBuf.length) throw new Error('DEFENCE=db requires a non-empty VIEW_MAC_KEY')
  return function viewMacMiddleware (req, res, next) {
    const template = routeTemplate(req)
    const r = template === null
      ? { ok: false, reason: 'view_route_unknown', path: null }
      : check(keyBuf, rawValues(req, HEADER), rawValues(req, 'dpop'), req.method, template, Object.assign({}, req.params))
    req.viewMac = r
    if (r.ok) return next()
    if (opts.onDeny) return opts.onDeny(req, res, r)
    res.set('WWW-Authenticate', 'DPoP error="invalid_token"')
    return res.status(401).json({ error: 'view_binding', reason: r.reason })
  }
}

module.exports = { HEADER, canonPath, removeDotSegments, normalisePct, substitute, encSegment, thumbprint, dpopBinding, mac, check, rawValues, routeTemplate, viewMac }
