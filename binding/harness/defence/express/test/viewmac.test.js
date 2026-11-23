'use strict'
const test = require('node:test')
const assert = require('node:assert')
const fs = require('fs')
const path = require('path')
const http = require('http')
const vm = require('../viewmac')

const VEC = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'vectors.json'), 'utf8'))

test('canon_path vectors', () => { for (const v of VEC.canon_path) assert.strictEqual(vm.canonPath(v.in), v.out, JSON.stringify(v.in)) })
test('thumbprint vectors', () => { for (const v of VEC.thumbprint) assert.strictEqual(vm.thumbprint(v.jwk), v.jkt, v.jwk.kty) })
test('mac vectors', () => { for (const v of VEC.mac) assert.strictEqual(vm.mac(Buffer.from(v.key, 'utf8'), v.jti, v.method, v.uri, v.jkt), v.out, v.uri) })
test('substitute vectors', () => { for (const v of VEC.substitute) assert.strictEqual(vm.substitute(v.template, v.params), v.out, JSON.stringify(v.params)) })
for (const v of VEC.check) {
  test('check: ' + v.name, () => {
    const r = vm.check(Buffer.from(v.key, 'utf8'), v.headers['x-verified-view'], v.headers.dpop, v.method, v.template, v.params)
    assert.deepStrictEqual([r.ok, r.reason], [v.expect.ok, v.expect.reason])
    if (v.expect.path !== null) assert.strictEqual(r.path, v.expect.path)
  })
}
test('empty key refused', () => {
  assert.throws(() => vm.viewMac(''))
  assert.throws(() => vm.check(Buffer.alloc(0), [], [], 'GET', '/', {}))
})

// ------------------------------------------------------------------ Express adapter
const express = require('express')
const methodOverride = require('method-override')
const KEY = 'adapter-key'
const DPOP = VEC.check.find((c) => c.name === 'benign_get').headers.dpop[0]
const [JTI, JKT] = vm.dpopBinding(DPOP)
const mac = (m, u) => vm.mac(Buffer.from(KEY), JTI, m, u, JKT)

function app () {
  const a = express()
  a.use(methodOverride('X-HTTP-Method-Override'))
  const g = vm.viewMac(KEY)
  const h = (req, res) => res.json({ m: req.method, path: req.viewMac.path })
  a.get('/api/v1/accounts/:id', g, h)
  a.delete('/api/v1/accounts/:id', g, h)
  a.get('/api/v1/public/:file', g, h)
  const v2 = express.Router()
  v2.get('/accounts/:id', g, h)
  a.use('/api/v2', v2)
  return a
}

function send (server, method, target, headers) { // headers: array of [k, v] (duplicates allowed)
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: server.address().port, method, path: target, headers: [].concat(['Host', 'api.bench.test'], ...headers) }, (res) => {
      let b = ""; res.on("data", (d) => { b += d }); res.on("end", () => { let body; try { body = JSON.parse(b) } catch (e) { body = { raw: b } } resolve({ status: res.statusCode, body, headers: res.headers }) })
    })
    req.on('error', reject); req.end()
  })
}

test('express adapter', async (t) => {
  const server = app().listen(0, '127.0.0.1')
  await new Promise((resolve) => server.once('listening', resolve))
  t.after(() => server.close())
  let r = await send(server, 'GET', '/api/v1/accounts/acc-alice-1', [['X-Verified-View', mac('GET', '/api/v1/accounts/acc-alice-1')], ['DPoP', DPOP]])
  assert.strictEqual(r.status, 200, JSON.stringify(r.body)); assert.strictEqual(r.body.path, "/api/v1/accounts/acc-alice-1")
  // prefix-mounted router: template includes req.baseUrl
  r = await send(server, 'GET', '/api/v2/accounts/acc-alice-1', [['X-Verified-View', mac('GET', '/api/v2/accounts/acc-alice-1')], ['DPoP', DPOP]])
  assert.strictEqual(r.status, 200)
  r = await send(server, 'GET', '/api/v2/accounts/acc-alice-1', [['X-Verified-View', mac('GET', '/api/v1/accounts/acc-alice-1')], ['DPoP', DPOP]])
  assert.strictEqual(r.status, 401)
  // Express decodes %2F inside a param: re-encoded, so it still matches the verifier's view
  r = await send(server, 'GET', '/api/v1/public/a%2Fb', [['X-Verified-View', mac('GET', '/api/v1/public/a%2Fb')], ['DPoP', DPOP]])
  assert.strictEqual(r.status, 200); assert.strictEqual(r.body.path, '/api/v1/public/a%2Fb')
  // decoded '..' param: fail closed
  r = await send(server, 'GET', '/api/v1/public/%2E%2E', [['X-Verified-View', mac('GET', '/api/v1/public/%2E%2E')], ['DPoP', DPOP]])
  assert.strictEqual(r.status, 401); assert.strictEqual(r.body.reason, 'view_param_dot_segment')
  // G1 method override: verifier saw POST, executor dispatches DELETE
  r = await send(server, 'POST', '/api/v1/accounts/acc-alice-1', [['X-HTTP-Method-Override', 'DELETE'], ['X-Verified-View', mac('POST', '/api/v1/accounts/acc-alice-1')], ['DPoP', DPOP]])
  assert.strictEqual(r.status, 401); assert.strictEqual(r.body.reason, 'view_mac_mismatch')
  assert.match(r.headers['www-authenticate'], /^DPoP/)
  r = await send(server, 'POST', '/api/v1/accounts/acc-alice-1', [['X-HTTP-Method-Override', 'DELETE'], ['X-Verified-View', mac('DELETE', '/api/v1/accounts/acc-alice-1')], ['DPoP', DPOP]])
  assert.strictEqual(r.status, 200); assert.strictEqual(r.body.m, 'DELETE')
  // missing / duplicated header (G3)
  r = await send(server, 'GET', '/api/v1/accounts/acc-alice-1', [['DPoP', DPOP]])
  assert.strictEqual(r.body.reason, 'view_mac_missing')
  const good = mac('GET', '/api/v1/accounts/acc-alice-1')
  r = await send(server, 'GET', '/api/v1/accounts/acc-alice-1', [['X-Verified-View', good], ['X-Verified-View', good], ['DPoP', DPOP]])
  assert.strictEqual(r.status, 401); assert.strictEqual(r.body.reason, 'view_mac_multiple')
})
