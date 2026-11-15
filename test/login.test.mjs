/**
 * 离线测试：登录模块（设备身份派生、手动 token、cookie 凭据挑选、续期请求形状）。
 * 红线：不联网、不启动真实浏览器、不打印 token。
 */
import { test, expect } from 'bun:test'
import crypto from 'node:crypto'
import {
  deriveDeviceIdentity, loginWithManualToken, refreshAccessToken, pickCredentials, tokenKind,
  COOKIE_NAMES, HEADER_TOKEN_NAMES, LOGIN_URL, TOKEN_REFRESH_URL,
} from '../lib/login.mjs'

/** 造一个 payload 可控的 JWT（不签名，只是形状对）。 */
function mkJwt(claims) {
  const h = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')
  const p = Buffer.from(JSON.stringify(claims)).toString('base64url')
  return `${h}.${p}.${crypto.randomBytes(8).toString('base64url')}`
}

const SSO_TOKEN = mkJwt({ tokenType: 'uc_auth_token_ty', 'x-aicloud-account-id': 'a1' })
const PORTAL_TOKEN = mkJwt({ exp: Math.floor(Date.now() / 1000) + 86400, userInfo: { name: 'x' } })

test('设备身份派生：同 seed 稳定，不同 seed 不同', () => {
  const a = deriveDeviceIdentity('acc-1')
  const b = deriveDeviceIdentity('acc-1')
  const c = deriveDeviceIdentity('acc-2')
  expect(a).toEqual(b)
  expect(a.deviceId).not.toBe(c.deviceId)
  expect(a.installId).not.toBe(c.installId)
})

test('deviceId 是 12 位 hex，installId 是 UUIDv4 形态', () => {
  const { deviceId, installId } = deriveDeviceIdentity('x')
  expect(deviceId).toMatch(/^[0-9a-f]{12}$/)
  expect(installId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
})

test('空 seed 也能派生（不抛）', () => {
  expect(() => deriveDeviceIdentity(undefined)).not.toThrow()
  expect(deriveDeviceIdentity(undefined).deviceId).toHaveLength(12)
})

test('手动 token：去空白后接受', () => {
  const r = loginWithManualToken('  aaa.bbb.ccc  ')
  expect(r.ok).toBe(true)
  expect(r.token).toBe('aaa.bbb.ccc')
})

test('手动 token：空值给出可操作提示', () => {
  const r = loginWithManualToken('   ')
  expect(r.ok).toBe(false)
  expect(r.error).toContain('粘贴 token')
})

test('登录常量指向 teleai 域，不是聊天网关', () => {
  expect(LOGIN_URL.startsWith('https://agent.teleai.com.cn/meter/teleagent-login/middle')).toBe(true)
  expect(TOKEN_REFRESH_URL).toBe('https://agent.teleai.com.cn/superCowork/sapi/cowork/auth/token-refresh')
  expect(COOKIE_NAMES).toContain('operationToken')
  expect(HEADER_TOKEN_NAMES).toContain('x-token')
})

test('pickCredentials：优先 operationToken，并带回 operToken 作门户凭据', () => {
  const r = pickCredentials([
    { name: 'operToken', value: 'oe', domain: '.teleai.com.cn' },
    { name: 'operationToken', value: 'ot', domain: 'agent.teleai.com.cn' },
  ])
  expect(r.token).toBe('ot')
  expect(r.operationToken).toBe('ot')
  expect(r.operToken).toBe('oe')
})

test('pickCredentials：只认 teleai 域，别域同名 cookie 不算', () => {
  expect(pickCredentials([{ name: 'operationToken', value: 'x', domain: '.evil.test' }])).toBeNull()
  expect(pickCredentials([])).toBeNull()
  expect(pickCredentials(null)).toBeNull()
})

test('pickCredentials：没有 operationToken 时回退 accessToken / x-token', () => {
  expect(pickCredentials([{ name: 'accessToken', value: 'at', domain: '.teleai.com.cn' }]).token).toBe('at')
  expect(pickCredentials([{ name: 'x-token', value: 'xt', domain: '.teleai.com.cn' }]).token).toBe('xt')
})

test('tokenKind：uc_auth_token 判 sso，门户 JWT 判 portal，非 JWT 判 opaque', () => {
  expect(tokenKind(SSO_TOKEN)).toBe('sso')
  expect(tokenKind(PORTAL_TOKEN)).toBe('portal')
  expect(tokenKind('plain-token')).toBe('opaque')
  expect(tokenKind('')).toBe('opaque')
  expect(tokenKind(undefined)).toBe('opaque')
})

test('pickCredentials：聊天拿 sso token，门户拿子域门户 token（不再互换）', () => {
  const r = pickCredentials([
    { name: 'operationToken', value: SSO_TOKEN, domain: '.teleai.com.cn', path: '/' },
    { name: 'operationToken', value: PORTAL_TOKEN, domain: 'agent.teleai.com.cn', path: '/' },
    { name: 'userId', value: '1000000000000000001', domain: 'agent.teleai.com.cn', path: '/' },
  ])
  // 聊天网关只认 uc_auth_token
  expect(r.token).toBe(SSO_TOKEN)
  // 门户只认子域那份带 userInfo 的 JWT
  expect(r.operationToken).toBe(PORTAL_TOKEN)
  expect(r.userId).toBe('1000000000000000001')
  // 整包 cookie 都在，门户请求要带上
  expect(Object.keys(r.jar).sort()).toEqual(['operationToken', 'userId'])
})

test('pickCredentials：子域在前也不会让门户 token 顶掉聊天 token', () => {
  const r = pickCredentials([
    { name: 'operationToken', value: PORTAL_TOKEN, domain: 'agent.teleai.com.cn', path: '/' },
    { name: 'operationToken', value: SSO_TOKEN, domain: '.teleai.com.cn', path: '/' },
  ])
  expect(r.token).toBe(SSO_TOKEN)
  expect(r.operationToken).toBe(PORTAL_TOKEN)
})

test('续期：成功解析 accessToken，ts 是 10 位秒', async () => {
  const fetchImpl = async (url, init) => {
    expect(url).toBe(TOKEN_REFRESH_URL)
    expect(init.method).toBe('POST')
    expect(init.headers['X-Token']).toBe('tok-1')
    expect(init.headers['X-SuperAgent-Device-Id']).toBe('dev-1')
    expect(String(init.headers['X-Timestamp'])).toMatch(/^\d{10}$/)
    return new Response(JSON.stringify({ data: { accessToken: 'tok-2', expiresIn: 604799 } }), {
      status: 200, headers: { 'Content-Type': 'application/json' },
    })
  }
  const r = await refreshAccessToken({ token: 'tok-1', deviceId: 'dev-1' }, { fetchImpl })
  expect(r.ok).toBe(true)
  expect(r.token).toBe('tok-2')
  expect(r.expiresIn).toBe(604799)
})

test('续期：401 报需要重新登录，不抛错', async () => {
  const fetchImpl = async () => new Response('{"code":40112}', { status: 401 })
  const r = await refreshAccessToken({ token: 't', deviceId: 'd' }, { fetchImpl })
  expect(r.ok).toBe(false)
  expect(r.error).toContain('重新登录')
})

test('续期：响应缺 accessToken 时如实报错', async () => {
  const fetchImpl = async () => new Response(JSON.stringify({ data: {} }), { status: 200 })
  const r = await refreshAccessToken({ token: 't', deviceId: 'd' }, { fetchImpl })
  expect(r.ok).toBe(false)
  expect(r.error).toContain('accessToken')
})

test('续期：网络异常被吞成结构化错误', async () => {
  const fetchImpl = async () => { throw new Error('ECONNRESET') }
  const r = await refreshAccessToken({ token: 't', deviceId: 'd' }, { fetchImpl })
  expect(r.ok).toBe(false)
  expect(r.error).toContain('ECONNRESET')
})
