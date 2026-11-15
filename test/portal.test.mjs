/**
 * 离线测试：门户（积分/签到）客户端。
 * 全部用注入的 fetchImpl，不发真实请求、不触发真实领取。
 */
import { test, expect, beforeEach, afterEach } from 'bun:test'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import {
  portalRequest, fetchPoints, fetchDailyStatus, claimDaily, fetchUserCenter,
  readPortalAuth, PORTAL_BASE,
} from '../lib/portal.mjs'
import { saveAccount } from '../lib/credential.mjs'

const AUTH = { userId: '12345', operationToken: 'op-token', operToken: 'oper-token' }

/** 记录请求并按队列返回响应。 */
function mockFetch(responses) {
  const calls = []
  const impl = async (url, init) => {
    calls.push({ url: String(url), headers: init?.headers ?? {} })
    const next = responses.shift()
    if (!next) throw new Error('mock 响应已用尽')
    return next
  }
  impl.calls = calls
  return impl
}

const jsonRes = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } })

test('portalRequest：带上 X-Token / userId / Cookie 三个凭据头', async () => {
  const fetchImpl = mockFetch([jsonRes({ code: 200, data: {} })])
  const r = await portalRequest(AUTH, '/points/detail', { fetchImpl })
  expect(r.ok).toBe(true)
  const h = fetchImpl.calls[0].headers
  expect(h['X-Token']).toBe('op-token')
  expect(h.userId).toBe('12345')
  expect(h.Cookie).toBe('operToken=oper-token; operationToken=op-token; userId=12345')
  expect(fetchImpl.calls[0].url).toBe(PORTAL_BASE + '/points/detail')
})

test('portalRequest：整包 cookie 一起发，显式凭据覆盖 jar 里的同名项', async () => {
  const fetchImpl = mockFetch([jsonRes({ code: 200, data: {} })])
  const auth = { ...AUTH, jar: { sso_token: 'sso', operationToken: 'stale', extra: 'x' } }
  await portalRequest(auth, '/points/detail', { fetchImpl })
  const cookie = fetchImpl.calls[0].headers.Cookie
  expect(cookie).toContain('sso_token=sso')
  expect(cookie).toContain('extra=x')
  // jar 里的旧 operationToken 被显式值覆盖，只剩一份
  expect(cookie.match(/operationToken=/g)).toHaveLength(1)
  expect(cookie).toContain('operationToken=op-token')
})

test('portalRequest：业务码非 200 当作失败并保留厂商话术', async () => {
  const fetchImpl = mockFetch([jsonRes({ code: 500, msg: '系统繁忙' })])
  const r = await portalRequest(AUTH, '/points/detail', { fetchImpl })
  expect(r.ok).toBe(false)
  expect(r.error).toContain('系统繁忙')
})

test('portalRequest：HTTP 错误不抛，返回结构化失败', async () => {
  const fetchImpl = mockFetch([new Response('nope', { status: 500 })])
  const r = await portalRequest(AUTH, '/x', { fetchImpl })
  expect(r.ok).toBe(false)
  expect(r.error).toContain('500')
})

test('portalRequest：非 JSON（登录页 HTML）识别为需要重新登录', async () => {
  const fetchImpl = mockFetch([new Response('<html>login</html>', { status: 200 })])
  const r = await portalRequest(AUTH, '/x', { fetchImpl })
  expect(r.ok).toBe(false)
  expect(r.error).toContain('重新登录')
})

test('portalRequest：网络异常被吞成结构化失败', async () => {
  const fetchImpl = async () => { throw new Error('ECONNREFUSED') }
  const r = await portalRequest(AUTH, '/x', { fetchImpl })
  expect(r.ok).toBe(false)
  expect(r.error).toContain('ECONNREFUSED')
})

test('fetchPoints：读出余额与最早到期时间', async () => {
  const fetchImpl = mockFetch([jsonRes({
    code: 200,
    data: {
      pointsBalance: 1280,
      userRole: 'vip',
      groups: [
        { active: [{ effectiveEnd: '2026-12-01' }, { effectiveEnd: '2026-11-20' }] },
      ],
    },
  })])
  const r = await fetchPoints(AUTH, { fetchImpl })
  expect(r.ok).toBe(true)
  expect(r.balance).toBe(1280)
  expect(r.expiresAt).toBe('2026-11-20')
})

test('fetchDailyStatus：映射签到字段', async () => {
  const fetchImpl = mockFetch([jsonRes({
    code: 200,
    data: {
      daily_task: {
        visible: true, daily_claimable_points: 100, claimed_today: false,
        total_claim_days: 7, total_claimed_points: 700, button_text: '领取',
      },
      activity: { visible: true, activity_title: '每日签到', end_date_text: '长期' },
    },
  })])
  const r = await fetchDailyStatus(AUTH, { fetchImpl })
  expect(r.ok).toBe(true)
  expect(r.claimedToday).toBe(false)
  expect(r.claimable).toBe(100)
  expect(r.totalDays).toBe(7)
  expect(r.activity.title).toBe('每日签到')
})

test('claimDaily：今天已领时短路，绝不调用领取接口', async () => {
  const fetchImpl = mockFetch([jsonRes({
    code: 200, data: { daily_task: { claimed_today: true, daily_claimable_points: 100 } },
  })])
  const r = await claimDaily(AUTH, { fetchImpl })
  expect(r.ok).toBe(true)
  expect(r.alreadyClaimed).toBe(true)
  expect(r.claimed).toBe(false)
  // 只发了状态查询这一次，没有 checkTask
  expect(fetchImpl.calls).toHaveLength(1)
  expect(fetchImpl.calls.some((c) => c.url.includes('checkTask'))).toBe(false)
})

test('claimDaily：未领时先查→领取→复查，三次请求', async () => {
  const fetchImpl = mockFetch([
    jsonRes({ code: 200, data: { daily_task: { claimed_today: false, daily_claimable_points: 100 } } }),
    jsonRes({ code: 200, data: {} }),
    jsonRes({ code: 200, data: { daily_task: { claimed_today: true } } }),
  ])
  const r = await claimDaily(AUTH, { fetchImpl })
  expect(r.ok).toBe(true)
  expect(r.claimed).toBe(true)
  expect(r.points).toBe(100)
  expect(fetchImpl.calls).toHaveLength(3)
  expect(fetchImpl.calls[1].url).toContain('type=daily_login')
})

test('fetchUserCenter：套餐名', async () => {
  const fetchImpl = mockFetch([jsonRes({ code: 200, data: { plan_display_name: '旗舰版' } })])
  const r = await fetchUserCenter(AUTH, { fetchImpl })
  expect(r.ok).toBe(true)
  expect(r.planName).toBe('旗舰版')
})

test('readPortalAuth：没存门户凭据时用登录 token 兜底（token-derived）', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ta-portal-'))
  const old = process.env.TELEAGENT_PLUGIN_DATA
  process.env.TELEAGENT_PLUGIN_DATA = dir
  try {
    const file = path.join(dir, 'teleagent-login', 'accounts.json')
    const header = Buffer.from(JSON.stringify({ alg: 'HS256' })).toString('base64url')
    const payload = Buffer.from(JSON.stringify({
      'x-aicloud-account-id': 'a1',
      'x-aicloud-user-id': 'a1',
      exp: Math.floor(Date.now() / 1000) + 86400,
    })).toString('base64url')
    const token = `${header}.${payload}.${crypto.randomBytes(8).toString('base64url')}`
    saveAccount({ token }, file)

    // 没有 portal 字段 → 用 token 兜底，userId 来自 claim（门户 401 的修复点）
    const fallback = readPortalAuth(undefined, 'a1')
    expect(fallback).not.toBeNull()
    expect(fallback.source).toBe('token-derived')
    expect(fallback.operationToken).toBe(token)
    expect(fallback.userId).toBe('a1')

    // 存了门户凭据 → 优先用门户那份
    saveAccount({ token, portal: { operationToken: 'ot', operToken: 'oe' } }, file)
    const auth = readPortalAuth(undefined, 'a1')
    expect(auth).not.toBeNull()
    expect(auth.source).toBe('plugin-credential-store')
    expect(auth.operationToken).toBe('ot')
    expect(auth.operToken).toBe('oe')
    expect(auth.userId).toBe('a1')
  } finally {
    if (old === undefined) delete process.env.TELEAGENT_PLUGIN_DATA
    else process.env.TELEAGENT_PLUGIN_DATA = old
    try { fs.rmSync(dir, { recursive: true, force: true }) } catch { /* 忽略 */ }
  }
})

test('parseClaims：天翼 UCloud 私有 claim 名映射成 accountId / userId', async () => {
  const { parseClaims } = await import('../lib/credential.mjs')
  const header = Buffer.from(JSON.stringify({ alg: 'HS256' })).toString('base64url')
  const payload = Buffer.from(JSON.stringify({
    tokenType: 'uc_auth_token_ty',
    jwtInfoId: 'jwtInfoId-1',
    'x-aicloud-user-type': 1,
    'x-aicloud-account-id': '1000000000000000001',
    'x-aicloud-user-id': '1000000000000000001',
    iat: 1794679558,
  })).toString('base64url')
  const claims = parseClaims(`${header}.${payload}.sig`)
  expect(claims.accountId).toBe('1000000000000000001')
  expect(claims.userId).toBe('1000000000000000001')
  expect(claims.tokenType).toBe('uc_auth_token_ty')
})

test('pickCredentials：整包 cookie 保留，门户 token 取子域那份', async () => {
  const { pickCredentials } = await import('../lib/login.mjs')
  const hit = pickCredentials([
    { name: 'operationToken', value: 'parent-token', domain: 'teleai.com.cn', path: '/' },
    { name: 'operationToken', value: 'sub-token', domain: 'agent.teleai.com.cn', path: '/' },
    { name: 'userId', value: '1000000000000000001', domain: 'agent.teleai.com.cn', path: '/' },
    { name: 'unrelated', value: 'nope', domain: 'example.com', path: '/' },
  ])
  expect(hit).not.toBeNull()
  expect(hit.jar.unrelated).toBeUndefined()
  expect(hit.jar.userId).toBe('1000000000000000001')
  // 门户要子域那份；聊天 token 保持原来的父域那份
  expect(hit.operationToken).toBe('sub-token')
  expect(hit.token).toBe('parent-token')
})
