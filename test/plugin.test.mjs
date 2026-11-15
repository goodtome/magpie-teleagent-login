/**
 * 离线测试：插件入口的钩子形状与「不花钱」路径。
 * 全程不发真实网络请求：需要发请求的用例都替换 globalThis.fetch。
 */
import { test, expect, beforeEach, afterEach } from 'bun:test'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import TeleAgentLoginPlugin, { PROVIDER, _internal } from '../index.mjs'
import { saveAccount } from '../lib/credential.mjs'
import { TELEAI_BASE_URL } from '../lib/models.mjs'

let dir
let oldEnv

/** 造一个假 JWT：只用于取声明，签名不校验。 */
function mkTok(claims = {}) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')
  const payload = Buffer.from(JSON.stringify({
    accountId: 'acc-1',
    accountName: '测试账号',
    exp: Math.floor(Date.now() / 1000) + 30 * 86400,
    ...claims,
  })).toString('base64url')
  return `${header}.${payload}.${crypto.randomBytes(8).toString('base64url')}`
}

function storeFile() {
  return path.join(dir, 'teleagent-login', 'accounts.json')
}

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ta-plugin-'))
  oldEnv = process.env.TELEAGENT_PLUGIN_DATA
  process.env.TELEAGENT_PLUGIN_DATA = dir
})
afterEach(() => {
  if (oldEnv === undefined) delete process.env.TELEAGENT_PLUGIN_DATA
  else process.env.TELEAGENT_PLUGIN_DATA = oldEnv
  try { fs.rmSync(dir, { recursive: true, force: true }) } catch { /* 忽略 */ }
})

test('插件是函数，返回完整钩子集合', async () => {
  expect(typeof TeleAgentLoginPlugin).toBe('function')
  const hooks = await TeleAgentLoginPlugin({})
  for (const key of ['config', 'auth', 'provider', 'chat.headers', 'tool']) {
    expect(hooks[key]).toBeDefined()
  }
  expect(hooks.auth.provider).toBe(PROVIDER)
  expect(hooks.auth.maxConcurrency).toBe(2)
})

test('config 钩子声明供应商与 5 个模型，且不覆盖已有配置', async () => {
  const hooks = await TeleAgentLoginPlugin({})
  const cfg = {}
  await hooks.config(cfg)
  expect(cfg.provider[PROVIDER].api).toBe(TELEAI_BASE_URL)
  expect(cfg.provider[PROVIDER].npm).toBe('@ai-sdk/openai-compatible')
  expect(Object.keys(cfg.provider[PROVIDER].models)).toHaveLength(5)

  const existing = { provider: { [PROVIDER]: { name: '自定义', api: 'https://custom.test' } } }
  await hooks.config(existing)
  expect(existing.provider[PROVIDER].name).toBe('自定义')
  expect(existing.provider[PROVIDER].api).toBe('https://custom.test')
})

test('登录方式：浏览器免输入、手动 token 一个输入框、补门户 cookie 一个输入框', async () => {
  const hooks = await TeleAgentLoginPlugin({})
  const methods = hooks.auth.methods
  expect(methods).toHaveLength(3)
  const browser = methods.find((m) => m.label.includes('浏览器'))
  const manual = methods.find((m) => m.label.includes('手动'))
  const portal = methods.find((m) => m.label.includes('门户'))
  expect(browser.keyless).toBe(true)
  expect(browser.prompts).toEqual([])
  expect(manual.keyless).toBe(false)
  expect(manual.prompts[0].key).toBe('token')
  expect(portal.prompts[0].key).toBe('cookie')
})

test('补门户 cookie：只覆盖 portal 字段，关键字段与 key 不变', async () => {
  const hooks = await TeleAgentLoginPlugin({})
  const manual = hooks.auth.methods.find((m) => m.label.includes('手动'))
  const first = await manual.authorize({ token: mkTok() })
  expect(first.key).toBe('acc-1')

  const portal = hooks.auth.methods.find((m) => m.label.includes('门户'))
  const res = await portal.authorize({ cookie: 'portal-jwt' })
  expect(res.type).toBe('success')
  // key 不因补门户而改变（否则 magpie 里已存的登录作用域会失联）
  expect(res.key).toBe('acc-1')
  const store = JSON.parse(fs.readFileSync(storeFile(), 'utf8'))
  expect(store.current).toBe('acc-1')
  const acc = store.accounts['acc-1']
  expect(acc.portal.operationToken).toBe('portal-jwt')
  expect(acc.portal.userId).toBe('acc-1')
  expect(typeof acc.token).toBe('string')
})

test('补门户 cookie：未登录时给出可操作失败而不是崩', async () => {
  const hooks = await TeleAgentLoginPlugin({})
  const portal = hooks.auth.methods.find((m) => m.label.includes('门户'))
  const res = await portal.authorize({ cookie: 'portal-jwt' })
  expect(res.type).toBe('failed')
  expect(res.error).toContain('登录')
})

test('手动 token 授权：写入凭据库并返回 magpie 认的 success', async () => {
  const hooks = await TeleAgentLoginPlugin({})
  const manual = hooks.auth.methods.find((m) => m.label.includes('手动'))
  const result = await manual.authorize({ token: mkTok() })
  expect(result.type).toBe('success')
  expect(result.key).toBe('acc-1')
  expect(result.metadata.accountName).toBe('测试账号')
  expect(result.metadata.expiresAt).toBeGreaterThan(Date.now())
  const raw = fs.readFileSync(storeFile(), 'utf8')
  expect(JSON.parse(raw).current).toBe('acc-1')
})

test('手动 token 授权：空 token 失败而不是崩', async () => {
  const hooks = await TeleAgentLoginPlugin({})
  const manual = hooks.auth.methods.find((m) => m.label.includes('手动'))
  const result = await manual.authorize({ token: '' })
  expect(result.type).toBe('failed')
  expect(result.error).toBeTruthy()
})

test('loader：未登录时抛错并标 signIn=expired', async () => {
  const hooks = await TeleAgentLoginPlugin({})
  const loader = await hooks.auth.loader(async () => ({ key: 'acc-1' }))
  expect(loader.baseURL).toBe(TELEAI_BASE_URL)
  await expect(loader.fetch(TELEAI_BASE_URL + '/chat/completions', { method: 'POST', body: '{}' }))
    .rejects.toThrow()
})

test('loader：目录外模型在发请求前就 404，不碰网络', async () => {
  saveAccount({ token: mkTok() }, storeFile())
  const hooks = await TeleAgentLoginPlugin({})
  const loader = await hooks.auth.loader(async () => ({ key: 'acc-1' }))
  const res = await loader.fetch(TELEAI_BASE_URL + '/chat/completions', {
    method: 'POST',
    body: JSON.stringify({ model: 'chat-unknown', messages: [] }),
  })
  expect(res.status).toBe(404)
  const json = await res.json()
  expect(json.error.message).toContain('chat-unknown')
  expect(json.error.message).toContain('chat-pro')
})

test('loader：签名请求只发上游，改域名时拒发且不泄露凭据', async () => {
  saveAccount({ token: mkTok() }, storeFile())
  const hooks = await TeleAgentLoginPlugin({})
  const loader = await hooks.auth.loader(async () => ({ key: 'acc-1' }))
  await expect(loader.fetch('https://evil.test/chat/completions', {
    method: 'POST',
    body: JSON.stringify({ model: 'chat-pro' }),
  })).rejects.toThrow()
})

test('loader：正常请求带上签名头且思考档位被削', async () => {
  saveAccount({ token: mkTok() }, storeFile())
  const hooks = await TeleAgentLoginPlugin({})
  const loader = await hooks.auth.loader(async () => ({ key: 'acc-1' }))

  const realFetch = globalThis.fetch
  let captured = null
  globalThis.fetch = async (url, init) => {
    captured = { url: String(url), headers: init.headers, body: init.body }
    return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } })
  }
  try {
    const res = await loader.fetch(TELEAI_BASE_URL + '/chat/completions', {
      method: 'POST',
      body: JSON.stringify({ model: 'chat-pro', reasoning_effort: 'medium', messages: [] }),
    })
    expect(res.status).toBe(200)
  } finally {
    globalThis.fetch = realFetch
  }
  expect(captured).not.toBeNull()
  expect(captured.url).toBe(TELEAI_BASE_URL + '/chat/completions')
  const h = captured.headers
  expect(h.get('x-superagent-signature')).toMatch(/^[0-9a-f]{64}$/)
  expect(h.get('x-superagent-sign-version')).toBe('v1')
  expect(h.get('x-superagent-timestamp')).toMatch(/^\d{10}$/)
  expect(h.get('x-token')).toBeTruthy()
  expect(h.get('x-teleai-run-unit-type')).toBe('agent_loop')
  expect(h.get('x-app-version')).toBe('3.0.1')
  expect(JSON.parse(captured.body).reasoning_effort).toBe('high')
})

test('provider.models 给回 rate 字段', async () => {
  const hooks = await TeleAgentLoginPlugin({})
  const models = await hooks.provider.models({ models: { 'chat-pro': { id: 'chat-pro' }, x: { id: 'x' } } })
  expect(models['chat-pro'].rate).toBe('x0.6')
  expect(models.x.rate).toBeUndefined()
})

test('chat.headers 只给本供应商加会话头，且清洗非法字符', async () => {
  const hooks = await TeleAgentLoginPlugin({})
  const output = { headers: {} }
  await hooks['chat.headers']({ model: { providerID: 'other' }, sessionID: 'ses_1' }, output)
  expect(output.headers['x-teleagent-session']).toBeUndefined()

  await hooks['chat.headers']({ model: { providerID: PROVIDER }, sessionID: 'abc/../def ghi' }, output)
  expect(output.headers['x-teleagent-session']).toBe('abcdefghi')

  const empty = { headers: {} }
  await hooks['chat.headers']({ model: { providerID: PROVIDER }, sessionID: '!!!' }, empty)
  expect(empty.headers['x-teleagent-session']).toBeUndefined()
})

test('points 工具：未登录时返回 ok=false 而不是抛错', async () => {
  const hooks = await TeleAgentLoginPlugin({})
  const r = await hooks.tool.points.execute()
  expect(r.ok).toBe(false)
  expect(r.error).toBeTruthy()
})

test('points 工具：登录了但没有门户凭据时说明积分不可用', async () => {
  saveAccount({ token: mkTok() }, storeFile())
  const hooks = await TeleAgentLoginPlugin({})
  const r = await hooks.tool.points.execute()
  expect(r.ok).toBe(false)
  expect(r.error).toBeTruthy()
})

test('auth.refresh：未登录时抛错', async () => {
  const hooks = await TeleAgentLoginPlugin({})
  await expect(hooks.auth.refresh(async () => ({ key: 'acc-1' }))).rejects.toThrow()
})

test('auth.refresh：成功时落盘新 token 并返回 success', async () => {
  saveAccount({ token: mkTok() }, storeFile())
  const hooks = await TeleAgentLoginPlugin({})
  const oldFetch = globalThis.fetch
  const newToken = mkTok({ exp: Math.floor(Date.now() / 1000) + 60 * 86400 })
  globalThis.fetch = async () => new Response(JSON.stringify({ data: { accessToken: newToken } }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
  try {
    const r = await hooks.auth.refresh(async () => ({ key: 'acc-1' }))
    expect(r.type).toBe('success')
    expect(r.key).toBe('acc-1')
  } finally {
    globalThis.fetch = oldFetch
  }
  const store = JSON.parse(fs.readFileSync(storeFile(), 'utf8'))
  expect(store.accounts['acc-1'].token).toBe(newToken)
  expect(store.accounts['acc-1'].expiresAt).toBeGreaterThan(Date.now() + 59 * 86400 * 1000)
})

test('auth.refresh：续期失败时抛错让 magpie 提示重登', async () => {
  saveAccount({ token: mkTok() }, storeFile())
  const hooks = await TeleAgentLoginPlugin({})
  const oldFetch = globalThis.fetch
  globalThis.fetch = async () => new Response('{"code":40112}', { status: 401 })
  try {
    await expect(hooks.auth.refresh(async () => ({ key: 'acc-1' }))).rejects.toThrow()
  } finally {
    globalThis.fetch = oldFetch
  }
})

test('explainFailure：封禁不改成登录失效，保留 x-magpie-sign-in', async () => {
  const res = new Response(JSON.stringify({ code: 40109, message: 'current user is banned' }), {
    status: 401,
    headers: { 'Content-Type': 'application/json' },
  })
  const out = await _internal.explainFailure(res)
  expect(out.status).toBe(401)
  expect(out.headers.get('x-magpie-sign-in')).toBe('kept')
  const body = await out.json()
  expect(body.code).toBe(40109)
})

test('explainFailure：普通 401 不被改写', async () => {
  const res = new Response('{"message":"nope"}', { status: 401 })
  const out = await _internal.explainFailure(res)
  expect(out.headers.get('x-magpie-sign-in')).toBeNull()
})

test('explainFailure：非 401/403 直接透传', async () => {
  const res = new Response('{}', { status: 500 })
  const out = await _internal.explainFailure(res)
  expect(out.status).toBe(500)
})

test('modelOfBody：坏 JSON 返回空串而不是抛', () => {
  expect(_internal.modelOfBody('not json')).toBe('')
  expect(_internal.modelOfBody('')).toBe('')
  expect(_internal.modelOfBody(JSON.stringify({ model: 'chat-flash' }))).toBe('chat-flash')
})
