/**
 * 离线测试：签名算法确定性、模型目录、思考档位。
 * 红线：不发真实网络请求、不读真实凭据、不打印 token。
 */
import { test, expect } from 'bun:test'
import { computeSignature, buildAuthHeaders, isUpstreamHost, signedPathFrom } from '../lib/sign.mjs'
import { MODELS, buildModels, TELEAI_BASE_URL, TELEAI_SIGNED_PATH } from '../lib/models.mjs'
import { normalizeEffort, normalizeUpstreamBody, reasoningOfBody } from '../lib/effort.mjs'

/**
 * 合成 JWT：三段形状真实（header.payload.signature），内容全是测试值。
 * 不含任何真实凭据；签名段是 64 位十六进制，正好对齐上游「把 JWT 第三段当 HMAC key」的用法。
 */
const JWT = [
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
  'eyJhY2NvdW50SWQiOiJhY2MtMDEiLCJleHAiOjE4OTM0NTYwMDB9',
  'deadbeef'.repeat(8),
].join('.')

test('签名是确定性的：同样的输入得到同样的 sig', () => {
  const input = {
    token: JWT, installId: 'inst-1', appVersion: '3.0.1',
    method: 'POST', pathname: TELEAI_SIGNED_PATH,
    ts: '1700000000', nonce: 'nonce-fixed', body: '{"model":"chat-pro"}',
  }
  const a = computeSignature(input)
  const b = computeSignature(input)
  expect(a.signature).toBe(b.signature)
  expect(a.k1).toHaveLength(64)
  expect(a.signature).toHaveLength(64)
  expect(a.signature).toMatch(/^[0-9a-f]{64}$/)
})

test('签名对每个字段敏感', () => {
  const base = {
    token: JWT, installId: 'inst-1', appVersion: '3.0.1',
    method: 'POST', pathname: TELEAI_SIGNED_PATH,
    ts: '1700000000', nonce: 'n1', body: '{}',
  }
  const sig = computeSignature(base).signature
  expect(computeSignature({ ...base, installId: 'inst-2' }).signature).not.toBe(sig)
  expect(computeSignature({ ...base, ts: '1700000001' }).signature).not.toBe(sig)
  expect(computeSignature({ ...base, nonce: 'n2' }).signature).not.toBe(sig)
  expect(computeSignature({ ...base, body: '{"a":1}' }).signature).not.toBe(sig)
  expect(computeSignature({ ...base, method: 'GET' }).signature).not.toBe(sig)
  // pathname 少了 /superCowork/sapi 前缀必须不同（这个坑会 40104）
  expect(computeSignature({ ...base, pathname: '/api/v1/chat/completions' }).signature).not.toBe(sig)
})

test('请求头包含全部签名头，且 Authorization 仅在给了 apiKey 时出现', () => {
  const auth = { token: JWT, installId: 'i', deviceId: 'd', appVersion: '3.0.1' }
  const h = buildAuthHeaders(auth, { body: '{}', apiKey: 'sk-test' })
  for (const key of [
    'X-Token', 'X-App-Version', 'X-Route-Target', 'X-Superagent-Device-Id',
    'X-Superagent-Install-Id', 'X-Superagent-Timestamp', 'X-Superagent-Nonce',
    'X-Superagent-Sign-Version', 'X-Superagent-Signature', 'X-Session-Id', 'X-Message-Id',
  ]) expect(h[key]).toBeTruthy()
  expect(h['X-Superagent-Sign-Version']).toBe('v1')
  expect(h['X-Teleai-Root-Session-Id']).toBe(h['X-Session-Id'])
  expect(h.Authorization).toBe('Bearer sk-test')
  expect(buildAuthHeaders(auth, { body: '{}' }).Authorization).toBeUndefined()
})

test('上游域名判定按 origin，挡掉仿冒与协议降级', () => {
  expect(isUpstreamHost('https://agent.teleai.com.cn/superCowork/sapi/api/v1/chat/completions')).toBe(true)
  expect(isUpstreamHost('https://agent.teleai.com.cn.evil.test/x')).toBe(false)
  expect(isUpstreamHost('http://agent.teleai.com.cn/x')).toBe(false)
  expect(isUpstreamHost('not a url')).toBe(false)
})

test('signedPathFrom 保留 /superCowork/sapi 前缀与查询串', () => {
  expect(signedPathFrom(TELEAI_BASE_URL + '/chat/completions')).toBe(TELEAI_SIGNED_PATH)
  expect(signedPathFrom(TELEAI_BASE_URL + '/chat/completions?a=1')).toBe(TELEAI_SIGNED_PATH + '?a=1')
})

test('模型目录：5 个模型，输出上限与看到的一致', () => {
  expect(MODELS.map((m) => m.id)).toEqual([
    'chat-pro', 'chat-flagship', 'chat-flash', 'chat-lite', 'chat-nano',
  ])
  const byId = Object.fromEntries(MODELS.map((m) => [m.id, m]))
  expect(byId['chat-pro'].maxTokens).toBe(65_536)
  expect(byId['chat-lite'].maxTokens).toBe(16_384)
  expect(byId['chat-nano'].maxTokens).toBe(16_384)
  // 只有实测支持视觉的两个模型声明 image
  const visionIds = MODELS.filter((m) => m.vision).map((m) => m.id)
  expect(visionIds).toEqual(['chat-pro', 'chat-flash'])
})

test('buildModels 产出 magpie 认的形状，rate 保留厂商写法', () => {
  const models = buildModels()
  expect(Object.keys(models)).toHaveLength(5)
  const pro = models['chat-pro']
  expect(pro.name).toBe('智能 · x0.6')
  expect(pro.rate).toBe('x0.6')
  expect(pro.limit.output).toBe(65_536)
  expect(pro.modalities.input).toEqual(['text', 'image'])
  expect(pro.interleaved).toEqual({ field: 'reasoning_content' })
  expect(models['chat-nano'].modalities.input).toEqual(['text'])
})

test('思考档位：三档原样，其余就近落档或删除字段', () => {
  expect(normalizeEffort('low')).toBe('low')
  expect(normalizeEffort('high')).toBe('high')
  expect(normalizeEffort('max')).toBe('max')
  expect(normalizeEffort('medium')).toBe('high')
  expect(normalizeEffort('minimal')).toBe('low')
  expect(normalizeEffort('xhigh')).toBe('high')
  expect(normalizeEffort('off')).toBeNull()
  expect(normalizeEffort('')).toBeNull()
})

test('normalizeUpstreamBody：不碰无关字段，medium 改成 high', () => {
  const raw = JSON.stringify({ model: 'chat-pro', messages: [{ role: 'user', content: 'hi' }], reasoning_effort: 'medium' })
  const r = normalizeUpstreamBody(raw)
  expect(r.changed).toBe(true)
  expect(r.from).toBe('medium')
  expect(r.to).toBe('high')
  const parsed = JSON.parse(r.body)
  expect(parsed.reasoning_effort).toBe('high')
  expect(parsed.messages).toEqual([{ role: 'user', content: 'hi' }])
})

test('normalizeUpstreamBody：已经是合法档位时原样返回同一字符串', () => {
  const raw = JSON.stringify({ model: 'chat-pro', reasoning_effort: 'high' })
  const r = normalizeUpstreamBody(raw)
  expect(r.changed).toBe(false)
  expect(r.body).toBe(raw)
})

test('normalizeUpstreamBody：关闭思考的写法直接删字段', () => {
  const raw = JSON.stringify({ model: 'chat-pro', reasoning_effort: 'off', thinking: { type: 'disabled' } })
  const r = normalizeUpstreamBody(raw)
  expect(r.changed).toBe(true)
  const parsed = JSON.parse(r.body)
  expect(parsed.reasoning_effort).toBeUndefined()
  expect(parsed.thinking).toBeUndefined()
  expect(parsed.model).toBe('chat-pro')
})

test('normalizeUpstreamBody：非 JSON 与非对象原样放行', () => {
  expect(normalizeUpstreamBody('not json').changed).toBe(false)
  expect(normalizeUpstreamBody('').changed).toBe(false)
  expect(normalizeUpstreamBody('[1,2,3]').changed).toBe(false)
})

test('reasoningOfBody 读出档位', () => {
  expect(reasoningOfBody(JSON.stringify({ reasoning_effort: 'max' }))).toBe('max')
  expect(reasoningOfBody('bad')).toBe('')
})
