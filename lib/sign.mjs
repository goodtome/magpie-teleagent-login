/**
 * TeleAgent 上游签名与请求发送。
 *
 * 复用自 opencode-teleagent-auth（MIT, anbulang），仅做免客户端适配：
 * auth 由插件自己的登录流程产生（不再是读桌面端磁盘），签名算法与上游完全一致。
 *
 * 两步 HMAC（逆向自 kernel 的 GatewaySigner.Sign，见 docs/PROTOCOL.md）：
 *   第 1 步  key = JWT 第三段；msg = "superagent-auth-v1/{token}/{installId}/{ts}/{nonce}" → k1
 *   第 2 步  key = k1（当 64 字符 hex 文本）；
 *            msg = "superagent-auth-v1\n{METHOD}\n{pathname}\n{ts}\n{nonce}\n{appVersion}\n{sha256hex(body)}" → sig
 * pathname 必须带 /superCowork/sapi 前缀。
 */
import crypto from 'node:crypto'
import {
  TELEAI_ORIGIN,
  TELEAI_SIGNED_PATH,
  TELEAI_ROUTE_TARGET,
  TELEAI_BASE_URL,
  DEFAULT_APP_VERSION,
} from './models.mjs'

const hex = (buf) => buf.toString('hex')
const sha256hex = (s) => hex(crypto.createHash('sha256').update(s).digest())
const hmacHex = (key, msg) => hex(crypto.createHmac('sha256', key).update(msg).digest())

/** 纯签名函数（无时间依赖，便于单测）。 */
export function computeSignature({ token, installId, appVersion, method, pathname, ts, nonce, body }) {
  const jwtThird = String(token).split('.')[2] ?? ''
  const k1 = hmacHex(jwtThird, `superagent-auth-v1/${token}/${installId}/${ts}/${nonce}`)
  const signature = hmacHex(k1, [
    'superagent-auth-v1',
    method,
    pathname,
    ts,
    nonce,
    appVersion,
    sha256hex(body),
  ].join('\n'))
  return { k1, signature }
}

/** 单次请求的签名头（每次请求都要新的 ts + nonce）。 */
export function buildAuthHeaders(auth, {
  body, method = 'POST', pathname = TELEAI_SIGNED_PATH,
  ts: tsIn, nonce: nonceIn, sessionId, messageId, requestId,
  apiKey = '', appVersion, installId, deviceId,
} = {}) {
  const version = appVersion ?? auth.appVersion ?? DEFAULT_APP_VERSION
  const ts = tsIn ?? String(Math.floor(Date.now() / 1000))
  const nonce = nonceIn ?? crypto.randomUUID()
  const { signature } = computeSignature({
    token: auth.token,
    installId: installId ?? auth.installId ?? '',
    appVersion: version,
    method: method.toUpperCase(),
    pathname,
    ts,
    nonce,
    body: body ?? '',
  })
  const sid = sessionId ?? newSessionId()
  const mid = messageId ?? newMessageId()
  const headers = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
    'X-Token': auth.token,
    'User-Agent': 'super-agent/1.0',
    'X-App-Version': version,
    'X-Route-Target': TELEAI_ROUTE_TARGET,
    'X-Superagent-Device-Id': deviceId ?? auth.deviceId ?? '',
    'X-Superagent-Install-Id': installId ?? auth.installId ?? '',
    'X-Superagent-Timestamp': ts,
    'X-Superagent-Nonce': nonce,
    'X-Superagent-Sign-Version': 'v1',
    'X-Superagent-Signature': signature,
    'X-Teleai-Run-Unit-Type': 'agent_loop',
    'X-Teleai-Upstream-Request-Id': crypto.randomUUID(),
    'X-Request-Id': requestId ?? crypto.randomUUID(),
    'X-Session-Id': sid,
    'X-Message-Id': mid,
    'X-Teleai-Root-Session-Id': sid,
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
  }
  if (typeof apiKey === 'string' && apiKey.length > 0) headers.Authorization = `Bearer ${apiKey}`
  return headers
}

function newSessionId() { return 'ses_' + crypto.randomBytes(10).toString('hex') }
function newMessageId() { return 'msg_' + crypto.randomBytes(10).toString('hex') }

/** 从完整 URL 反推签名用的 pathname。 */
export function signedPathFrom(url) {
  try {
    const u = new URL(String(url))
    return u.pathname + (u.search || '')
  } catch { return TELEAI_SIGNED_PATH }
}

/** 请求地址是否上游自己（比较 origin）。 */
export function isUpstreamHost(url) {
  try {
    const u = new URL(String(url))
    const upstream = new URL(TELEAI_ORIGIN)
    return u.protocol === upstream.protocol && u.host === upstream.host
  } catch { return false }
}

function safeHostOf(url) {
  try { return new URL(String(url)).host || '空域名' } catch { return '无法解析的地址' }
}

/**
 * 造一个「按账号签名」的 fetch，交给 magpie 的 auth.loader。
 * 免客户端版：auth 直接来自插件登录后保存的凭据（token/deviceId/installId）。
 */
export function createSignedFetch({ auth, apiKey, guard, log, baseFetch, onStatus } = {}) {
  const fetchImpl = baseFetch ?? globalThis.fetch
  return async function signedFetch(input, init = {}) {
    const url = typeof input === 'string' ? input : input?.url ?? String(input)
    const method = (init.method ?? 'POST').toUpperCase()
    const body = typeof init.body === 'string' ? init.body : ''
    const pathname = signedPathFrom(url)
    if (!isUpstreamHost(url)) {
      throw new Error(
        `拒绝向非上游域名发送签名请求：${safeHostOf(url)}` +
        `（只允许 ${new URL(TELEAI_ORIGIN).host}；检查 magpie 里 teleagent 的 api 配置）`,
      )
    }
    let key = ''
    try { key = typeof apiKey === 'function' ? (await apiKey()) ?? '' : (apiKey ?? '') } catch { key = '' }
    const headers = buildAuthHeaders(auth, { body, method, pathname, apiKey: key })
    const incoming = new Headers(init.headers ?? {})
    for (const [k, v] of Object.entries(headers)) {
      if (v === '' || v === undefined) continue
      incoming.set(k, v)
    }
    // 没拿到网关 apiKey 时删掉 magpie 加的 Authorization（占位值会被上游当攻击特征 40105）
    if (!key) incoming.delete('authorization')
    const run = async () => fetchImpl(url, { ...init, method, headers: incoming, body: init.body })
    const res = guard ? await guard.withSlot(run) : await run()
    guard?.observe?.(res.status)
    onStatus?.(res.status)
    log?.({ stage: 'fetch', status: res.status, path: pathname })
    return res
  }
}

/** 上游错误形状：尽量保留厂商原话。 */
export function errorBodyOf(json, text) {
  const message = json?.error?.message ?? json?.message ?? json?.msg ??
    (typeof text === 'string' && text.trim() ? text.trim().slice(0, 500) : '')
  return {
    error: {
      message: message || 'TeleAgent 上游返回了错误',
      type: 'upstream_error',
      code: String(json?.code ?? json?.error?.code ?? ''),
    },
  }
}

export { TELEAI_ORIGIN, TELEAI_BASE_URL }
