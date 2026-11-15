/**
 * TeleAgent 的 magpie / OpenCode v1 供应商插件（免客户端登录版）。
 *
 * 导出只有这一个插件函数（入口模块导出的每个函数都会被当成插件调用，
 * 辅助函数都放在 lib/ 里）。
 *
 * 与参考版 opencode-teleagent-auth 的区别：不需要安装 TeleAgent 桌面客户端。
 * 参考版复用桌面端磁盘登录态（safeStorage 加密 token + device-meta），本插件自己完成
 * 登录闭环：
 *   - 浏览器登录：自起临时 profile 的 Chromium，打开 Web 登录页，CDP 轮询读 cookie
 *   - 手动粘贴 token：零依赖兜底
 * 换到 JWT + 设备指纹后存进插件自己的凭据库（lib/credential.mjs），每次请求现读现签。
 *
 * 做的事：
 *   1. config 钩子声明供应商 teleagent 与 5 个模型；
 *   2. auth.methods 提供两条免客户端登录路径；
 *   3. auth.loader 为每个账号造一个 fetch：现读凭据、现签 ts/nonce、过 guard；
 *   4. auth.usage 报积分余额与套餐（magpie quota）；
 *   5. auth.checkin 按下每日签到（幂等）；
 *   6. tool 给 agent 一个只读的 points；
 *   7. chat.headers 补会话头。
 *
 * 安全边界：上游对自动化流量敏感（两次封号复盘），内置并发 2 / 每分钟 20 / 401·403 熔断
 * 10 分钟，并且不做任何启动自检式聊天请求。见 docs/PROTOCOL.md。
 */
import {
  buildModels, MODELS, TELEAI_BASE_URL, TELEAI_ORIGIN, DEFAULT_APP_VERSION,
} from './lib/models.mjs'
import {
  diagnoseCredential, listAccounts, saveAccount, storePaths, CredentialState,
  readAccount, parseClaims, updatePortal,
} from './lib/credential.mjs'
import { createSignedFetch } from './lib/sign.mjs'
import { normalizeUpstreamBody } from './lib/effort.mjs'
import { createGuard } from './lib/guard.mjs'
import { resolveApiKey } from './lib/apikey.mjs'
import {
  startBrowserLogin, loginWithManualToken, deriveDeviceIdentity, refreshAccessToken,
} from './lib/login.mjs'
import {
  readPortalAuth, fetchPoints, fetchDailyStatus, claimDaily, fetchUserCenter,
} from './lib/portal.mjs'

export const PROVIDER = 'teleagent'

/** 账号在 magpie 里的 key。 */
function keyForAccount(accountKey) { return accountKey }
function keyOf(auth) {
  return typeof auth?.key === 'string' ? auth.key : ''
}

/** magpie 的 success 返回形状（两条登录路径共用）。 */
function successOf(saved) {
  return {
    type: 'success',
    key: keyForAccount(saved.key),
    accountId: String(saved.account.accountId ?? saved.key),
    metadata: {
      // magpie 依次用 accountId / metadata.email / email 给账号命名
      email: saved.account.accountName ?? undefined,
      accountName: saved.account.accountName ?? null,
      scope: saved.key,
      expiresAt: saved.account.expiresAt ?? null,
    },
  }
}

export default async function TeleAgentLoginPlugin(input = {}) {
  const log = (level, message) => {
    try { input?.client?.app?.log?.({ body: { service: 'teleagent', level, message } }) } catch { /* 忽略 */ }
  }
  const options = () => input?.magpie?.options ?? input?.magpie?.option ?? {}
  const verbose = () => {
    const o = options()
    return o.verbose === true || o.debug === true
  }
  const say = (message) => { if (verbose()) log('info', message) }

  /** scope → guard，按账号隔离并发与熔断 */
  const guards = new Map()
  function guardFor(scope) {
    const existing = guards.get(scope)
    if (existing) return existing
    const created = createGuard({ onIdle: () => say(`空闲：${scope}`) })
    guards.set(scope, created)
    return created
  }

  /** 读当前账号的可用凭据。每次请求都读一遍，过期/重登即时生效。 */
  function readAuth(scope) {
    const d = diagnoseCredential(scope)
    if (!d.ok) {
      const error = new Error(`TeleAgent 凭据不可用：${d.detail}`)
      error.code = d.state
      if ([CredentialState.EXPIRED, CredentialState.NOT_SIGNED_IN].includes(d.state)) {
        error.signIn = 'expired'
      }
      throw error
    }
    return d
  }

  /** 网关 apiKey：免客户端版靠用户配置 / 环境变量（没有桌面端可读常量）。 */
  function resolveKey() {
    const o = options()
    return resolveApiKey({ explicit: typeof o.apiKey === 'string' ? o.apiKey : undefined })
  }

  return {
    // ---------------------------------------------------------- 供应商与模型
    config: async (cfg) => {
      cfg.provider ??= {}
      cfg.provider[PROVIDER] ??= {
        name: 'TeleAgent',
        npm: '@ai-sdk/openai-compatible',
        api: TELEAI_BASE_URL,
        models: buildModels(),
      }
      cfg.provider[PROVIDER].options ??= {}
    },

    // ---------------------------------------------------------------- 登录
    auth: {
      provider: PROVIDER,
      icon: 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NCA2NCI+PHJlY3Qgd2lkdGg9IjY0IiBoZWlnaHQ9IjY0IiByeD0iMTQiIGZpbGw9IiMwMDVhY2MiLz48cGF0aCBkPSJNMjAgNDJWMjJsMjQgMjBWMjIiIHN0cm9rZT0iI2ZmZiIgc3Ryb2tlLXdpZHRoPSI1IiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiIGZpbGw9Im5vbmUiLz48L3N2Zz4=',
      maxConcurrency: 2,
      methods: [
        {
          type: 'api',
          id: 'browser',
          keyless: true,
          label: '浏览器登录（自动获取，推荐）',
          placeholder: '弹出浏览器登录天翼账号，自动回取',
          get prompts() { return [] },
          /** 内置浏览器登录：无需装桌面端，也无需手动复制。 */
          async authorize() {
            const result = await startBrowserLogin({ log: (m) => log('info', m) })
            if (!result.ok) return { type: 'failed', error: result.error }
            // operationToken 同时是门户 cookie，一并保存 → 积分/签到开箱可用
            const saved = saveAccount({ token: result.token, portal: result.portal })
            return successOf(saved)
          },
        },
        {
          type: 'api',
          id: 'token',
          keyless: false,
          label: '手动粘贴 token（零依赖兜底）',
          placeholder: 'x-token / operationToken',
          get prompts() {
            return [{
              type: 'text',
              key: 'token',
              message: '粘贴 token：浏览器登录 agent.teleai.com.cn 后，F12 → Application → Cookies 里的 x-token（或 operationToken）',
            }]
          },
          async authorize(inputs) {
            const raw = typeof inputs?.token === 'string' ? inputs.token.trim() : ''
            const login = loginWithManualToken(raw)
            if (!login.ok) return { type: 'failed', error: login.error }
            // 同一个账号重贴一次 token 时，把已存的门户凭据带上，别把积分弄丢
            let portal
            try {
              const claims = parseClaims(login.token)
              const prev = readAccount(claims.accountId ?? claims.userId)
              if (prev.ok && prev.portal) portal = prev.portal
            } catch { /* 非 JWT：不继承门户凭据 */ }
            const saved = saveAccount({ token: login.token, portal })
            return successOf(saved)
          },
        },
        {
          type: 'api',
          id: 'portal',
          keyless: false,
          label: '补门户 cookie（只修积分/签到，不动聊天凭据）',
          placeholder: '粘贴 agent.teleai.com.cn 的 operationToken',
          get prompts() {
            return [{
              type: 'text',
              key: 'cookie',
              message: '粘贴门户 token：浏览器打开 https://agent.teleai.com.cn/teleagent 并登录，'
                + 'F12 → Application → Cookies → 选 agent.teleai.com.cn → 复制 operationToken 的值',
            }]
          },
          /**
           * 门户（积分/签到）和聊天网关是两套凭据：门户只认 agent.teleai.com.cn 子域那份
           * 带 userInfo 的 JWT。这个方法只覆盖 portal 字段，聊天用的 token / 设备指纹原样保留，
           * 所以补门户不会把已经能用的聊天登录弄坏。
           */
          async authorize(inputs) {
            const cookie = typeof inputs?.cookie === 'string' ? inputs.cookie.trim() : ''
            if (!cookie) return { type: 'failed', error: '请粘贴 operationToken 的值' }
            const current = readAccount()
            if (!current.ok) {
              return { type: 'failed', error: '请先用「浏览器登录」或「手动粘贴 token」完成登录，再补门户凭据' }
            }
            let claims = {}
            try { claims = parseClaims(cookie) } catch { /* 不是 JWT 也照样存 */ }
            const userId = String(claims.accountId ?? claims.userId ?? current.accountId ?? '')
            const saved = updatePortal({
              operationToken: cookie,
              operToken: cookie,
              userId,
              jar: current.portal?.jar ?? {},
            }, current.key)
            if (!saved.ok) return { type: 'failed', error: saved.error }
            return successOf(saved)
          },
        },
      ],

      /** 每个账号的请求：现签 + 现读凭据 */
      async loader(getAuth) {
        const auth = await getAuth()
        const scope = keyOf(auth)
        let cachedKey = ''
        let cachedSource = ''
        return {
          baseURL: TELEAI_BASE_URL,
          // magpie 会按 openai-compatible 规则加 Authorization；签名 fetch 里会替换成网关 apiKey
          apiKey: `teleagent:${scope || 'default'}`,
          async fetch(fetchInput, init) {
            // 目录外的模型 id 直接 404（上游对未知 id 会静默回落），在读凭据之前就拦下
            const asked = modelOfBody(init?.body)
            if (asked && !MODELS.some((m) => m.id === asked)) {
              return new Response(JSON.stringify({
                error: {
                  message: `TeleAgent 没有模型 ${asked}（可用：${MODELS.map((m) => m.id).join(' / ')}）`,
                  type: 'invalid_request_error',
                },
              }), { status: 404, headers: { 'Content-Type': 'application/json' } })
            }
            // 思考档位削成上游认的 low/high/max（这是所有请求的必经关口）
            const effort = normalizeUpstreamBody(init?.body)
            if (effort.changed) {
              say(`思考档位：${effort.from || '<无>'} → ${effort.to ?? '<删除>（上游不接受关闭思考）'}`)
              init = { ...init, body: effort.body }
            }
            // 凭据每次现读：重新登录后不用重启 magpie
            const diagnosis = readAuth(scope)
            const resolved = resolveKey()
            if (resolved.source !== cachedSource) {
              cachedSource = resolved.source
              cachedKey = resolved.key
              say(`loader：scope=${scope || ''} apiKey=${resolved.source}`)
            }
            const signed = createSignedFetch({
              auth: {
                token: diagnosis.token,
                installId: diagnosis.installId ?? '',
                deviceId: diagnosis.deviceId ?? '',
                appVersion: diagnosis.appVersion ?? DEFAULT_APP_VERSION,
              },
              apiKey: cachedKey,
              // 熔断/并发按账号隔离：一个账号被封不该拖住另一个
              guard: guardFor(diagnosis.scope),
              log: verbose() ? say : undefined,
            })
            let response
            try {
              response = await signed(fetchInput, init)
            } catch (error) {
              if (error?.circuitOpen === true) {
                const secs = Math.max(1, Math.ceil((error.retryAfterMs ?? 60_000) / 1000))
                return new Response(JSON.stringify({
                  error: {
                    message: `${error.message}（约 ${Math.ceil(secs / 60)} 分钟后自动恢复）`,
                    type: 'upstream_unavailable',
                  },
                }), {
                  status: 503,
                  headers: { 'Content-Type': 'application/json', 'Retry-After': String(secs) },
                })
              }
              throw error
            }
            return explainFailure(response)
          },
        }
      },

      /** 用量只反映 portal 状态；所有结果都保留模型登录态。 */
      async usage(getAuth) {
        const auth = await getAuth()
        const portal = safePortalAuth(keyOf(auth))
        if (!portal) {
          return {
            plan: undefined,
            signIn: 'kept',
            error: '积分暂不可用：缺少该账号的门户凭据（用「浏览器登录」重登一次可自动写入）',
            windows: [],
          }
        }
        const [points, center] = await Promise.all([
          fetchPoints(portal).catch((e) => ({ ok: false, error: String(e?.message ?? e) })),
          fetchUserCenter(portal).catch(() => ({ ok: false })),
        ])
        if (!points.ok) {
          return { signIn: 'kept', error: points.error ?? '读取积分失败', windows: [] }
        }
        const windows = [{
          name: '积分余额',
          balance: Number(points.balance ?? 0),
          unit: '积分',
          ...(points.expiresAt ? { runsOutAt: points.expiresAt } : {}),
        }]
        return {
          signIn: 'kept',
          plan: center.ok ? (center.planName ?? undefined) : undefined,
          windows,
        }
      },

      /** 每日签到（幂等；已领返回 done，不重复领取）。 */
      async checkin(getAuth) {
        const auth = await getAuth()
        const portal = safePortalAuth(keyOf(auth))
        if (!portal) return { outcome: 'failed', message: '读不到积分凭据（门户 cookie）：用「浏览器登录」重登一次' }
        try {
          const before = await fetchDailyStatus(portal)
          if (!before.ok) return { outcome: 'failed', message: before.error ?? '读取签到状态失败' }
          if (before.claimedToday) return { outcome: 'done', message: '今天已经签过了' }
          if (before.visible === false) return { outcome: 'inactive', message: '当前没有签到活动' }
          const r = await claimDaily(portal)
          if (!r.ok) return { outcome: 'failed', message: r.error ?? '签到失败' }
          if (!r.claimed) return { outcome: 'failed', message: '领取接口返回成功，但复查仍显示未签到' }
          return { outcome: 'claimed', credit: Number(r.points ?? 0), message: '签到成功' }
        } catch (error) {
          return { outcome: 'failed', message: String(error?.message ?? error) }
        }
      },

      /** 可选：JWT 临近过期时用它续期（服务端有 token-refresh 端点）。 */
      async refresh(getAuth) {
        const auth = await getAuth()
        const d = diagnoseCredential(keyOf(auth))
        if (!d.ok) {
          const error = new Error(d.detail)
          error.signIn = 'expired'
          throw error
        }
        const r = await refreshAccessToken({ token: d.token, deviceId: d.deviceId })
        if (!r.ok) {
          const error = new Error(r.error ?? '续期失败')
          error.signIn = 'expired'
          throw error
        }
        const saved = saveAccount({ token: r.token })
        return successOf(saved)
      },
    },

    // ------------------------------------------------ 每个账号的模型清单
    provider: {
      id: PROVIDER,
      async models(provider) {
        const out = {}
        for (const [id, model] of Object.entries(provider.models)) {
          const known = MODELS.find((m) => m.id === id)
          out[id] = known ? { ...model, rate: known.rate } : model
        }
        return out
      },
    },

    // -------------------------------------------------------------- 请求头
    'chat.headers': async (chatInput, output) => {
      if (chatInput?.model?.providerID !== PROVIDER) return
      const sessionId = typeof chatInput?.sessionID === 'string' ? chatInput.sessionID : ''
      if (!sessionId) return
      // 让上游看到「同一段对话」的会话头稳定
      const stable = sessionId.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 40)
      if (!stable) return
      output.headers['x-teleagent-session'] = stable
    },

    // ---------------------------------------------------------------- 工具
    tool: {
      points: {
        description: '查询登录的 TeleAgent 账号积分余额与每日签到状态。只读：不消耗积分、不触发领取、不发任何模型请求。',
        args: { type: 'object', properties: {}, required: [] },
        async execute() {
          const d = diagnoseCredential()
          if (!d.ok) return { ok: false, error: d.detail }
          const portal = safePortalAuth(d.scope)
          if (!portal) return { ok: false, error: '读不到积分凭据（门户 cookie）：用「浏览器登录」重登一次' }
          const [points, daily, center] = await Promise.all([
            fetchPoints(portal).catch((e) => ({ ok: false, error: String(e?.message ?? e) })),
            fetchDailyStatus(portal).catch((e) => ({ ok: false, error: String(e?.message ?? e) })),
            fetchUserCenter(portal).catch(() => ({ ok: false })),
          ])
          if (!points.ok) return { ok: false, error: points.error ?? '读取积分失败' }
          return {
            ok: true,
            balance: points.balance ?? null,
            expiresAt: points.expiresAt ?? null,
            planName: center.ok ? (center.planName ?? null) : null,
            claimedToday: daily.ok ? daily.claimedToday : null,
            claimable: daily.ok ? daily.claimable : null,
            totalClaimDays: daily.ok ? daily.totalDays : null,
            totalClaimedPoints: daily.ok ? daily.totalPoints : null,
          }
        },
      },
    },
  }
}

// ------------------------------------------------------------------ 辅助

/** 读 portal 凭据（永不抛）。 */
function safePortalAuth(scope) {
  try { return readPortalAuth(undefined, scope || undefined) } catch { return null }
}

/** 从请求体里取 model（拿不到返回空串）。 */
function modelOfBody(body) {
  if (typeof body !== 'string' || body.length === 0) return ''
  try {
    const parsed = JSON.parse(body)
    return typeof parsed?.model === 'string' ? parsed.model : ''
  } catch { return '' }
}

/**
 * 把上游「看起来成功但说不清」的响应翻译成 magpie 能处理的形状。
 * 40105（疑似攻击，apiKey 没带上）、40108（invalid token）、40109（封禁）
 * 都不是「账号被登出」，都报 x-magpie-sign-in: kept，避免 magpie 抹掉账号。
 * 40108 额外把原因和改进办法写进 message：它是「存错 token 类型」的典型症状。
 */
async function explainFailure(response) {
  const status = Number(response?.status ?? 0)
  if (status !== 401 && status !== 403) return response
  let text = ''
  try { text = await response.clone().text() } catch { return response }
  const banned = /40109|is banned|封禁|被封/i.test(text)
  const suspicious = /40105|疑似攻击/i.test(text)
  const invalidToken = /40108|invalid token|token (is )?invalid|令牌(无效|不合法)/i.test(text)
  if (!banned && !suspicious && !invalidToken) return response
  const headers = new Headers(response.headers)
  headers.set('x-magpie-sign-in', 'kept')
  let body = status === 204 || status === 205 ? null : text
  if (invalidToken && body) {
    try {
      const parsed = JSON.parse(body)
      const hint = '聊天网关不认这份 token（401 invalid token）：多半是存进去的是门户 token，'
        + '不是 SSO token。执行 `magpie plugin login teleagent` 选 1（浏览器登录）重登一次即可。'
      parsed.error = { ...(parsed.error ?? {}), message: hint }
      body = JSON.stringify(parsed)
    } catch { /* 非 JSON：原样返回 */ }
  }
  return new Response(body, { status, statusText: response.statusText, headers })
}

export const _internal = {
  buildModels, MODELS, TELEAI_BASE_URL, TELEAI_ORIGIN, explainFailure,
  modelOfBody, keyForAccount, keyOf, listAccounts, storePaths,
  startBrowserLogin, loginWithManualToken, deriveDeviceIdentity, refreshAccessToken,
}
