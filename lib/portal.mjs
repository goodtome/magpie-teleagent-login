/**
 * TeleAgent「积分福利社」portal 客户端（免客户端版）。
 *
 * 复用 opencode-teleagent-auth（MIT, anbulang）的 portalRequest 与业务接口，
 * 但删掉「从桌面端 Chromium SQLite cookie 库读 cookie」那一整段——免客户端版没有桌面端。
 *
 * 门户凭据来源：登录流程若在响应里下发了门户 token（operationToken / operToken），
 * 由 credential 存储保存；本模块从这里取。若登录接口不返回门户 token，则积分功能
 * 显示「不可用」，模型调用不受影响（聊天网关与门户是两个独立服务、独立凭据、独立降级）。
 *
 * 与聊天网关的区别：聊天走 /superCowork/sapi 需要两步 HMAC 签名；积分走
 * https://agent.teleai.com.cn/meter/super-agent/user/portal，鉴权是 cookie + 请求头，不签名。
 *
 * 隐私：本模块不打印任何 cookie / token / 账号名。
 */
import { readAccount, parseClaims } from './credential.mjs'

/** portal 服务根地址（注意：不是聊天网关） */
export const PORTAL_BASE = 'https://agent.teleai.com.cn/meter/super-agent/user/portal'

const noopLog = () => {}

/**
 * 读取某个账号的 portal 凭据（免客户端版：从插件凭据库取，不读桌面端 SQLite）。
 * 永不抛错；取不到返回 null。
 *
 * @param {string} [_home] 兼容签名，忽略
 * @param {string} [accountKey] 账号 key；省略则用当前账号
 * @returns {{userId: string, operationToken: string, operToken: string, source: string} | null}
 */
export function readPortalAuth(_home, accountKey) {
  const cred = readAccount(accountKey)
  if (!cred.ok) return null
  const portal = cred.portal ?? {}
  let operationToken = typeof portal.operationToken === 'string' ? portal.operationToken : ''
  let userId = String(portal.userId ?? '').trim()

  // 兜底：老凭据（修复 canonicalClaims 之前保存的）portal.userId 是空串，
  // 门户接口会直接 401。这里从 token 的 claim 现算一次账号 id；
  // 完全没门户 cookie 时（手动粘贴 token 登录），把 token 本身当门户 token 试一次。
  if (!userId || !operationToken) {
    let claims = {}
    try { claims = parseClaims(cred.token) } catch { /* 非 JWT：保持原样 */ }
    const id = claims.accountId ?? claims.userId ?? cred.accountId ?? ''
    if (!userId && id) userId = String(id)
    if (!operationToken && typeof cred.token === 'string' && cred.token.length > 0) {
      operationToken = cred.token
    }
  }

  if (!operationToken) return null
  return {
    userId,
    operationToken,
    operToken: portal.operToken ?? '',
    jar: portal.jar ?? {},
    source: portal.operationToken ? 'plugin-credential-store' : 'token-derived',
  }
}

// ---------------------------------------------------------------- HTTP

/**
 * 调 portal 接口。返回 `{ ok, status, json, error }`，永不抛错。
 * @param {{userId: string, operationToken: string, operToken?: string}} auth
 * @param {string} apiPath 形如 `/points/detail`
 */
export async function portalRequest(auth, apiPath, {
  query, timeoutMs = 15000, fetchImpl = globalThis.fetch,
  baseUrl = PORTAL_BASE, log = noopLog,
} = {}) {
  try {
    const url = new URL(baseUrl + apiPath)
    if (query) for (const [k, v] of Object.entries(query)) url.searchParams.set(k, String(v))
    const headers = {
      'X-Token': auth?.operationToken ?? '',
      userId: auth?.userId ?? '',
      Accept: 'application/json',
      'User-Agent': 'Mozilla/5.0 TeleAgent',
      Referer: 'https://agent.teleai.com.cn/teleagent-space',
    }
    const jar = { ...(auth?.jar ?? {}) }
    if (auth?.operToken) jar.operToken = auth.operToken
    if (auth?.operationToken) jar.operationToken = auth.operationToken
    if (auth?.userId) jar.userId = auth.userId
    const cookieParts = Object.entries(jar)
      .filter(([k, v]) => typeof v === 'string' && v.length > 0 && /^[A-Za-z0-9_.-]{1,64}$/.test(k))
      .map(([k, v]) => `${k}=${v}`)
    if (cookieParts.length > 0) headers.Cookie = cookieParts.join('; ')
    if (typeof fetchImpl !== 'function') {
      return { ok: false, status: 0, json: null, error: '当前环境没有可用的 fetch' }
    }
    const res = await fetchImpl(url.toString(), {
      headers,
      signal: typeof globalThis.AbortSignal?.timeout === 'function'
        ? globalThis.AbortSignal.timeout(timeoutMs) : undefined,
    })
    const text = typeof res?.text === 'function' ? await res.text() : ''
    let json = null
    try { json = JSON.parse(text) } catch { /* 非 JSON（可能是登录页 HTML） */ }
    const status = Number(res?.status ?? 0)
    // 门户的 401 也带 JSON 正文（{"code":"4001","message":"..."}），别把它吞成裸 "HTTP 401"：
    // 那句话（UserInfo JWT 解析失败 / 当前令牌是否存在）直接决定下一步怎么修。
    if (res && res.ok === false) {
      const upstream = json && (json.message ?? json.msg ?? json.code)
      const detail = upstream ? `${json.code ?? status} ${json.message ?? json.msg ?? ''}`.trim() : ''
      return {
        ok: false,
        status,
        json,
        error: detail ? `HTTP ${status}：${detail}` : `HTTP ${status}`,
      }
    }
    if (json === null) return { ok: false, status, json: null, error: '响应不是 JSON（可能需要重新登录）' }
    if (json.code !== undefined && Number(json.code) !== 200) {
      return { ok: false, status, json, error: `${json.code} ${json.msg ?? ''}`.trim() }
    }
    return { ok: true, status, json, error: null }
  } catch (error) {
    log('portal 请求异常', { error: String(error?.message ?? error) })
    return { ok: false, status: 0, json: null, error: String(error?.message ?? error) }
  }
}

// ---------------------------------------------------------------- 业务接口

/** 积分余额与明细。 */
export async function fetchPoints(auth, options = {}) {
  const r = await portalRequest(auth, '/points/detail', options)
  if (!r.ok) return { ok: false, error: r.error }
  const data = r.json?.data ?? {}
  const balance = Number(data.pointsBalance)
  const groups = Array.isArray(data.groups) ? data.groups : []
  let soonestExpiry = null
  for (const g of groups) {
    for (const item of (g?.active ?? [])) {
      const end = item?.effectiveEnd
      if (typeof end === 'string' && (soonestExpiry === null || end < soonestExpiry)) soonestExpiry = end
    }
  }
  return {
    ok: true,
    balance: Number.isFinite(balance) ? balance : null,
    userRole: data.userRole ?? null,
    groups,
    expiresAt: soonestExpiry,
  }
}

/** 每日领取状态（只读）。 */
export async function fetchDailyStatus(auth, options = {}) {
  const r = await portalRequest(auth, '/companyStore/v2/checkDayTask', options)
  if (!r.ok) return { ok: false, error: r.error }
  const data = r.json?.data ?? {}
  const task = data.daily_task ?? {}
  const activity = data.activity ?? null
  return {
    ok: true,
    activity: activity && activity.visible === true ? {
      title: activity.activity_title ?? null,
      endText: activity.end_date_text ?? null,
      actionText: activity.action_text ?? null,
    } : null,
    brandTitle: data.brand_title ?? null,
    visible: task.visible === true,
    claimable: Number(task.daily_claimable_points ?? 0),
    claimedToday: task.claimed_today === true,
    totalDays: Number(task.total_claim_days ?? 0),
    totalPoints: Number(task.total_claimed_points ?? 0),
    buttonText: task.button_text ?? null,
  }
}

/** 执行每日领取（幂等）。先查状态：已领直接返回，绝不调用领取接口。 */
export async function claimDaily(auth, options = {}) {
  const before = await fetchDailyStatus(auth, options)
  if (!before.ok) return { ok: false, claimed: false, points: 0, alreadyClaimed: false, error: before.error }
  if (before.claimedToday) return { ok: true, claimed: false, alreadyClaimed: true, points: 0 }
  const r = await portalRequest(auth, '/companyStore/checkTask', { ...options, query: { type: 'daily_login' } })
  if (!r.ok) return { ok: false, claimed: false, points: 0, alreadyClaimed: false, error: r.error }
  const after = await fetchDailyStatus(auth, options)
  const claimedNow = after.ok ? after.claimedToday && !before.claimedToday : true
  return { ok: true, claimed: claimedNow, points: before.claimable, alreadyClaimed: !claimedNow }
}

/** 套餐与账号信息（计划名 / 并发上限）。 */
export async function fetchUserCenter(auth, options = {}) {
  const r = await portalRequest(auth, '/companyStore/userCenter', options)
  if (!r.ok) return { ok: false, error: r.error }
  const d = r.json?.data ?? {}
  return {
    ok: true,
    planName: d.plan_display_name ?? null,
    balance: d.current_points_balance != null ? Number(d.current_points_balance) : null,
    maxConcurrentTasks: d.max_concurrent_tasks ?? null,
    endDate: d.end_date ?? null,
  }
}

