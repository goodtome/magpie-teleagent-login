/**
 * 免客户端凭据库：TeleAgent 登录成功后把 JWT + 设备指纹存到插件自己的目录。
 *
 * 与参考版（读桌面端磁盘）的根本区别：
 *   参考版凭据 = 桌面端 safeStorage 加密文件，插件只读。
 *   免客户端版凭据 = 插件自己跑完登录流程（浏览器登录 / 手动 token）后写到
 *   `<数据目录>/teleagent-login/accounts.json`，每次请求现读现签。
 */
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import { deriveDeviceIdentity } from './login.mjs'
import { DEFAULT_APP_VERSION } from './models.mjs'

/** 凭据状态枚举（值即 code，便于 loader / UI 稳定匹配）。 */
export const CredentialState = {
  OK: 'ok',
  NOT_SIGNED_IN: 'not_signed_in',
  EXPIRED: 'expired',
  TOKEN_MALFORMED: 'token_malformed',
}

/** 每种状态对应的用户动作。 */
export const REMEDIES = {
  [CredentialState.NOT_SIGNED_IN]: '在 magpie 里选择浏览器登录或手动粘贴 token 完成 TeleAgent 登录',
  [CredentialState.EXPIRED]: '登录已过期，请重新登录；续期端点失败时只能重登',
  [CredentialState.TOKEN_MALFORMED]: 'token 不是合法 JWT，请重新登录',
}

/** 插件数据目录。优先环境变量注入，否则回退 ~/.local/share/magpie-teleagent-login */
export function storePaths(home = os.homedir()) {
  const injected = process.env.TELEAGENT_PLUGIN_DATA ||
    process.env.MAGPIE_DATA_HOME ||
    process.env.XDG_DATA_HOME
  const root = injected
    ? path.join(injected, 'teleagent-login')
    : path.join(home, '.local', 'share', 'magpie-teleagent-login')
  return { home, root, file: path.join(root, 'accounts.json') }
}

/** 兼容参考版 appPaths 的调用点。 */
export function appPaths(home = os.homedir()) {
  const s = storePaths(home)
  return { home, data: s.root, config: s.root }
}

function emptyStore() {
  return { version: 1, current: null, accounts: {} }
}

function readStore(file = storePaths().file) {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'))
    if (parsed && typeof parsed === 'object' && parsed.accounts && typeof parsed.accounts === 'object') {
      return parsed
    }
  } catch { /* 不存在或损坏 → 空库 */ }
  return emptyStore()
}

/** 原子写：先写临时文件再 rename，避免半截 JSON。 */
function writeStore(store, file = storePaths().file) {
  const dir = path.dirname(file)
  fs.mkdirSync(dir, { recursive: true })
  const tmp = path.join(dir, `.accounts.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`)
  fs.writeFileSync(tmp, JSON.stringify(store, null, 2), 'utf8')
  fs.renameSync(tmp, file)
}

/** 从 JWT 里取声明（不校验签名）。容忍 `tenant:` 前缀。 */
export function parseClaims(token) {
  const jwt = token.includes(':') ? token.slice(token.indexOf(':') + 1) : token
  const payload = jwt.split('.')[1]
  if (!payload) {
    const e = new Error('凭据不是合法的 JWT')
    e.code = CredentialState.TOKEN_MALFORMED
    throw e
  }
  let raw
  try {
    raw = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'))
  } catch {
    const e = new Error('凭据里的声明不是合法 JSON')
    e.code = CredentialState.TOKEN_MALFORMED
    throw e
  }
  return canonicalClaims(raw)
}

/**
 * 天翼 UCloud 的 JWT 用的是带连字符的私有 claim 名
 * （实测已登录 token：tokenType / jwtInfoId / x-aicloud-user-type /
 *  x-aicloud-account-id / x-aicloud-user-id / iat，没有 exp）。
 * 这里把它们映射到本模块统一使用的 accountId / userId / accountName，
 * 上层（凭据 key、门户 userId 头、设备指纹派生）就都拿得到账号标识。
 * 原始 claim 全部保留，不做删除。
 */
export function canonicalClaims(raw) {
  const src = raw && typeof raw === 'object' ? raw : {}
  const pick = (...names) => {
    for (const n of names) {
      const v = src[n]
      if (v !== undefined && v !== null && String(v).length > 0) return String(v)
    }
    return undefined
  }
  const accountId = pick(
    'x-aicloud-account-id', 'x-aicloud-user-id',
    'accountId', 'account_id', 'userId', 'user_id', 'uid', 'sub',
  )
  const userId = pick('x-aicloud-user-id', 'x-aicloud-account-id', 'userId', 'user_id', 'uid', 'sub') ?? accountId
  const accountName = pick('accountName', 'name', 'nickName', 'nickname', 'email', 'preferred_username', 'phone')
  const out = { ...src }
  if (accountId !== undefined) out.accountId = accountId
  if (userId !== undefined) out.userId = userId
  if (accountName !== undefined) out.accountName = accountName
  if (out.tenant === undefined) {
    const t = pick('tenant', 'tenantId', 'tenant_id')
    if (t !== undefined) out.tenant = t
  }
  return out
}

/** 账号 key：优先 accountId，否则用 token 指纹。 */
export function accountKeyFor(token, claims = {}) {
  const id = claims.accountId ?? claims.userId
  if (id !== undefined && id !== null && String(id).length > 0) return String(id)
  return 'tok_' + crypto.createHash('sha256').update(String(token)).digest('hex').slice(0, 12)
}

/** 归一化门户凭据；userId 是门户接口必带的头。 */
/** 归一化门户凭据；userId 是门户接口必带的头，jar 是整包 cookie。 */
function normalizePortal(portal, claims = {}) {
  if (!portal || typeof portal !== 'object') return null
  let operationToken = typeof portal.operationToken === 'string' ? portal.operationToken : ''
  const jar = normalizeJar(portal.jar)
  if (!operationToken) operationToken = jar.operationToken ?? jar.operToken ?? jar.accessToken ?? ''
  if (!operationToken) return null
  const userId = portal.userId || jar.userId || claims.accountId || claims.userId || ''
  return {
    operationToken,
    operToken: typeof portal.operToken === 'string' ? portal.operToken : (jar.operToken ?? ''),
    userId: String(userId),
    jar,
  }
}

/** 只保留 `name=value` 形态、长度合理的 cookie，避免把整包脏数据写进凭据文件。 */
function normalizeJar(jar) {
  const out = {}
  if (!jar || typeof jar !== 'object') return out
  for (const [k, v] of Object.entries(jar)) {
    if (typeof k !== 'string' || typeof v !== 'string') continue
    if (!/^[A-Za-z0-9_.-]{1,64}$/.test(k)) continue
    if (v.length === 0 || v.length > 8192) continue
    if (/[;\r\n]/.test(v)) continue
    out[k] = v
  }
  return out
}

/**
 * 保存/覆盖一个账号凭据，并把它设为当前账号。
 * @param {object} cred { token, deviceId?, installId?, appVersion?, accountName?, portal? }
 */
export function saveAccount(cred, file = storePaths().file) {
  if (typeof cred?.token !== 'string' || cred.token.length === 0) {
    throw new Error('保存凭据失败：缺少 token')
  }
  let claims = {}
  try { claims = parseClaims(cred.token) } catch { /* 仍保存，key 退化成指纹 */ }
  const key = accountKeyFor(cred.token, claims)
  const expiresAt = typeof claims.exp === 'number' ? claims.exp * 1000 : undefined
  // 设备指纹：调用方给就用，否则由 accountId 确定性派生（同账号稳定，减少风控命中）
  let deviceId = cred.deviceId ?? ''
  let installId = cred.installId ?? ''
  if (!deviceId || !installId) {
    const derived = deriveDeviceIdentity(claims.accountId ?? claims.userId ?? key)
    deviceId = deviceId || derived.deviceId
    installId = installId || derived.installId
  }
  const account = {
    token: cred.token,
    deviceId,
    installId,
    appVersion: cred.appVersion ?? DEFAULT_APP_VERSION,
    accountName: cred.accountName ?? claims.accountName ?? null,
    accountId: claims.accountId ?? claims.userId ?? null,
    tenant: claims.tenant ?? null,
    expiresAt: expiresAt ?? null,
    savedAt: Date.now(),
    // 门户（积分/签到）凭据：浏览器登录读到的 operationToken 同时就是门户 cookie。
    // 缺失时积分显示不可用，模型调用不受影响（两服务、两套凭据、独立降级）。
    portal: normalizePortal(cred.portal, claims),
  }
  const store = readStore(file)
  store.accounts[key] = account
  store.current = key
  writeStore(store, file)
  return { key, account }
}

/**
 * 只更新某个已存在账号的门户凭据（积分/签到），不改 key、不动聊天 token 与设备指纹。
 * 门户和聊天是两套凭据，补门户不该把已经能用的聊天登录重写一遍（重写会换 key）。
 */
export function updatePortal(portal, key, file = storePaths().file) {
  const store = readStore(file)
  const k = key || store.current
  const account = k ? store.accounts[k] : undefined
  if (!account) return { ok: false, error: '账号不存在，请先登录' }
  let claims = {}
  try { claims = parseClaims(account.token) } catch { /* 非 JWT：只用传入值 */ }
  account.portal = normalizePortal(portal, claims)
  if (!account.accountId) account.accountId = claims.accountId ?? claims.userId ?? account.portal?.userId ?? null
  store.accounts[k] = account
  store.current = k
  writeStore(store, file)
  return { ok: true, key: k, account }
}

/** 读取当前账号（或指定 key）的凭据；过期返回 expired。 */
export function readAccount(key, file = storePaths().file) {
  const store = readStore(file)
  const k = key || store.current
  if (!k) return { ok: false, state: CredentialState.NOT_SIGNED_IN, detail: '尚未登录 TeleAgent' }
  const account = store.accounts[k]
  if (!account) return { ok: false, state: CredentialState.NOT_SIGNED_IN, detail: `账号不存在：${k}` }
  const base = { ok: true, state: CredentialState.OK, key: k, ...account }
  if (typeof account.expiresAt === 'number' && account.expiresAt < Date.now()) {
    const day = new Date(account.expiresAt).toISOString().slice(0, 10)
    return { ...base, ok: false, state: CredentialState.EXPIRED, detail: `登录已过期（${day}），请重新登录` }
  }
  const daysLeft = typeof account.expiresAt === 'number'
    ? Math.floor((account.expiresAt - Date.now()) / 86_400_000)
    : undefined
  const who = account.accountName ?? account.accountId ?? k
  return {
    ...base,
    daysLeft,
    detail: daysLeft === undefined ? `已登录：${who}` : `已登录：${who}，剩余 ${daysLeft} 天`,
  }
}

/** 列出所有已保存账号（登录选择器用）。 */
export function listAccounts(file = storePaths().file) {
  const store = readStore(file)
  return Object.entries(store.accounts).map(([key, a]) => ({
    key,
    accountName: a.accountName ?? null,
    accountId: a.accountId ?? null,
    expiresAt: a.expiresAt ?? null,
    daysLeft: typeof a.expiresAt === 'number'
      ? Math.floor((a.expiresAt - Date.now()) / 86_400_000)
      : undefined,
    current: store.current === key,
  })).sort((a, b) => (b.current ? 1 : 0) - (a.current ? 1 : 0))
}

/** 删除一个账号。 */
export function removeAccount(key, file = storePaths().file) {
  const store = readStore(file)
  if (!store.accounts[key]) return false
  delete store.accounts[key]
  if (store.current === key) store.current = Object.keys(store.accounts)[0] ?? null
  writeStore(store, file)
  return true
}

/** 兼容参考版 diagnoseCredential 的返回形状，供 loader 统一处理。 */
export function diagnoseCredential(key, file = storePaths().file) {
  const r = readAccount(key, file)
  if (!r.ok) return r
  return {
    ok: true,
    state: CredentialState.OK,
    token: r.token,
    deviceId: r.deviceId,
    installId: r.installId,
    appVersion: r.appVersion,
    scope: r.key,
    accountName: r.accountName,
    accountId: r.accountId,
    tenant: r.tenant,
    expiresAt: r.expiresAt,
    daysLeft: r.daysLeft,
    detail: r.detail,
  }
}
