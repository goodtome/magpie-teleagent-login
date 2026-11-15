/**
 * TeleAgent 登录闭环（免客户端版）。
 *
 * 侦察结论（见 docs/PROTOCOL.md 第三节）：上游**没有**公开的「手机号+短信验证码 → 直接换
 * TeleAgent JWT」纯 API 端点。所有已知第三方实现都靠①桌面端已登录态导入，或②浏览器登录。
 * 因此本插件的免客户端路径是**内置浏览器登录**：
 *
 *   startBrowserLogin()  自起一个临时 profile 的 Chromium（Chrome/Edge/Brave）打开 Web 登录页，
 *                        用户在弹窗里完成天翼账号登录，插件通过 CDP 轮询读 operationToken/x-token
 *                        cookie，拿到后自动关浏览器。无需装桌面端、无需手动复制。
 *
 * 另提供：
 *   loginWithManualToken()  手动粘贴 token（浏览器 F12 取 x-token/operationToken）——零依赖兜底。
 *   deriveDeviceIdentity()  由 accountId 确定性派生 deviceId/installId（客户端侧身份，非服务端下发）。
 *   refreshAccessToken()    续期 JWT（服务端有 token-refresh 端点，桌面版没用的那个）。
 *
 * 端点集中在 ENDPOINTS / LOGIN_URL / TOKEN_REFRESH_URL，上游变动只改这里。
 */
import crypto from 'node:crypto'
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

/** Web 登录入口（浏览器打开这个地址，登录后 token 落在 teleai.com.cn 域 cookie）。 */
export const LOGIN_URL =
  'https://agent.teleai.com.cn/meter/teleagent-login/middle' +
  '?redirect_url=https%3A%2F%2Fagent.teleai.com.cn%2Fteleagent'

/**
 * 登录成功后再落一次这个页面。门户（积分/签到）凭据不是登录那一刻下发的：
 * agent.teleai.com.cn 的页面脚本会调门户接口，顺便把门户用的那份 JWT
 * （带 userInfo 的 operationToken）写进子域 cookie。不落这一步，只有 SSO 的 uc_auth_token。
 */
export const SPACE_URL = 'https://agent.teleai.com.cn/teleagent'

/** 上游聊天网关基地址。 */
export const ORIGIN = 'https://agent.teleai.com.cn'

/** token 续期端点。 */
export const TOKEN_REFRESH_URL = ORIGIN + '/superCowork/sapi/cowork/auth/token-refresh'

/** web 登录成功后 token 可能落的位置（按优先级）。 */
export const COOKIE_NAMES = ['operationToken', 'operToken', 'accessToken']
export const LOCAL_STORAGE_KEYS = ['sso_token', 'console_token']
export const HEADER_TOKEN_NAMES = ['x-token', 'operationToken']

/**
 * 由 seed（推荐 accountId）确定性派生设备身份。同一账号每次得到同一组值。
 * installId 改变会提高风控命中率，所以固定 seed 保持稳定。
 */
export function deriveDeviceIdentity(seed) {
  const s = String(seed ?? 'teleagent')
  const deviceId = crypto.createHash('sha256').update(`teleagent-device:${s}`).digest('hex').slice(0, 12)
  const h = crypto.createHash('sha256').update(`teleagent-install:${s}`).digest()
  // 置 version=4、variant 位，摆成 UUID 形态
  h[6] = (h[6] & 0x0f) | 0x40
  h[8] = (h[8] & 0x3f) | 0x80
  const hex = h.toString('hex')
  const installId = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`
  return { deviceId, installId }
}

/**
 * 手动 token 登录（零依赖兜底）：直接用浏览器 F12 取到的 token。
 * @returns {{ok:boolean, token:string, error?:string}}
 */
export function loginWithManualToken(token) {
  const t = typeof token === 'string' ? token.trim() : ''
  if (!t) return { ok: false, token: '', error: '请粘贴 token（浏览器 F12 → Application → Cookies 里的 x-token / operationToken）' }
  // 容忍桌面端那种 `tenant:` 前缀，签名用的 JWT 是冒号后那段（sign.mjs 里 split('.')[2]）
  return { ok: true, token: t }
}

/**
 * 内置浏览器登录：起一个临时 profile 的 Chromium，打开登录页，CDP 轮询读 token cookie。
 *
 * @param {object} [opts]
 * @param {string} [opts.chromePath] 浏览器可执行文件；缺省按平台自动探测
 * @param {number} [opts.timeoutMs] 超时（默认 5 分钟）
 * @param {typeof fetch} [opts.fetchImpl] CDP HTTP 注入（测试用）
 * @param {(msg:string)=>void} [opts.log] 进度回调
 * @returns {Promise<{ok:boolean, token?:string, cookieToken?:string, error?:string}>}
 *
 * 实现：用 `--remote-debugging-port=0` 起 Chrome（0 = 随机端口，写进 stderr 的 DevTools line），
 * 连 CDP 的 Network domain，轮询 Network.getAllCookies 过滤 teleai.com.cn 域的目标 cookie。
 * 临时 profile 目录用完即删，不污染用户浏览器。
 */
export function startBrowserLogin(opts = {}) {
  const fetchImpl = opts.fetchImpl ?? globalThis.fetch
  const log = opts.log ?? (() => {})
  const timeoutMs = opts.timeoutMs ?? 5 * 60 * 1000
  return new Promise((resolve) => {
    let chrome = null
    let profileDir = null
    let ws = null
    let pollTimer = null
    let settled = false

    const cleanup = () => {
      if (pollTimer !== null) { clearInterval(pollTimer); pollTimer = null }
      try { ws?.close() } catch { /* 已关 */ }
      try { chrome?.kill() } catch { /* 已退 */ }
      if (profileDir) {
        try { fs.rmSync(profileDir, { recursive: true, force: true }) } catch { /* 忽略 */ }
        profileDir = null
      }
    }
    const finish = (result) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      cleanup()
      resolve(result)
    }
    const timer = setTimeout(
      () => finish({ ok: false, error: '浏览器登录超时：未检测到登录成功的 cookie' }),
      timeoutMs,
    )

    // 进入异步流程（executor 本身保持同步，避免 async executor 的未捕获拒绝）
    void (async () => {
      try {
        const exe = opts.chromePath ?? findChrome()
        if (!exe) {
          return finish({
            ok: false,
            error: '未找到 Chrome/Edge/Brave 浏览器；请用「手动粘贴 token」方式，或设置 chromePath',
          })
        }
        profileDir = fs.mkdtempSync(path.join(os.tmpdir(), 'teleagent-login-'))
        // --remote-debugging-port=0 让 Chrome 选随机端口并写进 stderr
        chrome = spawn(exe, [
          `--user-data-dir=${profileDir}`,
          '--remote-debugging-port=0',
          '--no-first-run',
          '--no-default-browser-check',
          '--window-size=480,720',
          LOGIN_URL,
        ], { stdio: ['ignore', 'ignore', 'pipe'] })
        chrome.on('exit', () => {
          if (!settled) finish({ ok: false, error: '浏览器被关闭：未完成登录' })
        })

        const port = await readDebugPort(chrome, Math.min(timeoutMs, 30_000))
        if (!port) return finish({ ok: false, error: '无法读取 Chrome 调试端口' })
        log('浏览器已启动，请在弹出的窗口里完成天翼账号登录…')

        const targets = await cdpTargets(port, fetchImpl)
        const page = (targets ?? []).find((t) => t.type === 'page')
        if (!page?.webSocketDebuggerUrl) return finish({ ok: false, error: '未找到浏览器页面 target' })

        ws = new WebSocket(page.webSocketDebuggerUrl)
        await new Promise((res, rej) => {
          ws.onopen = res
          ws.onerror = () => rej(new Error('CDP WebSocket 连接失败'))
        })
        // 启用 Network domain，让 getAllCookies 覆盖全部 cookie（不只当前文档）
        await cdpCall(ws, 'Network.enable', {})

        pollTimer = setInterval(async () => {
          if (settled) return
          try {
            const cookies = await cdpGetAllCookies(ws)
            const hit = pickCredentials(cookies)
            if (hit) {
              if (pollTimer !== null) { clearInterval(pollTimer); pollTimer = null }
              log('检测到登录凭据，正在补齐门户 cookie…')
              // 落一次门户页，逼它下发 agent.teleai.com.cn 上的那份门户 JWT
              let portalHit = hit
              try {
                await cdpCall(ws, 'Page.navigate', { url: SPACE_URL })
                await new Promise((r) => setTimeout(r, 2500))
                // 门户 token 与 SSO token 是两个客户端签的：问一次门户，按它给的
                // UPMS authorize 地址再走一遍（此时 SSO 会话已存在，静默下发门户 token）
                const mintUrl = await portalMintUrl(ws)
                if (mintUrl) {
                  log('正在补齐门户凭据（积分/签到）…')
                  await cdpCall(ws, 'Page.navigate', { url: mintUrl })
                  await new Promise((r) => setTimeout(r, 3000))
                }
                const richer = pickCredentials(await cdpGetAllCookies(ws))
                if (richer) portalHit = { ...hit, ...richer, token: hit.token }
                // 门户 JWT 也可能只存在 localStorage 里
                const storage = await cdpEval(ws, 'JSON.stringify(Object.fromEntries(Object.entries(localStorage)))')
                if (typeof storage === 'string') {
                  const fromStore = pickPortalTokenFromStorage(JSON.parse(storage))
                  // 只有 cookie 里没拿到独立门户 token 时才用 localStorage 的
                  if (fromStore && (!portalHit.operationToken || portalHit.operationToken === hit.token)) {
                    portalHit = { ...portalHit, operationToken: fromStore }
                  }
                }
              } catch { /* 补不到就用登录那一刻的 */ }
              log('检测到登录凭据，正在关闭浏览器…')
              finish({
                ok: true,
                token: hit.token,
                cookieToken: hit.token,
                portal: {
                  operationToken: portalHit.operationToken,
                  operToken: portalHit.operToken,
                  userId: portalHit.userId,
                  jar: portalHit.jar,
                },
              })
            }
          } catch { /* 单轮失败忽略，下一轮再试 */ }
        }, 1000)
        pollTimer.unref?.()
      } catch (e) {
        finish({ ok: false, error: `浏览器登录失败：${String(e?.message ?? e)}` })
      }
    })()
  })
}

/** 从 Chrome stderr 的 "DevTools listening on ws://127.0.0.1:PORT/..." 行读端口。 */
function readDebugPort(child, timeoutMs) {
  return new Promise((resolve) => {
    let buf = ''
    let done = false
    const settle = (value) => {
      if (done) return
      done = true
      clearTimeout(timer)
      try { child.stderr?.removeListener('data', onData) } catch { /* 已关 */ }
      try { child.stderr?.removeListener('end', onEnd) } catch { /* 已关 */ }
      resolve(value)
    }
    const onData = (chunk) => {
      buf += chunk.toString()
      const m = /DevTools listening on ws:\/\/127\.0\.0\.1:(\d+)\//.exec(buf)
      if (m) settle(Number(m[1]))
    }
    const onEnd = () => settle(null)
    const timer = setTimeout(() => settle(null), timeoutMs)
    timer.unref?.()
    child.stderr?.on('data', onData)
    child.stderr?.on('end', onEnd)
  })
}

async function cdpTargets(port, fetchImpl) {
  const res = await fetchImpl(`http://127.0.0.1:${port}/json/list`)
  return await res.json()
}

function cdpCall(ws, method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = Math.floor(Math.random() * 1e9)
    const onMessage = (ev) => {
      const data = JSON.parse(ev.data)
      if (data.id === id) {
        ws.removeEventListener('message', onMessage)
        if (data.error) reject(new Error(data.error.message ?? 'CDP error'))
        else resolve(data.result)
      }
    }
    ws.addEventListener('message', onMessage)
    ws.send(JSON.stringify({ id, method, params }))
  })
}

async function cdpGetAllCookies(ws) {
  const r = await cdpCall(ws, 'Network.getAllCookies', {})
  return r?.cookies ?? []
}

/** 在页面里求值（returnByValue），用于读 localStorage 里的 token。 */
async function cdpEval(ws, expression) {
  const r = await cdpCall(ws, 'Runtime.evaluate', {
    expression, returnByValue: true, awaitPromise: true,
  })
  return r?.result?.value
}

const JWT_RE = /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/

/** 门户积分接口（浏览器里用来探一次，拿到 401 正文里的 UPMS authorize 地址）。 */
const PORTAL_POINTS_URL = ORIGIN + '/meter/super-agent/user/portal/points/detail'

/** 在页面里问一次门户，把它 401 正文里的 UPMS authorize 地址拿出来。 */
async function portalMintUrl(ws) {
  const expr = `fetch(${JSON.stringify(PORTAL_POINTS_URL)}, { credentials: 'include', headers: { Accept: 'application/json' } })`
    + '.then(r => r.text()).then(t => { try { return JSON.parse(t).data || "" } catch (e) { return "" } })'
  const out = await cdpEval(ws, expr)
  return typeof out === 'string' && /^https?:\/\//.test(out) ? out : ''
}

/** 从 localStorage 里捞门户 JWT：优先带 userInfo 字段（name/phone/email/userName）的那份。 */
function pickPortalTokenFromStorage(storage) {
  if (!storage || typeof storage !== 'object') return ''
  const jwt = []
  for (const v of Object.values(storage)) {
    if (typeof v !== 'string') continue
    if (JWT_RE.test(v)) jwt.push(v)
    else {
      // 有些键存的是 JSON 包裹的 token
      for (const m of v.match(/[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g) ?? []) jwt.push(m)
    }
  }
  if (jwt.length === 0) return ''
  const userInfoKeys = ['name', 'phone', 'email', 'userName', 'username', 'nickName', 'mobile', 'x-aicloud-user-name']
  const scored = jwt.map((t) => {
    let score = 0
    try {
      const payload = JSON.parse(Buffer.from(t.split('.')[1], 'base64url').toString('utf8'))
      for (const k of userInfoKeys) if (payload[k] !== undefined && payload[k] !== null && payload[k] !== '') score += 1
      if (payload.userInfo !== undefined) score += 3
    } catch { /* 非 JWT payload，忽略 */ }
    return { t, score }
  })
  scored.sort((a, b) => b.score - a.score)
  return scored[0].t
}

/**
 * 判断一个 token 属于哪一类：
 * - `sso`：天翼 UPMS 的 uc_auth_token（claim 里带 `tokenType: uc_auth_token_ty`）。**聊天网关用这个。**
 * - `portal`：门户（meter/super-agent 那套）签的 JWT，有 exp / userInfo，没有 tokenType。
 * - `opaque`：不是 JWT（假数据或不透明串）。
 * 两者挑反就是「401 invalid token」与「4001 UserInfo JWT 解析失败」互相对撞，所以必须按类型挑。
 */
export function tokenKind(value) {
  const t = String(value ?? '')
  const payload = t.split('.')[1]
  if (!payload) return 'opaque'
  try {
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'))
    if (claims?.tokenType === 'uc_auth_token_ty') return 'sso'
    return 'portal'
  } catch {
    return 'opaque'
  }
}

/**
 * 从 cookie 列表里挑出全部 teleai 域凭据。
 *
 * 两个 token 必须分开挑，它们不是同一个东西：
 * - **聊天 token**：网关只认 SSO 的 uc_auth_token（父域那份）。挑成门户 JWT 就 401 invalid token。
 * - **门户 token**：门户只认 agent.teleai.com.cn 子域那份带 exp / userInfo 的 JWT。
 *   挑成 uc_auth_token 就 4001 UserInfo JWT 解析失败。
 *
 * 聊天 token 按 claim 类型优先（sso）→ 域最不具体（父域）→ 兜底；
 * 门户 token 按域最具体（子域）+ 非 sso 优先。
 *
 * @returns {{token:string, operationToken:string, operToken:string, jar:Record<string,string>, userId:string} | null}
 */
export function pickCredentials(cookies) {
  const wanted = ['operationToken', 'operToken', 'accessToken', 'x-token']
  const isTeleai = (d) => typeof d === 'string' && /(^|\.)teleai\.com\.cn$/i.test(d)
  const cands = []
  const jar = {}
  const rank = {}
  for (const c of cookies ?? []) {
    if (!isTeleai(c.domain) || !c.name || !c.value) continue
    const r = { domain: (c.domain ?? '').length, path: (c.path ?? '/').length }
    const prev = rank[c.name]
    // 同名的多份 cookie：域越具体（越长）越优先，其次 path 越深越优先
    if (!prev || r.domain > prev.domain || (r.domain === prev.domain && r.path >= prev.path)) {
      jar[c.name] = c.value
      rank[c.name] = r
    }
    if (wanted.includes(c.name)) {
      cands.push({ name: c.name, value: c.value, domain: c.domain ?? '', path: c.path ?? '/', kind: tokenKind(c.value) })
    }
  }
  if (cands.length === 0) return null

  const nameOrder = (n) => { const i = wanted.indexOf(n); return i < 0 ? 99 : i }
  const bySpecificityDesc = (a, b) => b.domain.length - a.domain.length || b.path.length - a.path.length
  const byName = (a, b) => nameOrder(a.name) - nameOrder(b.name)

  // 聊天 token：sso 优先 → 名字优先级（operationToken 最正）→ 域最不具体（父域）
  const chatRank = (c) => (c.kind === 'sso' ? 0 : 1)
  const chatSorted = [...cands].sort((a, b) => chatRank(a) - chatRank(b) || byName(a, b) || -bySpecificityDesc(a, b))
  const token = chatSorted[0]?.value ?? ''

  // 门户 token：非 sso 优先 → 名字优先级 → 域最具体（子域）
  const portalRank = (c) => (c.kind === 'sso' ? 1 : 0)
  const portalSorted = [...cands].sort((a, b) => portalRank(a) - portalRank(b) || byName(a, b) || bySpecificityDesc(a, b))
  const portalToken = portalSorted[0]?.value ?? ''

  if (!token) return null
  return {
    token,
    operationToken: portalToken || token,
    operToken: jar.operToken ?? '',
    jar,
    userId: typeof jar.userId === 'string' ? jar.userId : '',
  }
}

export { pickCredentials as pickTokenCookie }

/** 按平台探测 Chrome/Edge/Brave 可执行文件。可用 TELEAGENT_CHROME_PATH 覆盖。 */
function findChrome() {
  const fromEnv = process.env.TELEAGENT_CHROME_PATH
  if (typeof fromEnv === 'string' && fromEnv.trim()) {
    const candidate = fromEnv.trim()
    try { if (fs.existsSync(candidate)) return candidate } catch { /* 继续自动探测 */ }
  }
  const p = process.platform
  const candidates = p === 'win32'
    ? [
        'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
        'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
        'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
        'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
      ]
    : p === 'darwin'
      ? ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
         '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge']
      : ['/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/microsoft-edge']
  for (const c of candidates) {
    try { if (fs.existsSync(c)) return c } catch { /* 继续 */ }
  }
  return null
}

/**
 * 续期 JWT（服务端 token-refresh 端点；桌面版没有 refresh token，但服务端其实支持）。
 * @param {{token:string, deviceId:string}} auth
 * @param {object} [opts] { appVersion, fetchImpl }
 * @returns {Promise<{ok:boolean, token?:string, expiresIn?:number, error?:string}>}
 */
export async function refreshAccessToken(auth, opts = {}) {
  const fetchImpl = opts.fetchImpl ?? globalThis.fetch
  const appVersion = opts.appVersion ?? '3.0.1'
  try {
    const res = await fetchImpl(TOKEN_REFRESH_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Token': auth.token,
        'X-Timestamp': String(Math.floor(Date.now() / 1000)),
        'X-Nonce': crypto.randomUUID(),
        'X-App-Version': appVersion,
        'X-OS-Type': process.platform,
        'X-SuperAgent-Device-Id': auth.deviceId ?? '',
        'User-Agent': 'super-agent/1.0',
      },
      body: '',
    })
    if (!res.ok) return { ok: false, error: `续期失败：HTTP ${res.status}（可能需要重新登录）` }
    const json = await res.json().catch(() => null)
    const data = json?.data ?? {}
    const token = data.accessToken
    if (!token) return { ok: false, error: '续期响应里没有 accessToken' }
    return { ok: true, token, expiresIn: data.expiresIn }
  } catch (e) {
    return { ok: false, error: `续期失败：${String(e?.message ?? e)}` }
  }
}
