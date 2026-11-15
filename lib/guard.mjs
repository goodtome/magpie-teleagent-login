/**
 * 上游调用防护：并发节流 + 每分钟限速 + 认证失败熔断。
 * 复用自 opencode-teleagent-auth（MIT, anbulang）。
 * 这些数字是账号存活参数（2026-10-27 两次封号复盘结论），不要调大。
 */
export const DEFAULT_GUARD = {
  maxConcurrent: 2,
  maxPerMinute: 20,
  failureThreshold: 3,
  cooldownMs: 10 * 60 * 1000,
  authFailureStatuses: [401, 403],
  idleMs: 10 * 60 * 1000,
}

export class GuardBlockedError extends Error {
  constructor(retryAfterMs, reason) {
    super(`上游调用已暂停：${reason}`)
    this.name = 'GuardBlockedError'
    this.code = 'circuit_open'
    this.circuitOpen = true
    this.retryAfterMs = retryAfterMs
    this.reason = reason
  }
}

export function createGuard(options = {}, now = options.now ?? (() => Date.now())) {
  const cfg = { ...DEFAULT_GUARD, ...options }
  const maxConcurrent = Math.max(1, Number(cfg.maxConcurrent) || 1)
  const failureThreshold = Math.max(1, Number(cfg.failureThreshold) || 1)
  const cooldownMs = Math.max(0, Number(cfg.cooldownMs) || 0)
  const idleMs = Math.max(0, Number(cfg.idleMs) || 0)
  let active = 0
  const waiters = []
  let consecutiveFailures = 0
  let openUntil = 0
  let halfOpenProbeInFlight = false
  let lastReason = null
  let lastFailureAt = null
  let totalRejected = 0
  let windowStart = 0
  let windowCount = 0
  let totalThrottled = 0
  let lastActivityAt = now()
  let idleTimer = null
  let idleFired = false

  function touch() {
    lastActivityAt = now()
    if (idleMs <= 0 || idleFired) return
    if (idleTimer !== null) return
    const schedule = () => {
      idleTimer = setTimeout(() => {
        idleTimer = null
        if (active > 0) { schedule(); return }
        if (now() - lastActivityAt < idleMs) { schedule(); return }
        idleFired = true
        try { cfg.onIdle?.() } catch { /* 忽略 */ }
      }, Math.min(idleMs, 60_000))
      idleTimer.unref?.()
    }
    schedule()
  }

  function acquire() {
    if (active < maxConcurrent) { active++; return Promise.resolve() }
    return new Promise((resolve) => waiters.push(resolve))
  }
  function release() {
    active--
    const next = waiters.shift()
    if (next) { active++; next() }
  }

  return {
    config: cfg,
    check() {
      if (openUntil === 0) return
      const remaining = openUntil - now()
      if (remaining > 0) { totalRejected++; throw new GuardBlockedError(remaining, lastReason ?? '连续认证失败') }
      if (halfOpenProbeInFlight) { totalRejected++; throw new GuardBlockedError(cooldownMs, '半开状态已有探测请求在途') }
      halfOpenProbeInFlight = true
    },
    async throttle() {
      const limit = Number(cfg.maxPerMinute) || 0
      if (limit <= 0) return
      const t = now()
      if (t - windowStart >= 60_000) { windowStart = t; windowCount = 0 }
      if (windowCount < limit) { windowCount++; return }
      const waitMs = Math.max(1, Math.min(60_000 - (t - windowStart), 60_000))
      totalThrottled++
      await new Promise((resolve) => { const timer = setTimeout(resolve, waitMs); timer.unref?.() })
      windowStart = now()
      windowCount = 1
    },
    async withSlot(fn) {
      this.check()
      await this.throttle()
      await acquire()
      touch()
      try { return await fn() } finally { release(); touch() }
    },
    observe(status) {
      const numeric = Number(status)
      if (cfg.authFailureStatuses.includes(numeric)) {
        consecutiveFailures++
        lastReason = `连续 ${consecutiveFailures} 次认证失败（HTTP ${numeric}）`
        lastFailureAt = now()
        halfOpenProbeInFlight = false
        if (openUntil !== 0) { openUntil = now() + cooldownMs }
        else if (consecutiveFailures >= failureThreshold) { openUntil = now() + cooldownMs }
        return
      }
      consecutiveFailures = 0
      openUntil = 0
      halfOpenProbeInFlight = false
      lastReason = null
    },
    isOpen() { return openUntil !== 0 && now() < openUntil },
    reset() {
      consecutiveFailures = 0
      openUntil = 0
      halfOpenProbeInFlight = false
      lastReason = null
      lastFailureAt = null
    },
    snapshot() {
      return {
        open: this.isOpen(),
        cooldownRemainingMs: openUntil === 0 ? 0 : Math.max(0, openUntil - now()),
        consecutiveFailures, failureThreshold, maxConcurrent, active,
        queued: waiters.length, totalRejected, totalThrottled, maxPerMinute: cfg.maxPerMinute,
        lastReason, lastFailureAt,
      }
    },
    dispose() { if (idleTimer !== null) clearTimeout(idleTimer); idleTimer = null },
  }
}
