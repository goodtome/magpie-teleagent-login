/**
 * 思考档位（reasoning effort）的上游适配。
 * 复用自 opencode-teleagent-auth（MIT, anbulang）。
 *
 * TeleAgent 上游只认 low / high / max 三档，且拒绝任何"关闭思考"写法（否则整轮 400）。
 * 在 loader 的 fetch 里把宿主写进请求体的档位削成上游认的：只碰思考键，其余字段一字节不动。
 */
export const ACCEPTED_EFFORTS = ['low', 'high', 'max']
export const DEFAULT_EFFORT = 'high'

const EFFORT_KEYS = ['reasoning_effort', 'reasoningEffort']
const THINKING_KEYS = ['enable_thinking', 'thinking']
const OFF_VALUES = new Set(['off', 'none', 'disabled', 'false', 'no', '0'])

export function normalizeEffort(level) {
  if (typeof level !== 'string') return null
  const value = level.trim().toLowerCase()
  if (value === '') return null
  if (OFF_VALUES.has(value)) return null
  if (ACCEPTED_EFFORTS.includes(value)) return value
  if (value === 'minimal') return 'low'
  if (value === 'medium') return 'high'
  if (value === 'xhigh') return 'high'
  return DEFAULT_EFFORT
}

export function normalizeUpstreamBody(raw) {
  const text = typeof raw === 'string' ? raw : ''
  const unchanged = { body: text, changed: false, from: '', to: null }
  if (text.length === 0) return unchanged
  let parsed
  try { parsed = JSON.parse(text) } catch { return unchanged }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return unchanged
  const touched = [...EFFORT_KEYS, ...THINKING_KEYS].some((key) => key in parsed)
  if (!touched) return unchanged
  const foundKey = EFFORT_KEYS.find((key) => key in parsed)
  const rawEffort = foundKey ? parsed[foundKey] : undefined
  const from = typeof rawEffort === 'string' ? rawEffort : ''
  const to = normalizeEffort(from)
  const extraKeys = THINKING_KEYS.some((key) => key in parsed)
  const effortAlreadyFine = EFFORT_KEYS.some((key) => key in parsed) &&
    typeof rawEffort === 'string' && rawEffort === to &&
    !EFFORT_KEYS.some((key) => key in parsed && key !== EFFORT_KEYS[0])
  if (effortAlreadyFine && !extraKeys) return unchanged
  for (const key of [...EFFORT_KEYS, ...THINKING_KEYS]) delete parsed[key]
  if (to !== null) parsed.reasoning_effort = to
  return { body: JSON.stringify(parsed), changed: true, from, to }
}

export function reasoningOfBody(raw) {
  if (typeof raw !== 'string' || raw.length === 0) return ''
  try {
    const parsed = JSON.parse(raw)
    if (parsed === null || typeof parsed !== 'object') return ''
    for (const key of EFFORT_KEYS) {
      if (typeof parsed[key] === 'string') return parsed[key]
    }
  } catch { /* 不是 JSON */ }
  return ''
}
