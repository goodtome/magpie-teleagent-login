/**
 * 上游网关 apiKey 解析（免客户端版）。
 *
 * 参考 opencode-teleagent-auth（MIT, anbulang）：网关 apiKey 是桌面端 app.asar 内置常量，
 * 不是真正的鉴权（真正鉴权是 JWT + 签名），但缺失上游回 `40105 您的请求疑似攻击请求`。
 *
 * 免客户端版没有桌面端可读，所以只剩两条来源：
 *   1. 插件选项 apiKey（magpie plugin options teleagent '{"apiKey":"…"}'）
 *   2. 环境变量 TELEAGENT_API_KEY
 * 两步都失败就发空串，上游回 40105，插件翻译成「请在插件里配置网关 apiKey」。
 */
export function resolveApiKey({ explicit, env = process.env } = {}) {
  if (typeof explicit === 'string' && explicit.trim()) {
    return { key: explicit.trim(), source: '配置' }
  }
  const fromEnv = env.TELEAGENT_API_KEY
  if (typeof fromEnv === 'string' && fromEnv.trim()) {
    return { key: fromEnv.trim(), source: '环境变量' }
  }
  return { key: '', source: '未配置' }
}
