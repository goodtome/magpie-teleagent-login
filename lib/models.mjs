/**
 * magpie 插件的模型清单。
 * 复用自 opencode-teleagent-auth（MIT, anbulang）。五个内置模型与实测结论见 docs/PROTOCOL.md。
 * vision 是实测结论，不是上游目录声明。
 */
import { ACCEPTED_EFFORTS, DEFAULT_EFFORT } from './effort.mjs'

export const MODELS = [
  { id: 'chat-pro', name: '智能', contextWindow: 400_000, maxTokens: 65_536, rate: 'x0.6', vision: true },
  { id: 'chat-flagship', name: '旗舰', contextWindow: 400_000, maxTokens: 65_536, rate: 'x1.0', vision: false },
  { id: 'chat-flash', name: '极速', contextWindow: 400_000, maxTokens: 65_536, rate: 'x0.2', vision: true },
  { id: 'chat-lite', name: '轻量', contextWindow: 100_000, maxTokens: 16_384, rate: 'x0.5', vision: false },
  { id: 'chat-nano', name: '轻速', contextWindow: 100_000, maxTokens: 16_384, rate: 'x0.1', vision: false },
]

export const TELEAI_ACCEPTED_EFFORTS = ACCEPTED_EFFORTS
export const TELEAI_DEFAULT_EFFORT = DEFAULT_EFFORT
export const VISION_MODEL_IDS = MODELS.filter((m) => m.vision === true).map((m) => m.id)

export const TELEAI_ORIGIN = 'https://agent.teleai.com.cn'
export const TELEAI_API_PREFIX = '/superCowork/sapi'
export const TELEAI_CHAT_PATH = '/api/v1/chat/completions'
export const TELEAI_BASE_URL = TELEAI_ORIGIN + TELEAI_API_PREFIX + '/api/v1'
export const TELEAI_SIGNED_PATH = TELEAI_API_PREFIX + TELEAI_CHAT_PATH
export const TELEAI_ROUTE_TARGET = 'ops-gateway'

/**
 * 请求头 X-App-Version 的默认值（参与签名）。
 * 取上游客户端当前版本；上游改版时只改这一处。
 */
export const DEFAULT_APP_VERSION = '3.0.1'

/** 把模型清单转成 OpenCode Model（magpie 的 config 钩子里的 models）。 */
export function buildModels() {
  return Object.fromEntries(MODELS.map((m) => [m.id, {
    name: `${m.name} · ${m.rate}`,
    id: m.id,
    limit: { context: m.contextWindow, input: m.contextWindow, output: m.maxTokens },
    reasoning: true,
    tool_call: true,
    attachment: m.vision,
    modalities: { input: m.vision ? ['text', 'image'] : ['text'], output: ['text'] },
    interleaved: { field: 'reasoning_content' },
    rate: m.rate,
  }]))
}
