# TeleAgent 免客户端登录 — 协议笔记

本插件复用 [opencode-teleagent-auth](https://github.com/anbulang/opencode-teleagent-auth)（MIT, anbulang）
逆向出的上游协议，但把「凭据来源」从**读桌面端磁盘**换成**插件自己完成登录闭环**。

---

## 一、与参考版的根本区别

| 维度 | 参考版 opencode-teleagent-auth | 本插件 magpie-teleagent-login |
|---|---|---|
| JWT / deviceId / installId 来源 | 桌面端 `users/<scope>/app-auth/` 的 safeStorage 加密文件 | 插件自己登录（浏览器登录 / 手动 token），存进 `accounts.json` |
| 是否需要桌面客户端 | **需要**（2.7.1+，且已登录） | **不需要** |
| 凭据解密 | macOS 钥匙串 PBKDF2+AES-CBC / Windows DPAPI+AES-GCM | 不需要——token 由登录流程直接拿到 |
| 网关 apiKey | 运行时从桌面端 `app.asar` 读常量 | 桌面端不在了 → 用户显式配置 / 环境变量 |
| 平台 | macOS、Windows | macOS、Windows、Linux |

不变：签名算法、5 个模型目录、guard 限速、思考档位削档、portal 积分。

---

## 二、聊天网关签名

逆向自桌面端内核 `GatewaySigner.Sign`。地址：
`https://agent.teleai.com.cn/superCowork/sapi/api/v1/chat/completions`（OpenAI 兼容，流式 SSE）。

**第 1 步（绑定 installId）** — 分隔符是 `/`
```text
key = JWT 第三段（token.split(".")[2]）
msg = "superagent-auth-v1/{token}/{installId}/{ts}/{nonce}"
k1  = hex(HMAC-SHA256(key, msg))
```

**第 2 步（请求签名）** — 分隔符是换行
```text
key = k1（当作 64 字符十六进制文本，不是字节）
msg = "superagent-auth-v1\n{METHOD}\n{pathname}\n{ts}\n{nonce}\n{appVersion}\n{sha256hex(body)}"
sig = hex(HMAC-SHA256(key, msg))
```

三条易踩坑：

| 坑 | 现象 | 正确做法 |
|---|---|---|
| `pathname` 少 `/superCowork/sapi` 前缀 | `40104` | 签名用完整 pathname（含 query） |
| 两处分隔符弄反 | `40104` | 第一轮 `/`，第二轮 `\n` |
| `ts` 用毫秒 | `40103` | `ts` 是**秒**级，每请求新生成 |

### 请求头

| 头 | 值 |
|---|---|
| `Authorization` | `Bearer <网关 apiKey>`（缺失回 `40105`） |
| `X-Token` | JWT（容忍 `tenant:` 前缀） |
| `X-App-Version` | 客户端版本，默认 `3.0.1` |
| `X-Route-Target` | `ops-gateway` |
| `X-Superagent-Device-Id` / `-Install-Id` | 设备指纹 |
| `X-Superagent-Timestamp` / `-Nonce` / `-Signature` / `-Sign-Version` | 每请求现签，版本 `v1` |
| `X-Teleai-Run-Unit-Type` | `agent_loop` |
| `X-Session-Id` / `X-Message-Id` / `X-Teleai-Root-Session-Id` | 客户端生成 |
| `x-teleagent-session` | magpie `chat.headers` 补的稳定会话标识 |

会话/消息 id 由**客户端生成**（协议里不是服务端下发）。

---

## 三、登录闭环（本插件新增）

### 3.1 关键事实：没有纯 API 的短信登录端点

桌面端首次登录走的是**天翼账号 UPMS OAuth 授权码流程**：

```text
桌面端开 BrowserWindow → UPMS 统一认证页 → 用户在天翼账号页登录
  → 回调 /cowork/auth?code=ucc.XXXX → deeplink teleai-cowork://auth?token=… 回传 JWT
  → 桌面端加密写入 app-auth/token.json + 生成 device-meta.json
```

对第三方的限制（实测）：

- `code` 一次性，且已被消费的不可再兑换
- 官方回调 `callback/redirect` 只接受 teleai 域名白名单，`state=http://127.0.0.1` 被拒（401）
- token 走 deeplink 而非 HTTP 兑换端点

**结论**：不存在「手机号 + 短信验证码 → 直接换 TeleAgent JWT」的公开纯 API 端点。
所有已知第三方实现都靠①桌面端已登录态导入，或②浏览器登录。

### 3.2 因此本插件用浏览器登录

```text
GET https://agent.teleai.com.cn/meter/teleagent-login/middle
    ?redirect_url=https%3A%2F%2Fagent.teleai.com.cn%2Fteleagent
```

实现要点：

1. `spawn` 一个 Chromium 系浏览器，`--user-data-dir=<临时目录> --remote-debugging-port=0`
   （端口 0 = 系统分配，从 stderr 的 `DevTools listening on ws://127.0.0.1:PORT/` 读回）
2. 连 CDP：`/json/list` 取 page target 的 WebSocket，`Network.enable`
3. 每 1 秒 `Network.getAllCookies`，过滤 `(^|\.)teleai\.com\.cn$` 域的：
   `operationToken` → `operToken` → `accessToken` → `x-token`
4. 拿到就 `finish`：关浏览器、删临时 profile

`operationToken` 同时是门户（积分/签到）的 cookie，所以一并存进门户凭据，
积分开箱可用，不必像参考版那样去读桌面端的 Chromium SQLite cookie 库。

### 3.3 设备指纹

`deviceId`（12 位 hex）+ `installId`（UUIDv4）参与签名，缺任一上游拒。
二者是**客户端侧生成**的标识（桌面端写在 `app-auth/device-meta.json`），非服务端下发。
本插件由 accountId 确定性派生：

```text
deviceId  = sha256("teleagent-device:{accountId}").hex.slice(0, 12)
installId = sha256("teleagent-install:{accountId}") → 置 version=4 / variant 位 → UUID 形态
```

同账号每次登录得到同一组值。**不要随意更换** —— 改变设备身份会提高风控命中率。

### 3.4 续期

上游有 token-refresh 端点（桌面端没用它）：

```text
POST https://agent.teleai.com.cn/superCowork/sapi/cowork/auth/token-refresh
Content-Type: application/json
X-Token: <当前 JWT>
X-Timestamp: <10 位秒>
X-Nonce: <UUID>
X-App-Version: 3.0.1
X-OS-Type: <win32|darwin|linux>
X-SuperAgent-Device-Id: <deviceId>
Body: 空

响应: data.{ accessToken, expiresIn, absoluteExpiresAt }
```

`expiresIn ≈ 604799`（7 天），绝对上限约 90 天。终止错误 `40112`–`40116` / HTTP 401 = 必须重登。

---

## 四、门户服务（积分 / 签到）

与聊天网关**完全独立的另一个服务**，基址：
`https://agent.teleai.com.cn/meter/super-agent/user/portal`，**cookie 鉴权，不签名**。

| 头 | 值 |
|---|---|
| `X-Token` | `operationToken` |
| `userId` | 账号 id |
| `Cookie` | `operToken=…; operationToken=…` |

| 接口 | 用途 |
|---|---|
| `GET /points/detail` | `data.pointsBalance`、`groups[].active[].effectiveEnd` |
| `GET /companyStore/v2/checkDayTask` | 当日签到状态、可领积分、连续天数 |
| `GET /companyStore/checkTask?type=daily_login` | 执行签到 |
| `GET /companyStore/userCenter` | 套餐名、余额、并发上限 |

两条实测结论：

1. 封禁后门户**仍然可用**（余额能读、签到能领）——「积分还能查」不能证明账号没问题。
2. 签到必须幂等：先查 `claimed_today`，已领直接返回 `done`，**不碰领取接口**；
   领完再查一次确认，接口说成功但复查未签就如实报失败。

---

## 五、账号安全：合成探测会触发风控

上游风控对自动化探测非常敏感，命中后返回 `40109 current user is banned`。实测会触发的行为模式：

- 5 个模型 × 图片 data URL 逐个试
- 50–600KB 填充体测请求上限
- 10 / 100 / 265 个合成工具名
- 每次启动发一次真实请求自检

封禁只作用于**模型通道**，门户接口仍然可用 —— 所以「积分还能查」不能证明账号没问题。

### 硬约束（不要为了性能调大）

| 机制 | 值 | 位置 |
|---|---|---|
| 并发上限 | 2 | `lib/guard.mjs` `maxConcurrent` |
| 每分钟上限 | 20 | `maxPerMinute` |
| 连续认证失败熔断 | 3 次 401/403 → 停 10 分钟 | `failureThreshold` / `cooldownMs` |
| 启动自检聊天请求 | **不发** | 全项目无此代码路径 |

明确不要做：批量 `provider test`、循环压测、超大填充体测上限、批量合成工具名、
用真实账号反复试签名变体（`40104` 刷屏本身就是异常流量）。

---

## 六、上游错误码

| 码 | 含义 | 处置 |
|---|---|---|
| `40103` | 时间戳格式错（用了毫秒） | 用秒级 `ts` |
| `40104` | 签名无效 | 协议变了 / pathname 或分隔符错 → 更新插件 |
| `40105` | 请求疑似攻击 | 网关 apiKey 没带上 → 配置 `apiKey` |
| `40108` | token 无效 | 重新登录 |
| `40109` | 账号封禁（模型通道） | 停手、换账号 |
| `40110` | 账号停用 | 换账号 |
| `40112`–`40116` | 续期终止 | 必须重登 |
| `402` / `4029` | 积分不足 | 签到 / 换低倍率模型 |
| `429` / `4290` | 限流 | 等待 |
| `413` | 请求体过大 | 减工具 / 附件（不是账号问题） |
| `1210` | 内容类型不支持（如图片） | 换 `chat-pro` / `chat-flash` |

`40104` = 签名不对（token 是好的）；`40108` = 身份坏（token 过期/无效）。处置完全不同。

---

## 七、模型目录

来自桌面端 `provider.NewApi.models`（客户端真正在用的那份）：

| modelID | 名称 | context | output | 图片 | 倍率 |
|---|---|---|---|---|---|
| `chat-pro` | 智能 | 400000 | 65536 | ✅ 实测 | x0.6 |
| `chat-flagship` | 旗舰 | 400000 | 65536 | ❌ 1210 | x1.0 |
| `chat-flash` | 极速 | 400000 | 65536 | ✅ 实测 | x0.2 |
| `chat-lite` | 轻量 | 100000 | **16384** | ❌ 200 但答非所问 | x0.5 |
| `chat-nano` | 轻速 | 100000 | **16384** | ❌ not a multimodal model | x0.1 |

图片能力是实测结论（同一张「蓝色三角形 + 文字 42」逐个试），不是上游目录的声明。

**未知 model id 会静默回落**：请求目录外任意字符串，上游不报错而是返回另一个厂商模型的回答。
所以插件在本地对目录外 id 直接 404，不把这种请求放到上游。

### 思考档位

上游只认 `low` / `high` / `max`，且**拒绝任何"关闭思考"写法**（400：
「该模型始终思考，不支持关闭思考；请使用 low、high 或 max。」）。
宿主会按自己的理解写 `reasoning_effort`（如 `medium`），插件在 loader 的 fetch 里削：

- `low`/`high`/`max` 原样保留
- `minimal`→`low`、`medium`/`xhigh`→`high`（就近落档，不擅自降到底）
- `off`/`none`/`disabled` 及 `thinking` / `enable_thinking` 之类 → 删掉整个字段

只碰思考键，其余字段一字节不动；没有思考字段时原样返回同一字符串（不做 parse→stringify 往返）。
