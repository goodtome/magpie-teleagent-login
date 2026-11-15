# TeleAgent 模型接入 magpie —— 安装使用说明

5 分钟装完：不用下载天翼客户端、不用申请 API Key，用手机号在浏览器里登录一次就能用上
TeleAgent（天翼 AI 星辰）的模型。

---

## 0. 准备

- 一台能上网的电脑（Windows / macOS / Linux）
- 已经装好并打开过一次 **magpie**（托盘里有它的图标就算就绪）；没有的话找分享者要安装包
- 一个能登录 TeleAgent 的账号（手机号 + 验证码）

---

## 1. 装插件

```bash
magpie plugin add github:goodtome/magpie-teleagent-login
```

Windows 下 magpie 不在 PATH 里时，用完整路径（注意路径里有空格要加引号）：

```powershell
& "C:\你的路径\magpie.exe" plugin add github:goodtome/magpie-teleagent-login
```

成功的标志：

```
✓ added github:goodtome/magpie-teleagent-login
github:goodtome/magpie-teleagent-login (magpie-teleagent-login 0.2.1)  on
  tools  magpie-teleagent-login_points
  teleagent (TeleAgent, 5 models)  not signed in · magpie plugin login teleagent
```

`not signed in` 是正常的，下一步登录。

---

## 2. 登录（唯一需要动手的一步）

```bash
magpie plugin login teleagent
```

出现三个选项时，**选 1（浏览器登录）**：

```
1) 浏览器登录（自动获取，推荐）
2) 手动粘贴 token（零依赖兜底）
3) 补门户 cookie（只修积分/签到，不动聊天凭据）
```

选 1 之后会自动打开浏览器：

1. 输入手机号 → 获取验证码 → 登录
2. 看到授权/同意页面就点同意
3. 浏览器提示「可以关闭此页面了」，回到终端

终端出现这行就成功了：

```
signed in as user_xxxxxxxx
```

> 选 1 一次就同时拿到聊天凭据和门户凭据（积分/签到都能用）。
> 只有浏览器实在打不开时才用选 2 手动粘贴 token，那种情况下积分功能可能不可用。

---

## 3. 确认能用

```bash
magpie plugin list                     # 看 teleagent 是否 signed in
magpie quota                           # 看积分余额（不消耗额度）
```

预期输出：

```
> teleagent · 免费版 · user_xxxxxxxx
   subscription  积分余额 6,099.98 积分 left
```

---

## 4. 在 agent 里选模型

打开 magpie 主界面，找到你要用的 agent（Claude Code / Codex / DeepSeek Harness 等），
在它的模型下拉里选一个 `teleagent/...` 开头的模型即可。

| 模型 | 上下文 | 视觉 | 积分倍率 | 什么时候用 |
|---|---|---|---|---|
| `teleagent/chat-nano` | 100K | – | ×0.1 | 日常问答、改代码，最省 |
| `teleagent/chat-flash` | 400K | ✓ | ×0.2 | 要传截图/图片，性价比高 |
| `teleagent/chat-lite` | 100K | – | ×0.5 | 中等难度任务 |
| `teleagent/chat-pro` | 400K | ✓ | ×0.6 | 长文档 + 图片 |
| `teleagent/chat-flagship` | 400K | – | ×1.0 | 最难的推理/写作 |

免费版每天送的积分足够个人日常用，`magpie quota` 随时能看。

---

## 5. 日常维护

```bash
magpie plugin update    # 拉取插件更新
magpie quota            # 查余额
magpie plugin login teleagent   # 凭据失效时重新登录
magpie plugin rm github:goodtome/magpie-teleagent-login   # 卸载
```

---

## 常见问题

**`40108 invalid token` / `401 invalid token`**
存的凭据过期或类型不对。重新登录一次，**选 1**：

```bash
magpie plugin login teleagent
```

**`40105 疑似攻击请求`**
缺网关 apiKey。找分享者要这个常量，填一次：

```bash
magpie plugin options github:goodtome/magpie-teleagent-login '{"apiKey":"粘贴到这里"}'
```

**积分显示不出来，但聊天正常**
你之前是用选 2 手动粘的 token，只有聊天凭据没有门户 cookie。再登录一次选 1，或选 3 单独补门户 cookie。

**DeepSeek Harness 里切 `teleagent/chat-nano` 报 `context compaction failed`**
DSH 给每个模型默认留 65536 token 压缩余量，100K 窗口的模型会被挤到只剩 18080，
换模型前的自检压缩必然失败（跟插件无关，400K 的模型不会）。修法见插件 README 的
「DeepSeek Harness 里报 context compaction failed」一节。

**`40109` 或被封禁**
上游风控。插件默认并发 2、每分钟 20 次，不要再调大；等一段时间或换号。

---

## 注意

- 这是**非官方**项目，靠逆向上游协议实现，上游改了要等插件更新
- 用自己的账号登录，不要把 token 复制给别人
- 凭据只存在你自己机器上（插件数据目录里的 `accounts.json`），不会上传
