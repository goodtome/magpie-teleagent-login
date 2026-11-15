/**
 * 离线测试：凭据库（免客户端版）。
 * 每个测试用独立临时目录，绝不碰真实 ~/.local/share。
 */
import { test, expect, beforeEach, afterEach } from 'bun:test'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import {
  saveAccount, readAccount, listAccounts, removeAccount,
  diagnoseCredential, parseClaims, accountKeyFor, storePaths, CredentialState,
} from '../lib/credential.mjs'
import { deriveDeviceIdentity } from '../lib/login.mjs'

let dir
let file

/** 造一个带 accountId 的假 JWT（不校验签名，只取声明）。 */
function fakeJwt(claims, expOffsetSec = 30 * 86400) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')
  const payload = Buffer.from(JSON.stringify({
    accountId: 'acc-1', accountName: '测试账号', tenant: 't1',
    exp: Math.floor(Date.now() / 1000) + expOffsetSec,
    ...claims,
  })).toString('base64url')
  const sig = crypto.randomBytes(16).toString('base64url')
  return `${header}.${payload}.${sig}`
}

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ta-cred-'))
  file = path.join(dir, 'accounts.json')
})
afterEach(() => {
  try { fs.rmSync(dir, { recursive: true, force: true }) } catch { /* 忽略 */ }
})

test('storePaths 支持环境变量覆盖', () => {
  const old = process.env.TELEAGENT_PLUGIN_DATA
  process.env.TELEAGENT_PLUGIN_DATA = dir
  try {
    const p = storePaths()
    expect(p.root).toBe(path.join(dir, 'teleagent-login'))
    expect(p.file).toBe(path.join(dir, 'teleagent-login', 'accounts.json'))
  } finally {
    if (old === undefined) delete process.env.TELEAGENT_PLUGIN_DATA
    else process.env.TELEAGENT_PLUGIN_DATA = old
  }
})

test('空库：读账号返回 not_signed_in，不抛错', () => {
  const r = readAccount(undefined, file)
  expect(r.ok).toBe(false)
  expect(r.state).toBe(CredentialState.NOT_SIGNED_IN)
})

test('保存后能读回，并成为当前账号', () => {
  const token = fakeJwt({})
  const saved = saveAccount({ token }, file)
  expect(saved.key).toBe('acc-1')
  const r = readAccount(undefined, file)
  expect(r.ok).toBe(true)
  expect(r.token).toBe(token)
  expect(r.accountName).toBe('测试账号')
  expect(r.accountId).toBe('acc-1')
  expect(r.tenant).toBe('t1')
  expect(r.daysLeft).toBeGreaterThanOrEqual(29)
})

test('未给设备指纹时由 accountId 确定性派生，同账号稳定', () => {
  const token = fakeJwt({})
  const a = saveAccount({ token }, file)
  const b = saveAccount({ token }, file)
  expect(a.account.deviceId).toBe(b.account.deviceId)
  expect(a.account.installId).toBe(b.account.installId)
  expect(a.account.deviceId).toHaveLength(12)
  expect(a.account.installId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
  // 与直接派生一致
  const expect1 = deriveDeviceIdentity('acc-1')
  expect(a.account.deviceId).toBe(expect1.deviceId)
  expect(a.account.installId).toBe(expect1.installId)
})

test('过期账号：ok=false 且 state=expired', () => {
  const token = fakeJwt({ accountId: 'acc-exp' }, -3600)
  saveAccount({ token }, file)
  const r = readAccount('acc-exp', file)
  expect(r.ok).toBe(false)
  expect(r.state).toBe(CredentialState.EXPIRED)
})

test('多账号列出，当前账号排最前', () => {
  saveAccount({ token: fakeJwt({ accountId: 'a1' }) }, file)
  saveAccount({ token: fakeJwt({ accountId: 'a2' }) }, file)
  const list = listAccounts(file)
  expect(list.map((x) => x.key)).toEqual(['a2', 'a1'])
  expect(list[0].current).toBe(true)
  expect(list[1].current).toBe(false)
})

test('删除账号后当前指针转移到剩下的账号', () => {
  saveAccount({ token: fakeJwt({ accountId: 'a1' }) }, file)
  saveAccount({ token: fakeJwt({ accountId: 'a2' }) }, file)
  expect(removeAccount('a2', file)).toBe(true)
  expect(removeAccount('a2', file)).toBe(false)
  const r = readAccount(undefined, file)
  expect(r.ok).toBe(true)
  expect(r.key).toBe('a1')
})

test('parseClaims 容忍 `tenant:` 前缀', () => {
  const token = fakeJwt({ accountId: 'prefixed' })
  const claims = parseClaims('someprefix:' + token)
  expect(claims.accountId).toBe('prefixed')
})

test('parseClaims 对坏 token 抛 token_malformed', () => {
  expect(() => parseClaims('not-a-jwt')).toThrow()
  try { parseClaims('a.!!!.c') } catch (e) { expect(e.code).toBe('token_malformed') }
})

test('accountKeyFor 在没有 accountId 时退化为 token 指纹', () => {
  expect(accountKeyFor('t', { accountId: 42 })).toBe('42')
  const k = accountKeyFor('opaque-token', {})
  expect(k).toMatch(/^tok_[0-9a-f]{12}$/)
})

test('saveAccount 拒绝空 token', () => {
  expect(() => saveAccount({ token: '' }, file)).toThrow()
})

test('diagnoseCredential 给出 loader 需要的字段', () => {
  const token = fakeJwt({})
  saveAccount({ token }, file)
  const d = diagnoseCredential(undefined, file)
  expect(d.ok).toBe(true)
  expect(d.token).toBe(token)
  expect(d.scope).toBe('acc-1')
  expect(d.deviceId).toHaveLength(12)
  expect(d.installId).toMatch(/^[0-9a-f-]{36}$/)
  expect(d.appVersion).toBeTruthy()
  expect(d.detail).toContain('已登录')
})

test('diagnoseCredential 在未登录时透传状态码', () => {
  const d = diagnoseCredential(undefined, file)
  expect(d.ok).toBe(false)
  expect(d.state).toBe(CredentialState.NOT_SIGNED_IN)
})

test('写盘是原子替换：不会留下半截 JSON', () => {
  saveAccount({ token: fakeJwt({ accountId: 'a1' }) }, file)
  const raw = fs.readFileSync(file, 'utf8')
  expect(() => JSON.parse(raw)).not.toThrow()
  // 临时文件不应残留
  const leftovers = fs.readdirSync(dir).filter((n) => n.endsWith('.tmp'))
  expect(leftovers).toHaveLength(0)
})
