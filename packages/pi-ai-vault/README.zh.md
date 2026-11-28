# pi-ai-vault

[English](README.md)

ai-vault 的 pi 扩展——**omp 也能直接装同一个包**（omp 是 pi 的兼容分支，清单和工具 API 一致；差别只在 `src/host.ts` 的运行时探测里）。

它把本地加密密码库交给 [`ai-vault`](https://www.npmjs.com/package/@xiaolikt/ai-vault) 这个 Rust CLI：一台电脑一个库（`~/.ai-vault`），所有 agent 共用。插件本身不做加解密，只持有会话令牌。

## 安装

```bash
pi install npm:pi-ai-vault        # pi，自动带上 ai-vault CLI
omp plugin install npm:pi-ai-vault  # omp，同一个包
```

然后在该宿主的会话里：

```
/vault init
```

（弹窗设主密码，两次。有桌面就开 zenity，没有就退回宿主自己的输入框。）

不想用 npm 也可以从仓库装：`pi install git:github.com/xiaolikt/ai-vault`。

## 工具

| 工具 | 作用 | 模型看到密码？ |
|---|---|---|
| `vault_list` | 本地库条目元数据 | 否 |
| `vault_get` | 读一条：**先本地库，再 Bitwarden**；Bitwarden 命中会问「读一次 / 导入 ai-vault」 | 是，用户当场允许 |
| `vault_add` | 存一条；密码由用户在弹出的窗口里输入 | 否 |
| `vault_import` | 把 Bitwarden 登录项抄进本地库（先确认） | 否 |
| `bw_list` / `bw_run` / `bw_clipboard` / `bw_reveal` | 在线 Bitwarden（`bw` CLI） | 否，`bw_reveal` 除外 |
| `bw_inject` | 注入 bash 环境（**仅 pi**，omp 不注册） | 否 |
| `ente_list` | Ente Auth 条目元数据 | 否 |
| `ente_code` | 当前 TOTP/Steam 验证码（每次确认） | 是，用户当场允许 |

## 命令

```
/vault init | unlock | lock | status | list | add | remove
/vault grant <名称> [分钟] | revoke <名称|all> | audit [n]
/vault import <bitwarden.json> | import-bw [搜索词]
/bw status|unlock|lock|clear
```

## 解锁模式

本地库什么时候要主密码，由这台机器的模式决定（`/vault mode`，切换要主密码）：

| 模式 | 行为 |
|---|---|
| `never` | 永远不问，读取也不弹确认窗——「agent 可以自由使用」的那批密码 |
| `time` | 解锁后 N 小时（默认 8）再问一次 |
| `session` | 每个会话一次，会话结束失效（默认） |

`vault_get` 找不到本地条目时会去 Bitwarden 搜；命中后按 `bitwarden.import` 处理：

| `bitwarden.import` | 行为 |
|---|---|
| `ask`（默认） | 给你看这一条 → 读一次 → 问「导入 ai-vault / 只用这一次」 |
| `always` | 命中直接导入并返回，不开窗口 |
| `never` | 只读一次，永不写入本地库 |

所以默认情况下 **只有你同意导入的密码才会进 ai-vault**。Bitwarden 自己的主密码请求频率也有单独设置（`bitwarden.unlock`：`never` / `time` / `session`），用 `/vault settings` 查看和修改。

## Ente

`ente` CLI 自己登录一次（`ente account login --app auth`），插件只是它的客户端：`ente_list` 只给元数据，`ente_code` 每次弹窗确认。

想完全免钥匙串：`ente vault key generate` → `/vault ente-key` 粘进去 → `/vault settings ente.unlock never`。密钥由 ai-vault 加密封存。详见仓库 README。

## 安全边界（一句话版）

模型的 `bash` 能找到会话令牌、能 `list`，但**签不出读取确认**（签名密钥只在插件进程内存里）、**改不了令牌文件**（带 HMAC，改了就作废）、**免费拿不到 `grant`**（要主密码）。详见仓库 README「安全」一节。

## 隔离

每个会话、每个子代理各自 `ai-vault unlock`，拿自己的令牌和读授权；父会话的解锁子代理继承不到。空闲 10 分钟自动失效，`/new`、`/fork`、退出会清掉本绑定的令牌。

完整说明（CLI 参数、退出码契约、Bitwarden 擦洗、审计、安全模型）见仓库 README：https://github.com/xiaolikt/ai-vault

MIT
