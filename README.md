# omp-vault

omp 和 pi 共用的密码扩展：可以**直接查 Bitwarden**，可以把 Bitwarden **导入**到本地库，也可以**自己单独存**。单独存的时候，主密码和条目密码走**桌面弹窗**（zenity），不经过对话。

本地库用 ChaCha20-Poly1305 加密，文件在 `~/.omp/vault/store.json`（`0600`）。在线 Bitwarden 不把会话密钥写入磁盘，也不放进模型的 bash 环境。

不要同时安装 [pi-bitwarden](https://github.com/xiaolikt/pi-bitwarden)。两边都会注册 `bw_*`，工具会重复。

## 能做什么

| 工具 / 命令 | 作用 | 模型看得到密码？ |
|---|---|---|
| `bw_list` | 在线查 Bitwarden（名称 / 用户名 / URI / id） | 否 |
| `bw_inject` | 把 Bitwarden 密码注入后续 bash（**仅 pi**） | 否 |
| `bw_run` | 用 `$VAULT_SECRET` 跑一条命令（**pi 和 omp**） | 否，输出会擦掉 |
| `bw_clipboard` | 复制到剪贴板，到时清除 | 否 |
| `bw_reveal` | 明文返回（每次都要确认） | 是，用户当场允许 |
| `vault_list` | 本地库元数据 | 否 |
| `vault_add` | 存进本地库；**密码由弹窗输入** | 否 |
| `vault_import` | 把 Bitwarden 登录项抄进本地库（先弹窗确认） | 否 |
| `vault_get` | 读本地库；弹窗授权，5 分钟内有效 | 是，用户当场允许 |
| `/vault …` | 人来操作本地库 | — |
| `/bw …` | 人来操作 Bitwarden 会话 | — |

`bw_list` / `bw_inject` / `bw_run` / `bw_clipboard` / `bw_reveal` 的字段：`password`（默认）· `totp`（种子）· `code`（动态验证码）· `notes` · `field:<自定义字段>`。

## 弹窗

有桌面（`DISPLAY` 或 `WAYLAND_DISPLAY`）时，本地库这些操作打开 zenity 窗口：

- `/vault init`：主密码，再确认一次
- `/vault unlock`、以及任何需要解锁的工具：主密码
- `/vault add`、`vault_add`：用户名，然后密码。工具参数里**没有密码字段**
- `vault_get`、`vault_import`：确认窗口（默认焦点在「拒绝」）

关掉窗口就是取消，不会再弹一个终端输入框。没装 zenity、或窗口起不来时，才退回 omp/pi 的 TUI。pi 的 TUI 输入是可见的；omp 会尽量掩码。

## 安装

需要 Node 22+（omp 自带的运行时即可）、`bw`（先 `bw login`）和 `zenity`。

```bash
# omp
omp plugin install git+ssh://git@github.com/xiaolikt/omp-vault.git

# pi（私有仓库用 SSH）
pi install git:git@github.com:xiaolikt/omp-vault.git
```

本地开发（改完即生效，omp 是链接）：

```bash
omp plugin install /path/to/omp-vault
pi install /path/to/omp-vault
```

已经装过 pi-bitwarden 时先卸掉，避免 `bw_*` 出现两套：

```bash
omp plugin uninstall pi-bitwarden
pi remove git:github.com/xiaolikt/pi-bitwarden
```

## 用法

```
/vault init                      创建本地库（弹窗设主密码）
/vault unlock | lock             解锁 / 锁定
/vault add [名称]                弹窗输入密码
/vault import <bw.json>          从 Bitwarden 未加密 JSON 导入
/vault import-bw [搜索词]        从 bw CLI 直接导入
/bw status | unlock | lock       在线 Bitwarden
```

查在线库用 `bw_list`。要让命令用到密码、但对话里不出现，用 `bw_run`（omp）或 `bw_inject`（pi）。要把一批登录项留在本地，用 `vault_import` 或 `/vault import-bw`。之后即使不连 Bitwarden，也可以 `vault_list` / `vault_get`。

JSON 导入只收**带密码的登录项**。同名条目会更新；Bitwarden 里重名的会存成 `名称 (2)`、`名称 (3)`。

## 安全

- 本地主密码和条目密码只出现在弹窗或（没有桌面时）TUI 里，不进工具参数。
- Bitwarden 主密码经环境变量交给 `bw unlock`，不进 argv。`BW_SESSION` 只留在 agent 进程内存。
- `bw_inject` 在 omp 上会直接失败：omp 丢掉了 bash 的 `spawnHook` 环境。用 `bw_run`。
- 注入或 `bw_run` 过的值会从后续工具输出里擦掉（含 base64 / URL / hex）。短于 6 字符的值不擦。
- 本地库 10 分钟无操作自动锁定。`vault_get` 的授权默认 5 分钟。
- 审计：`~/.omp/vault/audit.log`。Bitwarden 侧的配置和审计仍在 `~/.bw/pi-extension/`（`autoLockMinutes`、`allowReveal`、`clipboardClearSeconds` 等，类型错误按关闭处理）。
- omp 一个进程里多个会话时，Bitwarden 解锁状态是进程级的，不按会话隔离。

`vault_get` 和 `bw_reveal` 得到的明文会进入模型上下文和会话文件，所以每次都要人点允许。

## 环境变量

- `OMP_VAULT_DIR` — 本地库目录，默认 `~/.omp/vault`

## 测试

```bash
npm test
npm run typecheck
```

## License

MIT
