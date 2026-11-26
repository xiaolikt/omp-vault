# omp-vault

omp 和 pi 共用一个插件：本地加密密码库 + 在线 Bitwarden。可以**直接查 Bitwarden**，可以把它**导入**到本地库，也可以**自己单独存**——单独存的时候，主密码和条目密码走桌面弹窗，不经过对话。

本地库：`~/.omp/vault/store.json`，ChaCha20-Poly1305 + scrypt，`0600`。Bitwarden 的会话密钥只留在 agent 进程内存里，不落盘、不进 bash 环境。

**不要同时安装 [pi-bitwarden](https://github.com/xiaolikt/pi-bitwarden)。** 两边都会注册 `bw_*`，工具会重复。

## 为什么是一个插件，而不是两个

omp 是 pi 的兼容分支，清单、工具、命令 API 一致，差异只有这几处，全部在 `src/host.ts` 里按运行时特性判断：

| 差异 | pi | omp |
|---|---|---|
| 会话生命周期 | `session_start` / `session_shutdown` 带 `reason` | 两者都没有 `reason`；切换原因在 `session_switch` |
| 子代理身份 | 无 | `ctx.agent.kind === "sub"` |
| 工具审批等级 | 无此字段（忽略） | `approval: "read" \| "write" \| "exec"` |
| bash 注入 | `createBashTool` 的 `spawnHook` 生效 | 丢弃 `spawnHook` 环境 → 只提供 `bw_run` |
| 定时器 | 自己管 | `ctx.setInterval` 随会话清理 |

核心（加密库、`bw` 调用、擦洗、导入）完全共用。拆成两个包只会把同一份核心复制两遍、让用户装错一个。

## 工具

| 工具 | 作用 | 等级 | 模型看到密码？ |
|---|---|---|---|
| `bw_list` | 查 Bitwarden 元数据（名称/用户名/URI/id） | read | 否 |
| `bw_run` | 用 `$VAULT_SECRET` 跑一条命令，输出擦洗 | exec | 否 |
| `bw_inject` | 注入 bash 环境（**仅 pi**，omp 不注册） | exec | 否 |
| `bw_clipboard` | 复制到剪贴板，到时清除 | write | 否 |
| `bw_reveal` | 明文返回（默认关闭，每次确认） | exec | 是，用户当场允许 |
| `vault_list` | 本地库元数据 | read | 否 |
| `vault_add` | 存进本地库；**密码由弹窗输入** | write | 否 |
| `vault_import` | 把 Bitwarden 登录项抄进本地库（先弹窗确认） | write | 否 |
| `vault_get` | 读本地库；弹窗授权，5 分钟内同一请求方有效 | exec | 是，用户当场允许 |

字段选择：`password`（默认）· `totp`（种子）· `code`（动态验证码）· `notes` · `field:<自定义字段名>`。

## 命令

```
/vault init                        创建本地库（弹窗设主密码，确认一次）
/vault unlock | lock               解锁 / 锁定（只影响本会话）
/vault status                      状态与授权剩余时间
/vault list                        本地条目元数据
/vault add [名称]                  新增条目（用户名、密码在弹窗里输入）
/vault remove <名称>               删除（带空格的名称加引号："GitHub (2)"）
/vault grant <名称> [分钟]         手动授权（默认 5 分钟，上限 60）
/vault revoke <名称|all>           撤销授权
/vault audit [n]                   最近 n 条审计（默认 30）
/vault import <bitwarden.json>     从 Bitwarden 未加密 JSON 导出导入
/vault import-bw [搜索词]          直接从 bw CLI 导入（先弹窗确认）
/bw status|unlock|lock|clear       在线 Bitwarden 会话
```

## 会话与隔离

omp 会为**每个会话和每个子代理**重新绑定插件工厂，所以每个绑定有自己的解锁状态和授权：

- 父会话 `vault_get` 得到的授权，子代理**不能**继承；子代理要么自己解锁，要么由你当场点允许。确认窗口会写明「请求方: 子代理 0-Explore」。
- `/new`、`/fork`、退出会清掉**这个绑定**的解锁和授权；`/resume` 保留（同一终端、同一个你）。会话里最后一个解锁的绑定离开时，内存里的密钥才被丢弃。
- Bitwarden 同理：换会话不会把别人的解锁带走。
- 库文件本身是共享的；同一个进程内只有一个内存副本，所以不会丢更新。**两个 omp 进程**同时写同一个库文件时，后写的会覆盖先写的（进程间没有锁）。

## 弹窗

有桌面（`DISPLAY` 或 `WAYLAND_DISPLAY`）时，下面的操作打开 zenity 窗口：

- 主密码：`/vault init`（两次）、解锁、Bitwarden 解锁
- `/vault add`、`vault_add`：用户名，然后密码；工具参数里**没有密码字段**
- `vault_get`、`vault_import`、`vault_remove`：确认窗口（焦点默认在「拒绝」）

关掉窗口就是取消，**不会**再弹一个终端输入框。zenity 不存在、拒绝参数、打不开显示时，才退回 omp/pi 的输入框。omp 会掩码输入；上游 pi 忽略掩码提示。

## Bitwarden

需要 `bw`（先 `bw login`）。第一次用到时弹窗要主密码，之后每次调用只在确认窗口里点允许。

- 要跑一条命令、又不想让密码进对话：`bw_run`（omp 和 pi 都可用）。值在子进程环境里，命令结束就没了；stdout/stderr 里出现原值、base64/base64url/URL/hex 形式（包括 `base64` 的 76 列换行和 `xxd` 的空格 hex）都会被替换成 `[BW_SCRUBBED:VAR]`。输出最多保留 8 MiB，超出部分丢弃并标注。
- pi 上还可以 `bw_inject` 注入 bash 环境，后续多条命令都能用。
- `bw_clipboard` 复制的值也会登记到擦洗列表：之后用 `pbpaste` / `xclip -o` / `wl-paste` 读回剪贴板，结果同样会被擦洗。
- 确认窗口里显示的是**实际命中的条目**（名称+用户名），不是模型给的引用。
- `/bw lock` 只丢弃当前绑定的会话密钥；同一进程里还有别的绑定持有时不会执行全局 `bw lock`，最后一个绑定释放时才真正作废 CLI 会话。

## 导入

- `/vault import-bw [搜索词]`：从 `bw` 现场读，先列出匹配项，确认后只导入带密码的登录项。
- `/vault import <文件>`：Bitwarden 未加密 JSON 导出；路径支持 `~`；加密导出会明确报错，不会「导入 0 条」。
- 每个条目都会记住它在 Bitwarden 里的 id：以后重导入时即使 `(2)` 编号漂移，也更新原来那一行，不会写错条目。

## 安全

- 主密码只经过弹窗或主机输入框；Bitwarden 主密码经环境变量交给 `bw unlock`，不进 argv。`BW_SESSION` 只在内存。插件启动的子进程（`bw`、`bw_run` 的 bash、剪贴板工具）都会剔除宿主环境里的 `BW_*`，避免用户 shell 里导出的会话密钥漏进命令环境。
- 本地库空闲 10 分钟自动锁定；解锁、读取、保存、导入、删除都算活动。`vault_get` 授权默认 5 分钟。
- 审计：`~/.omp/vault/audit.log`（本地库）和 `~/.bw/pi-extension/audit.log`（Bitwarden），记录会话/子代理标签、条目名、允许/拒绝，从不记录值；写失败不影响主操作。两个日志都在 1 MiB 时轮转成 `.1`。
- `bw_reveal` 默认关闭；要明文通道得在配置里显式打开。
- 擦洗只在值长度 ≥ 6 时生效（更短的会误伤正常输出）；网络外传、单向哈希防不住——`bw_run` / `bw_inject` 的价值是值不进对话，不是防住被注入的 agent。
- 原子写：临时文件（按进程和写入唯一命名）+ `fsync` + `rename` + 目录 `fsync`；KDF 参数写进文件头，以后调参不会毁老库。
- 擦洗列表保留最近使用的 512 个值；超过上限后，最久未用的值会失去保护（正常会话远达不到）。
- Bitwarden 确认窗口只使用列表里的元数据；条目的字段在用户点允许之后才按 id 读取。

## 配置 `~/.bw/pi-extension/config.json`

```jsonc
{
  "autoLockMinutes": 0,        // 空闲自动锁；0 = 一次解锁用到会话结束
  "keepOnResume": true,        // /resume 保留解锁状态（/new、/fork 一律锁）
  "clipboardClearSeconds": 30, // 0 = 不自动清（锁定/退出仍清）
  "allowReveal": false,        // 默认关闭明文通道
  "maxInjectedEnv": 12
}
```

类型或范围错误按 fail-closed 处理并往 stderr 打警告：`allowReveal`、`keepOnResume` 的非法值按 `false`；`autoLockMinutes` 非法按 15 分钟。

## 安装

需要 `bw`（先 `bw login`）；弹窗需要 zenity。

```bash
# omp（私有仓库用 SSH）
omp plugin install git+ssh://git@github.com/xiaolikt/omp-vault.git

# pi
pi install git:git@github.com:xiaolikt/omp-vault.git
```

本地开发（omp 是链接，改完即生效）：

```bash
omp plugin install /path/to/omp-vault
pi install /path/to/omp-vault
```

已在用 pi-bitwarden 的，先卸掉：

```bash
omp plugin uninstall pi-bitwarden
pi remove git:github.com/xiaolikt/pi-bitwarden
```

## 测试

```bash
npm test            # 66 个确定性用例：模拟 bw/zenity，驱动真实工具与命令
npm run typecheck
bash test/smoke.sh omp   # 模型驱动，真 omp 会话里跑一遍 bw_run
bash test/smoke.sh pi    # 同上，pi
```

`npm test` 里 `tests/vault-flow.test.mjs`、`tests/vault-idle.test.mjs` 和 `tests/bitwarden-tools.test.mjs` 覆盖：omp 的 `session_start` 不锁、`session_switch` 的 new/fork 锁、子代理不继承授权、解锁/确认窗口中途锁定被丢弃、弹窗期间自动锁定后保存/删除会重新解锁、带空格名称、空用户名保留、base64 短密码与换行编码擦洗、剪贴板值擦洗与复制/锁定竞态、`BW_SESSION` 不进子进程、只擦洗 bash 自己的临时输出文件、拒绝确认前不读取条目、审计会话标签、8 MiB 上限、进程组超时清理。

## License

MIT
