# ai-vault

一台电脑一个加密密码库。`ai-vault` 是一个 Rust 写的 CLI，库文件、加解密、桌面弹窗全在它里面；pi / omp 的插件只是它的客户端，不再各存一份。

```
~/.ai-vault/store.json      ChaCha20-Poly1305 + scrypt，0600
~/.ai-vault/audit.log       谁在什么时候读了什么，从不记值
~/.ai-vault/store.lock      多进程读改写时的文件锁
$XDG_RUNTIME_DIR/ai-vault/sessions/<token>.json   解锁令牌（0600，tmpfs）
```

因为位置是固定的、由 CLI 独占的，所以同一台机器上 pi、omp、脚本、别的 agent 拿到的都是同一批已导入的密码，不会再出现「这个 agent 导过、那个没导过」。

## 为什么是 CLI + 插件

- **加密只有一份实现**（Rust），插件里没有密钥、没有 crypto 代码，也没有第二份库。
- **会话不在 agent 进程里**：`ai-vault unlock` 派生 key 后写一个短命令牌文件，插件只持有令牌 id。agent 崩了、被 reload、换会话，key 都跟着令牌一起过期。
- **弹窗只有一份逻辑**：有桌面时 CLI 自己开 zenity；没有桌面时返回退出码 `3`，插件才用自己的输入框，绝不出现两个窗口抢输入。
- **换宿主很容易**：任何语言写的新 agent 只要会跑 `ai-vault get <名字> --json` 就能用同一个库。

## 安装

### npm（CLI）

```bash
npm i -g @xiaolikt/ai-vault     # 主包 + 本平台的二进制包
ai-vault --version
```

npm 上的裸名 `ai-vault` 已被别人占用（3.5.1），所以用 scope。主包 `@xiaolikt/ai-vault` 里的 `bin/ai-vault.cjs` 只是个转发器：找到 `@xiaolikt/ai-vault-<os>-<arch>` 里的真二进制，把 argv、stdio 和**退出码**（3/4/5 是宿主契约，不能改）原样交出去。

发布（需要 `npm login`）：

```bash
./scripts/stage-npm.sh                  # 编译并staging到 npm/linux-x64
npm publish npm/linux-x64 --access public
npm publish --access public
```

邮箱 OTP 2FA 的账号不能直接用 `--otp` 发布（npm 会回 `E403 ... granular access token with bypass 2fa enabled is required`）。做法：网页 Settings → Access Tokens → **Granular Access Token**，勾上 *Bypass 2FA*、权限 *Read and write (publish and stage)*，把令牌写进 `~/.npmrc`：

```bash
printf '//registry.npmjs.org/:_authToken=%s\n' "<token>" > ~/.npmrc && chmod 600 ~/.npmrc
```

这类令牌 npm 会在 2027 年 1 月起逐步作废，届时改用 trusted publishing 或 TOTP 2FA。

别的平台要有自己的二进制包：`./scripts/stage-npm.sh darwin-arm64 --from <交叉编译产物>`，发布后把对应名字加进 `optionalDependencies`。没有匹配的平台包时，shim 会明确报错并提示 `cargo install --path crates/ai-vault`。

### 从源码 / git

```bash
# 1. 编译 CLI 并放进 PATH（~/.local/bin/ai-vault）
./install.sh

# 2. 插件：pi
pi install git:github.com/xiaolikt/ai-vault     # 或 npm:@xiaolikt/ai-vault
#    omp
omp plugin install git+ssh://git@github.com/xiaolikt/ai-vault.git

# 3. 建库（弹窗设主密码，两次）
/vault init
```

要求：Rust（`cargo`）编译期用；运行时需要 `zenity` 才弹窗，没有就退回宿主的输入框。

**不要同时安装旧的 `omp-vault` 和 `ai-vault`**：两边都注册 `vault_*` 工具，会重复。

### 从 omp-vault 迁移

第一次运行 `ai-vault` 时，如果 `~/.ai-vault/store.json` 不存在而 `~/.omp/vault/store.json` 存在，CLI 会**复制**（不删除）库和审计日志过去，主密码不变——文件格式没变，只是位置变了。旧文件留着，想回退随时可以。

## CLI

```text
ai-vault [--dir DIR] [--json] <命令>
```

| 命令 | 作用 |
|---|---|
| `path` | 打印库、会话目录的位置 |
| `doctor` | 路径、是否初始化、有没有桌面和 zenity、版本 |
| `init [--password-stdin]` | 建库（弹窗两次设密码），成功后直接给一个令牌 |
| `unlock [--password-stdin] [--requester ID] [--idle-min N]` | 解锁，stdout 一个令牌 |
| `status --token T` | 条目数、过期时间、还活着的读授权 |
| `lock --token T \| --all` | 丢掉令牌（`--all` 清空本机所有会话） |
| `list --token T` | 条目元数据（名称/用户名/URI），没有密码 |
| `get <名字> [--reason R] [--answer-stdin]` | 读一条；没有授权时先弹确认窗 |
| `add --name N [--username U] [--uri U] [--notes N] [--password-stdin] [--yes]` | 新增/更新；密码由弹窗输入 |
| `save --yes [--file F]` | 从 stdin 读一组条目 JSON，批量写入（导入用） |
| `remove <名字> [--yes]` | 删除（带空格的名称加引号） |
| `grant <名字> [--minutes N]` / `revoke <名字\|--all>` | 手动给/撤读授权（默认 5 分钟，上限 60） |
| `audit [n]` | 最近 n 条审计（默认 30） |
| `import <bitwarden.json> [--yes]` | 从 Bitwarden 未加密导出导入 |

令牌也可以走环境变量：`AI_VAULT_TOKEN`。库目录：`--dir` / `AI_VAULT_DIR` / `~/.ai-vault`。

### 退出码（宿主集成契约）

| 码 | 含义 | 宿主该做什么 |
|---|---|---|
| 0 | 成功 | stdout 是结果（`--json` 时是 JSON） |
| 1 | 出错 | 把 stderr 第一行给用户看 |
| 2 | 参数/用法错误 | 同上 |
| 3 | 需要界面 | stderr 有 `needs-ui: password\|text\|confirm`；宿主自己弹框，把值经 stdin 送回并加对应开关 |
| 4 | 用户拒绝/取消 | **不要重试**，问用户 |
| 5 | 未解锁 / 密码错 | 重新 `unlock`，或提示主密码错误 |

所以「没有桌面的机器」也能用：`unlock --password-stdin`、`get --answer-stdin`、`add --password-stdin --yes`、`save --yes` 就是无界面路径。

## 插件里的工具

| 工具 | 作用 | 等级 | 模型看到密码？ |
|---|---|---|---|
| `vault_list` | 本地库元数据 | read | 否 |
| `vault_get` | 读一条；弹窗授权，5 分钟内同一请求方可复用 | exec | 是，用户当场允许 |
| `vault_add` | 存一条；密码在弹窗里输入 | write | 否 |
| `vault_import` | 把 Bitwarden 登录项抄进本地库（先确认） | write | 否 |
| `bw_list` | 查在线 Bitwarden 元数据 | read | 否 |
| `bw_run` | 用 `$VAULT_SECRET` 跑一条命令，输出擦洗 | exec | 否 |
| `bw_inject` | 注入 bash 环境（**仅 pi**） | exec | 否 |
| `bw_clipboard` | 复制到剪贴板，到时清除 | write | 否 |
| `bw_reveal` | 明文返回（默认关闭，每次确认） | exec | 是，用户当场允许 |

字段选择：`password`（默认）· `totp`（种子）· `code`（动态验证码）· `notes` · `field:<自定义字段名>`。

## 插件里的命令

```
/vault init                        创建本地库（弹窗设主密码）
/vault unlock | lock               解锁 / 锁定本会话
/vault status                      状态、过期时间、授权剩余
/vault list                        条目元数据
/vault add [名称]                  新增（用户名、密码在弹窗里输入）
/vault remove <名称>               删除（"GitHub (2)" 这种要加引号）
/vault grant <名称> [分钟]         手动授权读取
/vault revoke <名称|all>           撤销授权
/vault audit [n]                   最近 n 条审计
/vault import <bitwarden.json>     从未加密导出导入
/vault import-bw [搜索词]          直接从 bw 导入登录项
/bw status|unlock|lock|clear       在线 Bitwarden 会话
```

## 会话与隔离

- 每个绑定（一个会话，或一个子代理）在第一次用到库时各自 `ai-vault unlock`，拿到**自己的令牌**。父会话的解锁和授权子代理继承不到；确认窗口里会写「请求方: 子代理 0-Explore」。
- 令牌空闲 10 分钟自动失效（可以被 `--idle-min` 改，1–600 分钟）。`/new`、`/fork`、退出会让插件把自己的令牌删掉；`/resume` 保留。
- 读授权存在令牌里，所以天然按请求方隔离；`/vault grant`、`/vault revoke` 改的就是它。
- 库文件本身共享：读改写有 `flock`，两个 agent 同时写不会丢更新（旧版是后写覆盖先写）。

## Bitwarden

需要 `bw`（先 `bw login`）。第一次用到时弹窗要主密码，之后每次调用只在确认窗口里点允许。

- 要跑一条命令、又不想让密码进对话：`bw_run`。值在子进程环境里，命令结束就没了；stdout/stderr 里出现原值、base64/base64url/URL/hex 形式（包括 `base64` 的 76 列换行和 `xxd` 的空格 hex）都会被替换成 `[BW_SCRUBBED:VAR]`。输出最多保留 8 MiB，超出部分丢弃并标注。
- pi 上还可以 `bw_inject` 注入 bash 环境，后续多条命令都能用。
- `bw_clipboard` 复制的值也会登记到擦洗列表：之后用 `pbpaste` / `xclip -o` / `wl-paste` 读回剪贴板，结果同样会被擦洗。
- 确认窗口里显示的是**实际命中的条目**（名称+用户名），不是模型给的引用。
- `/bw lock` 只丢弃当前绑定的会话密钥；同一进程里还有别的绑定持有时不会执行全局 `bw lock`，最后一个绑定释放时才真正作废 CLI 会话。
- Bitwarden 会话密钥只在 agent 进程内存里，不落盘、不进 bash 环境。

## 安全

- 主密码只经过弹窗或宿主输入框；`unlock` 派生出的 key 只写进令牌文件（0600，优先 tmpfs，登出即消失）。它和「agent 进程内存里有 key」是同一级别的暴露面，好处是换会话、reload、崩溃都会自然清掉。
- 会话令牌只是 id，不是 key：泄露令牌不等于泄露密码，但仍能读库，所以 `lock` 要真删文件。
- 插件启动的子进程（`bw`、`bw_run` 的 bash、剪贴板工具）都会剔除宿主环境里的 `BW_*`，避免用户 shell 里导出的会话密钥漏进命令环境。
- 审计：`~/.ai-vault/audit.log` 记录会话/子代理标签、条目名、允许/拒绝，从不记录值；写失败不影响主操作；1 MiB 轮转成 `.1`。
- `bw_reveal` 默认关闭；要明文通道得在配置里显式打开。
- 擦洗只在值长度 ≥ 6 时生效（更短的会误伤正常输出）；网络外传、单向哈希防不住——`bw_run` / `bw_inject` 的价值是值不进对话，不是防住被注入的 agent。
- 原子写：临时文件（0600、唯一命名）+ `fsync` + `rename` + 目录 `fsync`；KDF 参数写在文件头，以后调参不会毁老库。
- 库格式和旧版 `omp-vault` 完全一致（`v:1`、`salt`、`kdf{N,r,p}`、`ct = base64(iv‖ct‖tag)`），主密码不变，Node 和 Rust 两边都验证过互读。

## 开发

```bash
cargo test                  # Rust 单元测试（存储、加密格式、导入映射）
npm test                    # 先把 CLI 编译出来，再跑插件测试（真实 CLI + mock zenity）
npm run test:npm            # 打 tarball、临时 prefix 全局安装、跑 shim 与退出码
npm run test:cli            # 只测二进制：无桌面时的退出码契约、加密落盘、审计
npm run typecheck
bash test/smoke.sh pi       # 真宿主冒烟（需要模型凭据）
```

目录：

```
crates/ai-vault/src/   main.rs cli.rs crypto.rs store.rs session.rs dialog.rs import.rs audit.rs paths.rs
bin/ai-vault.cjs       npm 入口：找平台包、转发 argv/stdio/退出码
scripts/stage-npm.sh   把 release 二进制 stage 成 npm 平台包
src/                   index.ts（工具/命令） cli.ts（CLI 客户端） bitwarden.ts prompt.ts host.ts import-map.ts scrub.ts
test/cli.sh            二进制级集成测试
test/npm.sh            npm 打包/安装/转发测试
```

## License

MIT
