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

### npm

三个包：

| 包 | 内容 | 谁装 |
|---|---|---|
| `@xiaolikt/ai-vault` | `bin/ai-vault.cjs` 转发器 + Rust 源码 | 想只要 CLI 的人 |
| `@xiaolikt/ai-vault-linux-x64` | 预编译二进制，`os/cpu` 限定 | 被上一条自动拉下来 |
| **`pi-ai-vault`** | pi/omp 插件（`vault_*` + `bw_*` 工具） | pi 或 omp，依赖上一条 |

```bash
npm i -g @xiaolikt/ai-vault      # 只要 CLI
pi install npm:pi-ai-vault       # 插件（自动带上 CLI）
omp plugin install npm:pi-ai-vault
```

插件本身就是 pi 的扩展清单，omp 是 pi 的兼容分支，**同一个包在两个宿主里都能用**：omp 上会自动注册 `bw_run`、pi 上还会多一个 `bw_inject`，差别只在 `src/host.ts` 的运行时探测里。

npm 上的裸名 `ai-vault` 已被别人占用（3.5.1），所以 CLI 用 scope。主包里的 `bin/ai-vault.cjs` 只是个转发器：找到 `@xiaolikt/ai-vault-<os>-<arch>` 里的真二进制，把 argv、stdio 和**退出码**（3/4/5 是宿主契约，不能改）原样交出去。

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

# 2. 插件（仓库根也有 pi 清单，指向 packages/pi-ai-vault，所以 git 装法依旧可用）
pi install git:github.com/xiaolikt/ai-vault
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
| `unlock [--password-stdin] [--requester ID]` | 按当前模式解锁，stdout 一个令牌 |
| `mode [get]` / `mode set never\|time\|session [--hours N]` | 查看/切换解锁模式（切换要主密码） |
| `settings [键] [值]` | 全部设置：`vault.unlock` `vault.hours` `bitwarden.unlock` `bitwarden.hours` `bitwarden.import` |
| `bw-session get\|put\|clear` | Bitwarden 会话密钥的落盘副本（`bitwarden.unlock != session` 时用，加密封存） |
| `rekey` | 把旧库的 scrypt 参数升到当前默认（要主密码） |
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

所以「没有桌面的机器」也能用：`unlock --password-stdin`、`add --password-stdin --yes`、`save --yes` 就是无界面路径。

**转发确认是宿主特权**，需要三样东西同时成立：

```bash
AI_VAULT_HOST=1 \
AI_VAULT_HOST_SECRET=<unlock 时返回的 hostSecret> \
ai-vault get <条目> --token <T> --answer-stdin --approval <hex> <<< 'y'
# approval = HMAC-SHA256(hostSecret, "allow:<T>:<条目小写>:y")
```

`unlock`/`init` 只在 `AI_VAULT_HOST=1` 时返回 `hostSecret`；它只存在于宿主进程内存里，CLI 用它给会话文件签名、用它核对转发。少了任何一样，`--answer-stdin` 都是退出码 2。这就是为什么模型的 `bash` 即使拿到令牌也签不出「允许」。

## 插件里的工具

| 工具 | 作用 | 等级 | 模型看到密码？ |
|---|---|---|---|
| `vault_list` | 本地库元数据 | read | 否 |
| `vault_get` | 读一条：**先本地库，再 Bitwarden**；命中后按 `bitwarden.import` 处理（问 / 直接导入 / 只读一次） | exec | 是，用户当场允许 |
| `vault_add` | 存一条；密码在弹窗里输入 | write | 否 |
| `vault_import` | 把 Bitwarden 登录项抄进本地库（先确认） | write | 否 |
| `bw_list` | 查在线 Bitwarden 元数据 | read | 否 |
| `bw_run` | 用 `$VAULT_SECRET` 跑一条命令，输出擦洗 | exec | 否 |
| `bw_inject` | 注入 bash 环境（**仅 pi**） | exec | 否 |
| `bw_clipboard` | 复制到剪贴板，到时清除 | write | 否 |
| `bw_reveal` | 明文返回（默认关闭，每次确认） | exec | 是，用户当场允许 |
| `ente_list` | Ente Auth 条目元数据（名称/签发方/账号/类型） | read | 否 |
| `ente_code` | 读一条当前 TOTP/Steam 验证码，每次弹窗确认 | write | 是，用户当场允许 |

字段选择：`password`（默认）· `totp`（种子）· `code`（动态验证码）· `notes` · `field:<自定义字段名>`。

### 查询顺序：本地优先，Bitwarden 兜底

`vault_get` 先问 `ai-vault`（这台机器共用的库），只有本地没有才去搜 Bitwarden：

```
vault_get "github"
  └─ ai-vault 有 → 直接返回（按解锁模式决定要不要窗口）
  └─ ai-vault 没有 → Bitwarden 搜索
       ├─ 没命中 → 报「本地没有、Bitwarden 也没有」
       └─ 命中 → ① 给你看这一条（名称/用户名），问读不读
                 ② 读了再问：导入 ai-vault（以后免 Bitwarden）还是只用这一次
```

这样两者就隔离了：**只有你同意导入的密码才进 ai-vault**，ai-vault 里的就是「agent 可以自由使用」的那批；其余仍留在 Bitwarden 里，每次都要你点。

### 解锁模式

`ai-vault` 什么时候要主密码，由这台机器的模式决定（`~/.ai-vault/config.json`）：

| 模式 | 行为 | 适合 |
|---|---|---|
| `never` | 永远不问。密钥写在 `~/.ai-vault/agent.session.json`（0600），**读取也不再弹确认窗** | 把一批「随便用」的密码交给 agent |
| `time` | 解锁后 N 小时（默认 8，`--hours` 可改）再问一次 | 有边界的长任务 |
| `session` | 每个会话问一次，会话结束就失效（默认） | 日常 |

```bash
ai-vault mode                      # 看当前模式
ai-vault mode set never            # 切换要主密码
ai-vault mode set time --hours 4
ai-vault mode set session
```
插件里同样有：`/vault mode`、`/vault mode time 4`。**切换模式一定要输主密码**——尤其是切到 `never`，因为它把密钥落到磁盘上。

`never` 不是「安全一点」而是「明确放弃这层保护」：任何能读你 home 目录的进程都能读出库里的全部密码。它存在的意义是把「可以让 AI 随便用」的密码和 Bitwarden 里那些「每次都要问」的分开。

### Bitwarden 也是同样三种模式（独立设置）

| 设置 | 值 | 行为 |
|---|---|---|
| `bitwarden.unlock` | `never` | `bw` 会话密钥落盘（`~/.ai-vault/bitwarden.session.json`，0600），**不再问 Bitwarden 主密码** |
| | `time` | 同上，但 `bitwarden.hours` 小时后失效，重新要密码 |
| | `session` | 密钥只在 agent 进程内存里，每个会话问一次（默认） |
| `bitwarden.import` | `ask` | `vault_get` 本地没命中 → 显示 Bitwarden 命中项 → 读一次 → 问是否导入（默认） |
| | `always` | 命中就直接导入并返回，**一个窗口都不开**（完全自动，慎用） |
| | `never` | 只读一次，问一次，永不写入本地库 |

```bash
ai-vault settings                                   # 全部设置
ai-vault settings bitwarden.unlock never
ai-vault settings bitwarden.import always
ai-vault settings bitwarden.hours 24
```
插件里：`/vault settings`、`/vault settings bitwarden.import always`。

> `bitwarden.import = always` 配合 `bitwarden.unlock = never`，等于「Bitwarden 里任何一条被问到就自动进库、以后免密随便读」。这是最快也是最不设防的组合，只在完全信任 agent 时用。

`bw-session put/get/clear` 就是那个落盘密钥的读写口：插件在主密码解锁成功后写入，切回 `session` 模式时自动清掉，`/bw lock` 也会清掉。

## 插件里的命令

```
/vault init                        创建本地库（弹窗设主密码）
/vault unlock | lock               解锁 / 锁定本会话
/vault mode [never|time|session]   查看/切换解锁模式（切换要主密码）
/vault settings [键 值]            查看/修改设置（bitwarden.* 也在这里）
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
- 令牌寿命由解锁模式决定（见上）：`session` 最长 24 小时、`time` 到 N 小时、`never` 不过期。`/new`、`/fork`、退出会让插件把自己的令牌删掉；`/resume` 保留。失效、被改、属于旧库的令牌文件在**每次** CLI 调用时都会被清掉。
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

## Ente（Auth 验证码）

`ente` 是 Ente 官方的终端客户端（0.4+）。它**自己登录一次**：

```bash
ente account login --app auth        # 邮箱 + 密码（+ 2FA 验证码）
ente auth code list                  # 之后每次都不再问密码
```

会话存在 `$XDG_DATA_HOME/ente-cli`（Linux 默认 `~/.local/share/ente-cli`），数据库密钥默认放系统钥匙串；无桌面/无人值守时用

```bash
ente vault key generate              # 打印一个 key
export ENTE_CLI_VAULT_KEY=<那个 key> # 之后连钥匙串都不用
```

所以在 `session` 这种日常形态下，**每次查看不会再要你的密码**，最多要一次系统钥匙串解锁。

pi-ai-vault 只是这套 CLI 的客户端，本身不保存 Ente 的任何密钥：

| 工具 | 作用 |
|---|---|
| `ente_list` | 列出条目（name / issuer / accountName / type），**不含验证码** |
| `ente_code <名字>` | 弹窗显示实际命中的条目，允许后返回当前验证码和过期时间 |

安全上和 `bw_*` 一套规则：列表只给元数据；读码每次确认；拒绝后不重试；允许/拒绝都写审计（`~/.bw/pi-extension/audit.log`，`ente.code` 事件，不含码本身）；条目名/签发方进窗口前会被压成一行，防伪造。

插件启动的 bash 会剔除 `ENTE_CLI_VAULT_KEY` / `ENTE_CLI_PASSWORD`，避免你 shell 里导出的免密 key 漏进模型自己的命令环境。**注意**：`ente` 二进制本身也在 PATH 上，模型直接跑 `ente auth code view` 仍能绕过这个扩展的确认窗——要收紧要靠 `ENTE_CLI_VAULT_KEY` + 把模型的 `ENTE_CLI_HOME` 指到别处，或者干脆不让 agent 有 shell。

## 安全

### 威胁模型：谁能做什么

所有东西都跑在**你的用户**下，所以边界不是「用户 vs 别人」，而是**你（人）vs 跑在你账号下的 agent**。设计目标是：agent 可以*用*密码，但不能*绕过你*去拿。

| 角色 | 能 | 不能 |
|---|---|---|
| **你**（终端里手敲 `ai-vault`） | 一切 | — |
| **宿主**（pi/omp 扩展进程，持 `AI_VAULT_HOST=1` + 内存里的 host secret） | 替你转发确认（要签名）、改设置 | 不知道主密码（除非你输了） |
| **agent**（模型的 `bash`，同一用户，能读 `~/.ai-vault`） | 读到会话令牌文件（但插件开的会话没有 secret 用不了，一用就作废） | **伪造一次读取确认、给令牌加授权、改确认窗里的请求方、`list` 插件会话、拿到 Bitwarden 主密码** |
| **别的用户 / 离线拿到文件的人** | 读到密文 | 解密（scrypt + ChaCha20-Poly1305） |

### 怎么做到的

- **确认窗不能被绕过。** `vault_get` 的确认要么是 CLI 自己开的 zenity 窗口，要么是宿主转发的答案。转发的答案必须带 `--approval`：用**宿主进程内存里的 secret** 对 `allow:<token>:<条目>:<y|n>` 做 HMAC。模型的 bash 能找到令牌文件，但没有 secret，签不出来；拿别的条目的签名重放、把 `n` 改成 `y`，都会对不上。
- **令牌文件不能改。** 每个会话文件带 HMAC（宿主会话用 host secret，手敲 CLI 的会话用库目录的 wrap key）。改了 `grants`、改了 `requester`、哪怕只改一个字节，CLI 都报 `session file was modified outside ai-vault` 并删掉文件。
- **`grant` 不再是免费的。** 给一条条目「N 分钟免确认」是一次长期授权，现在要主密码（和切模式同一级别）。
- **`never` 模式是明确放弃上面这些。** 密钥写在 `~/.ai-vault/agent.session.json`，读取不再有任何窗口。它的意义是把「可以让 AI 随便用」和「每次都要问我」分开；开了它，就等于信任 agent 的输出渠道，不只是 agent。
- **Bitwarden 会话密钥加密封存。** `bitwarden.unlock = never|time` 时，`bw` 的会话密钥用 ChaCha20-Poly1305 封在 `~/.ai-vault/bitwarden.session.json` 下，密钥是 `~/.ai-vault/.wrap`（0600）。单独拷走那个文件什么都打不开。`bw unlock --raw` 的会话密钥等价于**整个** Bitwarden 保险库的读权限，所以这个文件的敏感度 ≥ 库本身。
- **确认窗里的字不是模型写的。** 条目名、原因、用户名、URI 进窗口前都压成一行、去掉控制字符、截到 80–120 字符，模型没法在名字里塞换行伪造第二条「已授权」。
- **KDF。** 新库 scrypt `N=2^17`（128 MiB）；文件头记着参数，旧库（`N=2^15`）照常打开，`ai-vault rekey` 升级。低于 `2^15` 的参数一律拒收（防降级）。
- **主密码**只经过弹窗或宿主输入框；`unlock` 派生的 key 只写进令牌文件（0600，优先 tmpfs）。`BW_*` 在所有子进程环境里剔除。
- **审计**：`~/.ai-vault/audit.log` 记录会话、条目、允许/拒绝/原因、以及 `unsigned-relay`、`bad-approval`、`modified-outside` 这类尝试，从不记值；1 MiB 轮转。
- **原子写 + flock**：临时文件（0600）→ fsync → rename → 目录 fsync；多进程读改写有文件锁。失效/被改/旧库的令牌文件每次调用都会被清掉。
- `bw_reveal` 默认关闭；擦洗只在值长度 ≥ 6 时生效，防不住网络外传和单向哈希——`bw_run` / `bw_inject` 的价值是值不进对话，不是防住被注入的 agent。
- `notes` 只在 `get`（授权之后）里出现，`list` 不输出它。

### 已知边界

- `session` 模式下，模型的 bash **能**读到令牌文件，但拿到也没用：插件开的会话用宿主内存里的 secret 签名，bash 没有 secret，第一次用就会被判「文件被改」而作废（连 `list` 都做不了，还会把那个文件删掉）。只有**你在终端手敲** `ai-vault unlock` 开出来的会话（用 wrap key 签名）才能被同用户进程 `list`——那种会话本来就没有窗口可以绕，这是「同一用户」的固有暴露面。真正收紧要靠不同的用户或容器。
- 一个 `AI_VAULT_HOST=1` 但没带 secret 的调用方，会被当成普通用户对待：拿不到 secret、签不了转发。
- `bitwarden.import = always` + `bitwarden.unlock = never` 等于「Bitwarden 里任何一条被问到就自动进免费库」。README 不建议，但它能开。
- zenity 窗口的标题栏属于窗口管理器；全屏伪造窗口不在防护范围内。

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
packages/pi-ai-vault/  npm 包 pi-ai-vault：src/ = index.ts（工具/命令） cli.ts（CLI 客户端）
                       bitwarden.ts prompt.ts host.ts import-map.ts scrub.ts
test/cli.sh            二进制级集成测试
test/npm.sh            npm 打包/安装/转发测试
```

## License

MIT
