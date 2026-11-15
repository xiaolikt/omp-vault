# omp-vault

[omp](https://github.com/hljhljhlj)/pi 扩展：给 AI agent 用的**受限、需用户授权**的密码库。

针对的威胁模型：agent 会读网页 / 邮件 / 命令输出这类不可信内容，可能被注入指令诱导去取密码。omp-vault 保证最坏情况下它只能**请求**一个密码——每次读取都要经过你在 TUI 里按下的确认框，授权 5 分钟自动过期，全部动作进审计日志。

## 特性

- **加密存储**：ChaCha20-Poly1305 + scrypt，`~/.omp/vault/store.json`，零原生依赖（纯 Node crypto），原子写入，`0600` 权限
- **人在环上**：`vault_get` 首次读取某条目时弹原生确认框；拒绝后 agent 收到明确指令不得重试
- **限时授权**：每条授权默认 5 分钟（手动 `/vault grant` 上限 60 分钟），过期自动失效
- **自动锁定**：10 分钟无操作自动锁库并清空全部授权
- **审计日志**：`~/.omp/vault/audit.log`，append-only JSONL（unlock / grant / read_allow / read_deny / auto_lock …）
- **元数据与密文分离**：`vault_list` 只暴露名称/用户名/URI，永远不含密码

## 安装

```bash
omp plugin install hljhljhlj/omp-vault
```

本地开发：

```bash
git clone https://github.com/hljhljhlj/omp-vault && cd omp-vault
npm install
omp plugin link .
```

## 使用

```
/vault init                  创建加密库（设置主密码）
/vault unlock | lock         解锁 / 锁定（清空所有授权）
/vault status                当前状态与授权剩余时间
/vault add [name]            新增条目
/vault remove <name>         删除条目
/vault grant <name> [min]    手动授权（默认 5 分钟，上限 60）
/vault revoke <name|all>     撤销授权
/vault audit [n]             最近 n 条审计记录
/vault import <bw.json>      从 Bitwarden JSON 导出导入
```

Agent 侧工具：

- `vault_list()` — 列出条目元数据（无密码）
- `vault_get(name, reason)` — 读密文；需要未过期的授权，没有则弹框问你

## 从 Bitwarden 迁移

```bash
bw export --format json --output /tmp/bw.json     # 未加密导出（用完即删）
# 在 omp 里:
/vault unlock
/vault import /tmp/bw.json
rm /tmp/bw.json
```

## 环境变量

- `OMP_VAULT_DIR` — 存储目录（默认 `~/.omp/vault`）

## License

MIT
