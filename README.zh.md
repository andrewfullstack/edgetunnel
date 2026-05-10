# edgetunnel

[English version →](./README.md)

一个运行在 Cloudflare Workers / Pages 上的 VLESS 代理。

📦 **只想直接部署？** 从
[Releases 页面](https://github.com/andrewfullstack/edgetunnel/releases)
下载 `edgetunnel.zip`，并按照下方
[Cloudflare Pages（zip 上传）](#cloudflare-pages-zip-上传--推荐--已测试)
的步骤操作即可。

本项目是 [`cmliu/edgetunnel`](https://github.com/cmliu/edgetunnel) 的 TypeScript
重构版本。上游项目是一个 4619 行的 `_worker.js`，使用中文标识符且没有任何
测试；这个 fork 把它拆成了 37 个带类型的模块，配套 171 个单元测试和 9 个集
成测试，同时保留了运行时与 KV schema 的兼容性，便于现有部署无缝升级。

最终交付物仍是单个 `_worker.js`（压缩后约 80 KB）。

## 项目范围

- **VLESS** over WebSocket / XHTTP / gRPC。Cloudflare 边缘负责入站 TLS；
  本代码负责解析 VLESS 帧并转发流量。
- **管理面板**（`/admin`），基于 KV 的配置、日志查看、流量统计、运行时
  配置校验。
- **订阅生成器**（`/sub`），支持 Clash、Sing-box、Surge、Quantumult X、
  Loon、mihomo 等，服务端缓存 5 分钟以减少客户端刷新洪峰带来的 CPU 压力。
- **上游链路**：直连、ProxyIP、SOCKS5、HTTP CONNECT。
- **自动迁移**老版本中文键名的 KV 配置。

## 不在范围内的内容

完整说明见 [`docs/PLATFORM_LIMITS.md`](./docs/PLATFORM_LIMITS.md)。简述如下：

- Shadowsocks 和 Trojan 支持 — 已移除；VLESS 已能覆盖相同场景
- HTTPS 上游代理模式 — 已与手写 TLS 客户端一并移除
- 基于 UDP 的协议（Hysteria2、TUIC）— Workers 没有 UDP API
- REALITY — Workers 无法终止入站 TLS
- 多租户账号 — 在收到需求前暂不支持

如果你需要上述任何功能，请改在 VPS 上运行
[Xray-core](https://github.com/XTLS/Xray-core) 或
[sing-box](https://github.com/SagerNet/sing-box)。在那种环境下它们是更合适
的工具。

## 部署

你需要一个 Cloudflare 账号和一个域名（接入 Cloudflare DNS 即可，免费版也可以）。

### Cloudflare Pages（zip 上传） — 推荐 ✅ 已测试

最稳妥的路径 — Workers 控制台的"粘贴部署"有时会把项目错判为纯静态资源
项目，进而拒绝你添加环境变量。Pages 没有这个问题。

1. **获取 `edgetunnel.zip`。** 二选一：
   - 从 [Releases 页面](https://github.com/andrewfullstack/edgetunnel/releases)
     下载（推荐 — 每个 tag 都由 CI 构建、测试、签名），或者
   - 本地构建：`npm run build && zip edgetunnel.zip _worker.js`。

   两种方式得到的 zip 都只在根目录包含一个 `_worker.js`（约 80 KB）。
   **不要使用上游 `cmliu/edgetunnel` 的压缩包 — 它里面的 `_worker.js`
   是重构前那份原始的 4619 行文件，与本 fork 文档描述的不一致。**
2. **Pages 控制台 → 创建 → Pages 选项卡 → 上传资产** → 给项目命名 →
   上传 zip → **部署站点**。
3. **设置 → 环境变量 → 生产** → 添加 `ADMIN` = 你的管理员密码 →
   **保存**。
4. 返回 **部署** → **创建新部署** → 重新上传同一个 zip → **保存并部
   署**。（这一步是必需的，让环境变量在运行中的部署里生效。）
5. **设置 → 绑定 → KV 命名空间** → 添加绑定，变量名填 `KV` → 保存 →
   再重新部署一次。
6. **自定义域** → 绑定一个 CNAME 子域名（注意：不要用根域，要用类似
   `vless.your-domain.com` 的子域名）。
7. 访问 `https://<你的子域名>/admin`，使用 `ADMIN` 登录。

### Cloudflare Pages（GitHub 连接）

1. Fork 本仓库。
2. **Pages → 连接到 Git** → 选择你的 fork → 设置 `ADMIN` 环境变量。
3. 按上面的步骤添加 KV 绑定与自定义域名。

### Cloudflare Workers（通过 wrangler CLI 部署）

最稳妥的 Workers 部署方式；可以避开控制台的静态资产分类陷阱。

```bash
npm install
npx wrangler login
npx wrangler secret put ADMIN          # 粘贴你的管理员密码
npx wrangler kv namespace create KV    # 记下输出里的 id
# 在 wrangler.toml 中添加 KV 绑定：
#   [[kv_namespaces]]
#   binding = "KV"
#   id = "<上面 create 输出的 id>"
npm run deploy
```

接着在 Cloudflare 控制台的 **触发器 → 自定义域** 给 worker 绑定一个自定
义域名。

### Cloudflare Workers（控制台粘贴） — 见警告

> ⚠️ Cloudflare 新版控制台有时会把粘贴部署的 Worker 归类为"仅静态资
> 产"，然后拒绝让你添加环境变量（错误信息：*"Variables cannot be added
> to a Worker that only has static assets"*）。如果遇到这种情况，**删
> 掉这个 Worker，改用上面任一方式重新部署**。

1. **Workers & Pages → 创建 → Workers 选项卡 → Hello World 模板 →
   部署。**（不要用其他"创建"路径 — 它们可能把代码当作静态资产上传。）
2. 打开 Worker → **编辑代码** → 把整段内容替换为
   [`_worker.js`](./_worker.js) 的内容 → **保存并部署**。
3. **设置 → 变量**：添加 `ADMIN` = 你的管理员密码。
4. **设置 → 绑定**：添加名为 `KV` 的 KV 命名空间。
5. **触发器 → 自定义域**：绑定一个子域名。
6. 访问 `https://<你的域名>/admin` 登录。

### 验证部署

在绑定自定义域并等 DNS 生效之后：

1. **`/admin`** 能正常打开 — 说明 Worker 在跑，并且 `ADMIN` 环境变量
   已经接好。
2. **`/admin/validation.json`** 返回 `{"ok": true, "count": 0}` — 说明
   KV 绑定正确，没有 schema 问题。如果 `ok` 是 false，管理面板会同时
   显示一条黄色横幅，列出对应问题。
3. **订阅 URL** — 从管理面板复制，粘贴到客户端（Clash / Sing-box /
   Surge），确认节点已出现。
4. **真实连接** — 通过任一节点出网，访问 `https://ifconfig.me` 之类，
   确认 IP 是 Cloudflare 的地址（说明流量真的过了 worker）。
5. **`wrangler tail <project-name>`**（可选）— 实时打印部署后 worker
   的 `console.log`。对那些客户端看不到的问题排查很有用。

如果 `/admin` 显示黄色横幅（"⚠️ Config has N validation issues"），访
问 `/admin/validation.json` 可以看到 KV 配置中所有出问题的字段；校验器
会把不合法字段强制设回默认值并继续提供服务，所以即使你还没修，worker
依然能用。

## 配置

### 环境变量

| 名称 | 必填 | 示例 | 说明 |
|---|:---:|---|---|
| `ADMIN` | 是 | `mypassword` | 管理面板密码。用户 UUID 由它派生。 |
| `KEY` | 否 | `mykey` | 快速订阅路径：访问 `/<KEY>` 可快速拉取节点。 |
| `UUID` | 否 | `90cd4a77-...` | 强制使用固定 UUID。必须为 UUIDv4。 |
| `PROXYIP` | 否 | `proxyip.example.net:443` | 默认反代 IP。 |
| `URL` | 否 | `https://example.com` | 伪装首页 URL（也可填 `1101`）。 |
| `GO2SOCKS5` | 否 | `*.example.com,*.foo.cn` | 强制走 SOCKS5 的主机名（`*` 表示全局）。 |
| `DEBUG` | 否 | `1` | 开启 `console.log`。 |
| `OFF_LOG` | 否 | `1` | 关闭访问日志。 |
| `BEST_SUB` | 否 | `1` | 作为优选订阅生成器运行。 |

### 基于路径的运行时配置

worker 支持通过 URL 路径段切换上游代理：

```
/proxyip=proxyip.example.net
/socks5=user:password@127.0.0.1:1080
/socks5://user:password@127.0.0.1:1080      （全局 SOCKS5）
/http=user:password@127.0.0.1:8080
/http://user:password@127.0.0.1:8080         （全局 HTTP CONNECT）
```

上游里的 `/https=...` 与 `/https://...` 语法在本 fork 中**不再支持** —
原因见 [`docs/PLATFORM_LIMITS.md`](./docs/PLATFORM_LIMITS.md)。

### 轮换订阅 token / 节点 UUID

订阅 token 与节点 UUID 由 `md5x2(ADMIN + KEY)` 派生。要轮换它们：

- 修改 `ADMIN` 或 `KEY` → 两者一起轮换。
- 显式设置 `UUID` 来固定 UUID（必须是合法的 UUIDv4）。

## 客户端兼容性

| 平台 | 推荐客户端 |
|---|---|
| Windows | v2rayN、FlClash、mihomo-party、Clash Verge Rev |
| macOS | FlClash、mihomo-party、Clash Verge Rev、Surge |
| iOS | Surge、Shadowrocket、Stash |
| Android | ClashMetaForAndroid、FlClash、v2rayNG（建议使用 Meta 核心） |

## 本地开发

需要 Node.js 20+。

```bash
npm install
npm run lint              # tsc --noEmit
npm test                  # vitest run（约 1 秒，171 个测试）
npm run test:integration  # build + 基于 workerd 的端到端测试（约 5 秒）
npm run build             # esbuild → _worker.js
npm run analyze           # 按模块的打包体积细分
npm run deploy            # build + wrangler deploy
```

仓库中提交的 `_worker.js` 必须与从 `src/` 重新构建的产物一致。CI 通过
漂移检查强制这一点；如果你修改了 `src/`，**务必重新构建并把生成的产
物一并提交**。

完整流程见 [`CONTRIBUTING.md`](./CONTRIBUTING.md)。

## 文档

- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — 如何提 PR
- [`REFACTORING.md`](./REFACTORING.md) — 架构、schema 迁移、改名映射表
- [`docs/PLATFORM_LIMITS.md`](./docs/PLATFORM_LIMITS.md) — 哪些功能不可用以及原因

## 免责声明

本项目仅供教育与个人安全测试用途。请遵守所在司法辖区的法律。维护者对
任何滥用行为不承担责任。Cloudflare 的服务条款禁止把 Workers 当作"通用
代理"使用 — 执行力度并不一致，但账号被封停的风险是真实存在的。请使
用专门的 CF 账号，不要用你的主账号。详见 `docs/PLATFORM_LIMITS.md`。
