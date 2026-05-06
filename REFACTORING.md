# EdgeTunnel 重构总结

把上游单文件 `_worker.js`（4619 行）拆分成模块化 TypeScript 项目，移除所有中文标识符，保留行为完全一致的部署产物。

## Why This Refactor

[The upstream project `cmliu/edgetunnel`](https://github.com/cmliu/edgetunnel) is a brilliant Cloudflare Workers edge-proxy implementation — **a great idea, but very hard to maintain**:

- All logic is crammed into a single 4619-line `_worker.js` file
- Variables and functions are heavily named in Chinese identifiers
- Zero TypeScript types
- Zero test coverage

This organization makes it extremely hard for anyone to fix a bug, add a small feature, or even **figure out what a block of code is doing**. As a result, the project is effectively maintained by the original author alone, and the contribution barrier is high.

The goal of this refactor is simple: **make the project something anyone can read, modify, and contribute to** — lower the maintenance bar so that more people can get involved, while preserving runtime behaviour and deployment shape exactly so existing users can upgrade seamlessly.

## 当前状态：100% 完成 ✅

```
源码模块            51 个 .ts 文件
测试模块            24 个 .ts 文件
测试通过            227 / 227
TypeScript 错误     0
构建产物            _worker.js (232 KB, esbuild bundled)
对比原始单文件      git show <initial-commit>:_worker.original.js
```

```bash
npm install      # 安装依赖
npm run lint     # tsc --noEmit
npm test         # vitest run（24 个文件、227 个测试）
npm run build    # esbuild → _worker.js
npm run deploy   # build + wrangler deploy
```

## 项目结构

```
edgetunnel/
├── _worker.js                   ← 构建产物（被 npm run build 覆盖；原始单文件 _worker.original.js 已从工作树移除，保存在初始提交里）
├── package.json                 ← 依赖 + 脚本
├── tsconfig.json                ← TypeScript 配置
├── build.mjs                    ← esbuild 入口
├── vitest.config.ts             ← 测试配置
├── wrangler.toml                ← 部署配置
├── REFACTORING.md               ← 本文档
├── src/
│   ├── index.ts                 ← 主 fetch handler（路由分发）
│   ├── constants.ts             ← TLS / SS 协议常量
│   ├── state.ts                 ← ProxyContext（替代模块全局变量）
│   ├── crypto/                  (10) 加密层
│   │   ├── aes-gcm.ts                ← Web Crypto AES-GCM 包装
│   │   ├── chacha20.ts               ← ChaCha20 流密码（手写）
│   │   ├── chacha20-poly1305.ts      ← AEAD（手写，RFC 8439）
│   │   ├── ecdh.ts                   ← X25519 / P-256 ECDH
│   │   ├── hmac-hkdf.ts              ← HMAC + HKDF + TLS 1.2 PRF
│   │   ├── md5.ts                    ← md5x2 + UUID 格式化
│   │   ├── poly1305.ts               ← Poly1305 MAC（手写）
│   │   ├── sha224.ts                 ← SHA-224（Trojan 鉴权用）
│   │   ├── tls-record.ts             ← TLS 记录/握手解析器 + AEAD 辅助
│   │   ├── tls-messages.ts           ← ClientHello/ServerHello/etc 解析+构造
│   │   └── tls-client.ts             ← TlsClient 类（TLS 1.2/1.3 客户端）
│   ├── protocols/               (4) 协议解析
│   │   ├── dispatch.ts               ← 缓冲式协议探测（XHTTP/gRPC）
│   │   ├── shadowsocks.ts            ← SS AEAD 派生 + 加解密
│   │   ├── trojan.ts                 ← Trojan 帧解析
│   │   └── vless.ts                  ← VLESS 帧解析
│   ├── transports/              (8) 传输层
│   │   ├── byob-stream.ts            ← BYOB 流式优化
│   │   ├── direct.ts                 ← forwardTcp + connectDirect 主转发
│   │   ├── http-connect.ts           ← HTTP CONNECT 隧道
│   │   ├── https-proxy.ts            ← TLS 包装的代理 (含 ChaCha 回退)
│   │   ├── socket-utils.ts           ← close/wsSend/waitConnect
│   │   ├── socks5.ts                 ← SOCKS5 客户端
│   │   ├── tls-wrap.ts               ← TlsClient → 套接字接口包装
│   │   └── udp.ts                    ← DNS UDP + Trojan UDP 帧
│   ├── handlers/                (7) HTTP 处理器
│   │   ├── admin.ts                  ← /admin/* 路由 (KV CRUD)
│   │   ├── grpc.ts                   ← gRPC 数据面
│   │   ├── login.ts                  ← /login + cookie 验证
│   │   ├── ss-inbound.ts             ← SS 入站 AEAD 状态机
│   │   ├── sub.ts                    ← /sub 订阅生成主逻辑
│   │   ├── websocket.ts              ← 主数据面
│   │   └── xhttp.ts                  ← XHTTP 数据面
│   ├── subscription/            (3) 订阅热补丁
│   │   ├── clash.ts                  ← Clash YAML 补丁
│   │   ├── singbox.ts                ← Sing-box JSON schema 迁移
│   │   └── surge.ts                  ← Surge 配置补丁
│   ├── admin/                   (8) 管理工具
│   │   ├── cloudflare-api.ts         ← Cloudflare GraphQL 用量
│   │   ├── config.ts                 ← readConfigJson + 旧 schema 迁移
│   │   ├── pages.ts                  ← nginx() / html1101() 伪装页
│   │   ├── parse-address.ts          ← 反代 IP 解析+缓存+确定性洗牌
│   │   ├── preferred-sub.ts          ← 优选 IP API + 多编码 CSV 解析
│   │   ├── proxy-resolver.ts         ← parseSocks5Auth + parseProxyParams
│   │   ├── random-ip.ts              ← ISP-aware 随机 IP 生成
│   │   └── transport.ts              ← transport 配置 helpers
│   └── utils/                   (7) 工具
│       ├── bytes.ts                  ← 字节工具
│       ├── dns.ts                    ← DoH + ECH 提取
│       ├── hostname.ts               ← IP/host 工具
│       ├── log.ts                    ← 访问日志 + TG 推送
│       ├── logger.ts                 ← 调试日志
│       ├── path.ts                   ← randomPath / replaceAsterisks / bulkReplaceDomains
│       └── url.ts                    ← normalizeRequestUrl / toArray
└── tests/                       ← Vitest 测试套件（24 个文件，227 个测试）
    ├── crypto/         8 个文件 / 88 测试   含 RFC 8439 + FIPS 180-4 标准向量
    ├── protocols/      3 个文件 / 35 测试   VLESS/Trojan/Dispatch 边界覆盖
    ├── transports/     4 个文件 / 32 测试   socket-utils/tls-wrap/udp/byob
    ├── handlers/       1 个文件 /  9 测试   SS 入站状态机
    ├── subscription/   1 个文件 /  6 测试   Surge 补丁
    ├── admin/          3 个文件 / 30 测试   proxy-resolver/transport/random-ip
    └── utils/          4 个文件 / 50 测试   bytes/url/hostname/path/log
```

## 关键架构变化

### 1. 模块全局变量 → 请求级 ProxyContext

原代码使用模块顶层 mutable 变量（`let 反代IP = ''` 之类），依赖 fetch handler 在每次请求开头重置它们。这种做法在 Cloudflare Workers isolate 复用 + 并发请求场景下脆弱——状态可能串。

新代码：所有请求级状态在 `ProxyContext` 对象里，fetch handler 顶部 `createDefaultContext()`，逐层显式传参。

```typescript
// 原
let 反代IP = '';
function 处理请求() { 反代IP = '...' }

// 新
const ctx = createDefaultContext();
function handleRequest(ctx: ProxyContext) { ctx.proxyIP = '...' }
```

### 2. 中文标识符全部翻译为英文

所有变量名、函数名、字段名、对象键全部改成英文。**字符串字面量保留中文**（用户面向的 TG 推送模板、ISP 显示名 `CF移动优选`、加密密钥默认提示、CSV 表头 `IP地址`/`端口`/`数据中心` 等都是功能性数据）。

主要重命名：

| 原中文标识符 | 新英文 |
|---|---|
| `反代IP` | `ctx.proxyIP` |
| `启用SOCKS5反代` | `ctx.socks5Mode` |
| `启用SOCKS5全局反代` | `ctx.socks5GlobalEnabled` |
| `我的SOCKS5账号` | `ctx.socks5Auth` |
| `调试日志打印` | `ctx.debugLogEnabled` |
| `SOCKS5白名单` | `ctx.socks5Whitelist` |
| `启用反代兜底` | `ctx.proxyFallbackEnabled` |
| `config_JSON` | `ctx.configJson` |
| `处理WS请求` | `handleWebSocketRequest` |
| `处理XHTTP请求` | `handleXhttpRequest` |
| `处理gRPC请求` | `handleGrpcRequest` |
| `解析木马请求` | `parseTrojanRequest` |
| `解析魏烈思请求` | `parseVlessRequest` |
| `读取XHTTP首包` | `readFirstPacket` |
| `转发木马UDP数据` | `forwardTrojanUdp` |
| `MD5MD5` | `md5x2` |
| `读取config_JSON` | `readConfigJson` |
| `生成随机IP` | `generateRandomIPs` |
| `获取传输协议配置` | `getTransportConfig` |
| `获取传输路径参数值` | `getTransportPath` |
| `Clash订阅配置文件热补丁` | `patchClashSubscription` |
| `Singbox订阅配置文件热补丁` | `patchSingboxSubscription` |
| `Surge订阅配置文件热补丁` | `patchSurgeSubscription` |
| `请求日志记录` | `logRequest` |
| `掩码敏感信息` | `maskSensitive` |
| `DoH查询` | `dohQuery` |
| `获取优选订阅生成器数据` | `fetchPreferredSubData` |
| `请求优选API` | `requestPreferredApi` |
| `反代参数获取` | `parseProxyParams` |
| `获取SOCKS5账号` | `parseSocks5Auth` |
| `解析地址端口` | `parseAddressPort` |

### 3. config.json schema：旧中文键 → 新英文键 + 自动迁移

原存储在 KV `config.json` 里的字段名是中文（`协议类型`、`反代`、`优选订阅生成`…）。新代码使用全英文 schema，但 `readConfigJson` 检测到旧 schema 时会**透明地递归迁移并写回 KV**——存量用户更新代码后无需手动迁移。

```
协议类型 → protocol             订阅转换配置 → subConverter
传输协议 → transport             反代 → proxy
gRPC模式 → grpcMode              路径模板 → template
随机路径 → randomPath            全局 → global
跳过证书验证 → skipCertVerify    标准 → standard
启用0RTT → enable0RTT            账号 → auth
TLS分片 → tlsFragment            白名单 → whitelist
完整节点路径 → fullNodePath      加密方式 → cipher
加载时间 → loadTime              优选订阅生成 → preferredSub
本地IP库 → localIP                 随机IP → randomIP
随机数量 → count                   指定端口 → port
SOCKS5.启用 → SOCKS5.mode        TG.启用 → TG.enabled
```

迁移逻辑见 `src/admin/config.ts` 顶部的 `SCHEMA_MIGRATION` / `SCOPED_MIGRATION` 表和 `migrateLegacySchema()` 函数。第一次读取后会写回新 shape，后续读取直接 no-op。

### 4. 单文件源 → 编译产物

原工作流：编辑 `_worker.js` → 直接部署。
新工作流：编辑 `src/**/*.ts` → `npm run build` → 生成 `_worker.js` → 部署。

**部署产物形态不变**——`_worker.js` 仍然是单文件，仍然可以粘贴到 Workers Dashboard 或上传到 Pages。只是它现在是 **esbuild 打包产物** 而不是手写源码。

## 测试覆盖

```
crypto/        88 个测试  ChaCha20、Poly1305、ChaCha20-Poly1305 用 RFC 8439 标准向量；
                          SHA-224 用 FIPS 180-4 Appendix A 向量；md5、tls-record、
                          tls-messages 各自有覆盖
protocols/     35 个测试  VLESS / Trojan 全边界（错 UUID、错命令、错地址类型、半包等）；
                          dispatch 包含 byte-by-byte 分块场景
transports/    32 个测试  socket-utils（close/wsSend/waitConnect）、tls-wrap、
                          udp（Trojan UDP 帧）、byob-stream
handlers/       9 个测试  SS 入站目标头解析
subscription/   6 个测试  Surge 补丁
admin/         30 个测试  proxy-resolver、transport、random-ip（CIDR + ISP 适配）
utils/         50 个测试  bytes、url、hostname、path、log
```

**未覆盖区域**——以下模块依赖真实网络/Workers runtime，单元测试价值有限：
- `transports/direct.ts` 的 `forwardTcp` 主路径（深度集成 WebSocket + connect()）
- `crypto/tls-client.ts` 的完整握手（需要真实 TLS 服务器）
- `handlers/websocket.ts` / `handlers/xhttp.ts` / `handlers/grpc.ts` 数据面主流程
- `subscription/clash.ts` / `subscription/singbox.ts` 大段补丁逻辑

需要部署到 Cloudflare Workers 做集成测试验证。

## Bundle 大小分析

`_worker.js` 当前约 **77 KB**（VLESS-only + esbuild minify；CF Workers 免费版上限 1 MB unzipped，使用率约 8%）。CI 已设硬上限 900 KB；当 bundle 接近这个值时再考虑下面的优化。

随时运行 `npm run analyze` 可获取最新的逐模块 size breakdown（基于 esbuild metafile）。

### 当前贡献 Top 10（截至 2026-05）

| 模块 | 大小 | 备注 |
|---|---|---|
| `crypto/tls-client.ts` | 25.7 KB | 出站 TLS 客户端，**仅** `socks5Mode === 'https'` 路径调用 |
| `subscription/singbox.ts` | 13.5 KB | 仅 `/sub` 路径调用 |
| `handlers/sub.ts` | 10.8 KB | 订阅入口；仅 `/sub` |
| `admin/config.ts` | 10.4 KB | KV CRUD，仅 `/admin` |
| `handlers/grpc.ts` | 10.2 KB | 数据面热路径 |
| `admin/preferred-sub.ts` | 10.0 KB | 仅 `/admin` |
| `handlers/ss-inbound.ts` | 9.4 KB | 数据面热路径（SS 协议） |
| `handlers/websocket.ts` | 9.0 KB | 数据面热路径 |
| `subscription/clash.ts` | 8.1 KB | 仅 `/sub` |

### 分组(粗略)

- **数据面热路径**(始终需要): handlers/transports/protocols 大部分 + 必需 crypto ≈ 95 KB
- **冷路径**(请求时才命中): admin UI ≈ 25 KB · 订阅生成 ≈ 23 KB · TLS 客户端 ≈ 35 KB

### 未来 lazy-load / WORKER_LITE 路线（**仅在真到 size pressure 时再做**）

如果 bundle 增长到接近 1 MB(例如新增 REALITY-style 协议、AEAD-2022、内嵌静态资源等),按 **冷路径优先** 的顺序剥离:

1. **TLS 客户端家族**(`tls-client` + `tls-messages` + `tls-record` ≈ 35 KB)。绝大多数用户 `socks5Mode` 不是 `'https'`,可通过 esbuild `alias` 把 `transports/https-proxy.ts` 在 `WORKER_LITE` 模式下指向 stub,运行时若真的命中再返回明确错误。
2. **订阅系统**(`handlers/sub.ts` + `subscription/* ≈ 33 KB`)。如果用户只用单节点不需要订阅,完全可剥离。
3. **Admin UI**(`handlers/admin.ts` + `admin/pages.ts` + `admin/preferred-sub.ts` + `admin/cloudflare-api.ts` ≈ 25 KB)。极简部署可直接禁用 `/admin`,通过环境变量配 UUID。

#### 实现注意事项

- esbuild `bundle: true` **不会**通过 dynamic `import()` 实现真正的 size 节省 —— 静态导入还是会被 inlining,代码分割只在 `splitting: true` 多文件输出下生效,而项目部署形态(单文件 `_worker.js`)不允许多文件。
- 因此正确的剥离方式是 **build-time aliasing**:`alias` 把重模块换成 stub,esbuild DCE 会把整个子图剔除。
- WORKER_LITE 是 cross-cutting change,**当前没有 size pressure 时不要做**,会引入测试矩阵翻倍(全功能 + lite 双模)和回归风险。

## 重要注意事项

1. **原始单文件保存在初始提交里**。`_worker.original.js` 已从工作树移除（避免每次构建产物提交时的 noisy diff），但作为 4619 行原始代码的"原貌"快照保存在初始提交 `8de49df` 里。需要查阅或 diff 时：
   ```bash
   git show 8de49df:_worker.original.js > /tmp/_worker.original.js
   diff /tmp/_worker.original.js _worker.js
   ```

2. **手写加密代码不要重构**。`chacha20.ts`、`poly1305.ts`、`sha224.ts` 是密码学敏感——按位移、按字节、按特定常量。任何"看起来更优雅"的改写都可能改变算法语义。

3. **TLS 客户端模块整体保留**（~600 行）。`tls-client.ts` 的内部状态机非常紧密耦合，进一步拆分反而更难读。

4. **首次部署后**用 TG 推送或 `/admin` 后台验证一遍：
   - WebSocket 连接（VLESS / Trojan / SS 三种协议都试一下）
   - 订阅生成（Clash / Sing-box / Surge）
   - 旧 KV 配置自动迁移（如果是从旧版升级）

5. **上游同步**：原仓库的 `.github/workflows/sync.yml` 会定时从 `cmliu/edgetunnel` 拉 `_worker.js`。本项目已移除该 workflow——如果想跟踪上游变更，建议手动从初始提交取出原始单文件（`git show 8de49df:_worker.original.js`）作为基准，diff 上游最新 `_worker.js`，再决定哪些差异需要回填到 `src/`。
