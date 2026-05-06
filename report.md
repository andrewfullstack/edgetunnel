# EdgeTunnel 项目深度解析

> 一份从代码到协议、从架构到生态的完整技术报告
>
> 项目仓库：`cmliu/edgetunnel` 系列
> 本报告基于 `_worker.js`（约 4619 行，单文件、零依赖）的源码分析

---

## 目录

- [第 1 章 项目概述](#第-1-章-项目概述)
- [第 2 章 整体架构](#第-2-章-整体架构)
- [第 3 章 请求处理流程](#第-3-章-请求处理流程)
- [第 4 章 入站协议详解](#第-4-章-入站协议详解)
- [第 5 章 加密层](#第-5-章-加密层)
- [第 6 章 出站连接机制](#第-6-章-出站连接机制)
- [第 7 章 协议生态科普](#第-7-章-协议生态科普)
- [第 8 章 抗审查能力分析](#第-8-章-抗审查能力分析)
- [第 9 章 为什么 EdgeTunnel 行得通](#第-9-章-为什么-edgetunnel-行得通)
- [第 10 章 总结与思考](#第-10-章-总结与思考)

---

## 第 1 章 项目概述

### 1.1 是什么

EdgeTunnel 是一个**单文件 Cloudflare Workers/Pages 应用**，把 Cloudflare 的边缘网络变成一个支持 VLESS / Trojan / Shadowsocks 三种入站协议的代理网关。客户端（Clash、Sing-box、V2Ray、Shadowrocket 等）通过订阅链接连上部署后的 Worker 域名，所有流量先经过 Cloudflare 边缘，由 Worker 解出真实目标地址，再用 Cloudflare 提供的 `connect()` API 打开一条原始 TCP 连接到目标服务器，最后把字节双向转发。

### 1.2 不是协议转换器

它**不在协议之间做转换**——出站永远是原始 TCP。所谓"代理"就是：**剥掉入站协议的封装层，把里面的真实数据发到真实目标**。

### 1.3 项目定位与维护

- 这是 `cmliu/edgetunnel` 上游的派生版本，活跃维护
- `.github/workflows/sync.yml` 配置了**每日定时从上游拉取主分支**
- 最近的提交活动集中在 Singbox/Clash 订阅兼容性改进、ECH 处理、BYOB 性能优化

### 1.4 目标用户

- 没有 VPS 资源、希望零成本部署的个人用户
- 需要稳定、长期、低维护代理通道的非专业用户
- 想要"挂在 Cloudflare 上"享受 CDN 级别防封锁的用户

---

## 第 2 章 整体架构

### 2.1 项目仓库的目录结构

```
edgetunnel/
├── .git/
├── .github/
│   └── workflows/
│       └── sync.yml          # 上游同步自动化
├── _worker.js                # 全部应用代码（~4619 行）
├── wrangler.toml             # Cloudflare 部署配置
├── README.md                 # 部署说明
├── CHANGELOG
├── LICENSE
└── img.png
```

仓库**极其精简**——没有 `src/`、`lib/`、`dist/`、`package.json`、构建脚本、依赖管理。**所有应用逻辑都在 `_worker.js` 这一个文件里**。

### 2.2 部署模型

```
                      Cloudflare 边缘
                  ┌───────────────────┐
  客户端           │   _worker.js       │           真实目标
(Clash/Sing-box) ─▶│  (~4619 行 JS)    │──connect()─▶ google.com
                  │                   │              :443
                  │  ┌─VLESS 解析     │
                  │  ├─Trojan 解析    │   ProxyIP fallback
                  │  ├─SS AEAD 解密  │   SOCKS5 链
                  │  └─出站调度       │   HTTP CONNECT 链
                  └───────────────────┘
                      │           │
                  ┌───▼───┐  ┌────▼───┐
                  │ KV 存储│  │ 静态页 │
                  │(配置/  │  │(管理   │
                  │ 日志)  │  │ 面板)  │
                  └───────┘  └────────┘
                            edt-pages.github.io
```

### 2.3 三种部署方式

| 方式 | 操作 | 特点 |
|---|---|---|
| Workers 直接部署 | 把 `_worker.js` 粘贴到 Workers 编辑器 | 最快 |
| Pages + ZIP 上传 | 把项目 ZIP 上传到 Cloudflare Pages | 推荐 |
| Pages + GitHub | Fork 仓库，连接到 Pages，自动部署 | 持续同步 |

三种方式都需要：
- `ADMIN` 环境变量（管理员密码）
- `KV` 命名空间绑定（持久化存储）
- 自定义域名（CNAME 到 Pages，或 Workers 自定义域）

### 2.4 KV 存储布局

| Key | 内容 |
|---|---|
| `config.json` | 订阅生成器配置（节点模板、传输参数等） |
| `cf.json` | Cloudflare API Token 与 Zone 信息（用于查带宽） |
| `tg.json` | Telegram 机器人集成配置 |
| `ADD.txt` | 优选 IP 列表（订阅生成时用） |
| `log.json` | 请求访问日志 |

### 2.5 环境变量

| 变量 | 用途 |
|---|---|
| `UUID` 或 `uuid` | 数据面的鉴权 UUID（不设则从 `ADMIN` 派生） |
| `ADMIN`（也可用 `password` `pswd` `TOKEN` `KEY`） | 管理员密码 |
| `KEY` | Cookie 加密密钥 + 快速订阅路径 token |
| `HOST` | 允许的访问主机名（逗号或换行分隔） |
| `PROXYIP` | 自定义反代 IP 白名单 |
| `GO2SOCKS5` | 强制走 SOCKS5 的域名列表 |
| `URL` | 主页伪装目标（默认显示 nginx 欢迎页） |
| `DEBUG` | 启用详细日志 |
| `OFF_LOG` | 关闭 KV 日志记录 |
| `BEST_SUB` | 启用 IP 质量优选订阅模式 |
| `KV` (binding) | 必需的 KV 命名空间绑定 |

### 2.6 几个关键设计特点

1. **同一个域名同时承载数据面和控制面**——代理流量、订阅 URL、管理面板共用一个域名。从外部看就是个普通 HTTPS 站点。
2. **管理面板 HTML 不在仓库里**——Worker 从 `https://edt-pages.github.io` 拉取后通过自己的域名提供。
3. **零依赖**——没有 `package.json`，不用 npm install，没有构建步骤。直接运行。
4. **大量手写加密**——为了在 Cloudflare Workers 的运行时限制下工作（详见第 5 章）。

---

## 第 3 章 请求处理流程

### 3.1 整体流程图

```
                     Cloudflare 边缘 _worker.js
       ┌──────────────────────────────────────────────┐
   ────▶│ 第 1 层：HTTP 形状分发（fetch 主入口）          │
       │   - WebSocket 升级? → 处理WS请求()            │
       │   - POST + grpc?    → 处理gRPC请求()          │
       │   - POST 其他?       → 处理XHTTP请求()        │
       │   - GET /sub?       → 订阅生成器              │
       │   - GET /admin*?    → 管理面板（带 cookie）    │
       │   - GET /?          → 伪装页                  │
       └──────────────────────────────────────────────┘
                              │
                              ▼
       ┌──────────────────────────────────────────────┐
       │ 第 2 层：协议识别（针对前三种代理路径）         │
       │   WS 路径：第一字节模式嗅探                    │
       │     - URL 带 ?enc= → SS                       │
       │     - 字节[56..58] = \r\n → Trojan            │
       │     - 否则 → VLESS                            │
       │   XHTTP/gRPC：缓冲式双重试探                  │
       │     - 边读边喂 Trojan / VLESS 两个解析器       │
       │     - 任一返回 'ok' → 确定协议                 │
       └──────────────────────────────────────────────┘
                              │
                              ▼
       ┌──────────────────────────────────────────────┐
       │ 第 3 层：协议解析提取目标地址                   │
       │   { hostname, port, isUDP, rawData }          │
       └──────────────────────────────────────────────┘
                              │
                              ▼
       ┌──────────────────────────────────────────────┐
       │ 第 4 层：出站连接（cloudflare:sockets）        │
       │   connect({hostname, port}) → 双向流式转发      │
       └──────────────────────────────────────────────┘
```

### 3.2 第一层调度：HTTP 形状分发

主入口在 `_worker.js:11`，根据请求形状分发：

```js
// _worker.js:35-48 简化版
if (管理员密码 && upgradeHeader === 'websocket') {
    return await 处理WS请求(request, userID, url);              // WebSocket 通道
} else if (管理员密码 && request.method === 'POST' && 不是admin/login路径) {
    if (contentType.startsWith('application/grpc')) {
        return await 处理gRPC请求(request, userID);             // gRPC 通道
    }
    return await 处理XHTTP请求(request, userID);                // XHTTP 通道
} else {
    // 处理 /sub 订阅、/admin 管理面板、/login 登录、/ 伪装页等
}
```

| 请求形状 | 处理函数 | 文件位置 |
|---|---|---|
| `Upgrade: websocket` | `处理WS请求()` | `_worker.js:995` |
| `POST` + `Content-Type: application/grpc` | `处理gRPC请求()` | `_worker.js:765` |
| `POST` + 其他 | `处理XHTTP请求()` | `_worker.js:461` |
| `GET /sub?token=…` | 订阅生成器 | `_worker.js:266` |
| `GET /admin*` | 管理面板（带 cookie 鉴权） | `_worker.js:74` |
| `GET /` | 伪装页（默认 nginx 欢迎页） | `_worker.js:434` |

### 3.3 第二层调度：协议识别

确定了入站传输方式后，下一步识别**应用层协议**——VLESS、Trojan 还是 Shadowsocks。WS 路径和 XHTTP/gRPC 路径走不同的识别策略。

#### 3.3.1 WebSocket 路径：按字节模式嗅探

WS 升级完成后，第一个数据块到达时执行（`_worker.js:1354-1361`）：

```js
if (判断协议类型 === null) {
    if (url.searchParams.get('enc')) 判断协议类型 = 'ss';
    else {
        const bytes = new Uint8Array(chunk);
        判断协议类型 = bytes.byteLength >= 58 && bytes[56] === 0x0d && bytes[57] === 0x0a
            ? '木马'      // Trojan
            : '魏烈思';   // VLESS（源码故意混淆这个标识符）
    }
}
```

三条规则按顺序执行：

1. **Shadowsocks**：URL 查询参数带 `?enc=<加密算法>`（如 `aes-128-gcm`）。SS 的特殊性在于"从第一字节开始就是密文"，没法靠字节模式嗅探，必须由客户端主动声明。
2. **Trojan**：第一块字节数 ≥ 58，且第 56、57 字节是 `\r\n`（这是 Trojan 协议在 56 字节 SHA-224 密码哈希后的固定 CRLF）。
3. **VLESS**：兜底。源码用 `魏烈思` 这个混淆标识符，并在多处用 `'vl'+'ess'` 字符串拼接（如 `_worker.js:656`），躲避静态扫描。

#### 3.3.2 XHTTP/gRPC 路径：缓冲式双重试探

XHTTP/gRPC 没有 WS 那种干净的"首条消息"边界，字节可能分多次零碎到达。所以用 `读取XHTTP首包`（`_worker.js:606-763`）边读边试：

```js
// _worker.js:730-755 简化逻辑
while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer.set(value, offset); offset += value.byteLength;

    const 木马结果 = 尝试解析木马首包(当前数据);
    if (木马结果.状态 === 'ok') return { ...木马结果.结果, reader };

    const 魏烈思结果 = 尝试解析魏烈思首包(当前数据);
    if (魏烈思结果.状态 === 'ok') return { ...魏烈思结果.结果, reader };

    if (木马结果.状态 === 'invalid' && 魏烈思结果.状态 === 'invalid') return null;
}
```

每个解析器返回三种状态之一：`'ok'`（成功）、`'need_more'`（数据不够）、`'invalid'`（格式不对）。这样**支持半包/分片**，特别适合 XHTTP 这种 chunked 传输。

注意：**XHTTP/gRPC 不支持 Shadowsocks**，只支持 VLESS 和 Trojan。

### 3.4 端到端流量示例

以 Clash 通过 EdgeTunnel 访问 `https://www.google.com` 为例：

```
1. Clash → WSS 连接到 https://your-domain/?path=...
   带 Upgrade: websocket 头

2. Cloudflare 边缘路由到 _worker.js
   fetch handler 检测到 Upgrade: websocket → 调 处理WS请求()

3. 处理WS请求 (_worker.js:995)
   创建 WebSocketPair，accept 服务端
   ReadableStream 包装 WS message
   pipeTo(WritableStream) 处理每个数据块

4. 第一个 chunk 到达
   URL 没 ?enc= → 不是 SS
   chunk[56..58] != \r\n → 不是 Trojan
   → VLESS

5. 解析VLESS请求 (_worker.js:1382)
   校验 chunk[1..17] 是否等于 MD5(ADMIN) 的 16 字节格式
   读 cmd=1 (TCP), port=443, atype=2 (域名)
   提取域名 "www.google.com"
   提取 rawData = chunk[headerLen..]

6. forwardataTCP("www.google.com", 443, rawData, ...)
   调 connectDirect (_worker.js:1682)
   不命中 SOCKS5 白名单
   不需要 ProxyIP
   connect({hostname: "www.google.com", port: 443})

7. 双向管道
   WS → socket.writable: 把 rawData（Clash 发的 TLS ClientHello）写到 Google
   socket.readable → WS: 读 Google 返回的字节，原样转发
   BYOB 优化：512KB 预分配缓冲区 + 自适应 flush

8. Clash 那一端
   收到回包，剥掉 [version, 0] 后是真正的 TLS ServerHello
   后续就是 Clash 和 Google 之间端到端的 TLS
   Worker 看不到明文，只是个透明字节通道
```

**关键观察**：TLS 握手在 Clash 和 Google 之间端到端进行，Worker 是透明字节管道。VLESS 协议本身**不做加密**——它假设外层 WSS 已经加密了。

---

## 第 4 章 入站协议详解

### 4.1 VLESS 帧格式

代码位置：`_worker.js:609-663`（`尝试解析魏烈思首包`） + `_worker.js:1480-1514`（`解析魏烈思请求`）

**帧结构**：

| 偏移 | 字段 | 说明 |
|---|---|---|
| `[0]` | 版本字节 | 响应头会原样回送 `[version, 0]` |
| `[1..17]` | 16 字节 UUID | 必须等于 `MD5(管理员密码)` 的格式化形式 |
| `[17]` | optLen | 可选附加项长度（一般为 0） |
| `[18+optLen]` | cmd | `1`=TCP, `2`=UDP |
| 接下来 2 字节 | port | 大端 |
| 接下来 1 字节 | 地址类型 | `1`=IPv4, `2`=域名（带长度前缀）, `3`=IPv6 |
| 后续地址字节 | 目标地址 | 按类型解析 |
| 剩余 | 真实负载 | `rawData` |

**鉴权字段（16 字节 UUID 二进制）**：

UUID 字符串形如 `550e8400-e29b-41d4-a716-446655440000`，去掉连字符后是 32 个十六进制字符 → 转成 16 字节二进制：

```
"550e8400-e29b-41d4-a716-446655440000"
            ↓ 去连字符 + 转二进制
0x55 0x0e 0x84 0x00 0xe2 0x9b 0x41 0xd4 0xa7 0x16 0x44 0x66 0x55 0x44 0x00 0x00
```

客户端把这 16 字节直接写入帧的 byte[1..17)，**不加密、不混淆、不 hash**。

**服务器校验**（`_worker.js:1483`）：

```js
if (formatIdentifier(new Uint8Array(chunk.slice(1, 17))) !== token)
    return { hasError: true, message: 'Invalid uuid' };
```

`formatIdentifier()`（`_worker.js:1840`）把 16 字节转回 UUID 字符串再比较。

**鉴权失败的处理**：直接返回错误、断开连接。**没有 fallback 机制**。

### 4.2 Trojan 帧格式

代码位置：`_worker.js:666-724`（`尝试解析木马首包`）

**帧结构**：

| 偏移 | 字段 | 说明 |
|---|---|---|
| `[0..56]` | 56 字节 ASCII 十六进制 | `SHA-224(管理员密码)` 的字符串形式 |
| `[56..58]` | CRLF (`\r\n`) | 固定分隔符——也是 WS 嗅探的依据 |
| `[58]` | cmd | `1`=TCP, `3`=UDP（**SOCKS5 风格**） |
| `[59]` | atype | `1`=IPv4, `3`=域名, `4`=IPv6（**SOCKS5 风格**） |
| 后续地址字节 | 目标地址 | |
| 接下来 2 字节 | port | 大端 |
| 接下来 2 字节 | CRLF | 又一个固定分隔符 |
| 剩余 | 真实负载 | `rawData` |

**鉴权字段（56 字节 SHA-224 hex）**：

SHA-224 输出 28 字节二进制 → 十六进制字符串化 → 56 个 ASCII 字符（`'0'-'9'` `'a'-'f'`）。

举例：`SHA-224("hello") = ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193`，正好 56 个字符。

**服务器校验**（`_worker.js:670-674`）：

```js
if (length < 58) return { 状态: 'need_more' };
if (data[56] !== 0x0d || data[57] !== 0x0a) return { 状态: 'invalid' };
for (let i = 0; i < 56; i++) {
    if (data[i] !== 密码哈希字节[i]) return { 状态: 'invalid' };
}
```

**为什么用 hex ASCII 而不是直接发二进制密码**：

| 选择 | 直接发密码 | 发 SHA-224 hex |
|---|---|---|
| 长度是否固定 | 否，密码长短不一 | 永远 56 字节 |
| 字符集是否安全 | 可能含 `\r\n`、`\0` | 只含 `0-9 a-f` |
| **fallback 时是否像 HTTP** | 二进制密码扔给 nginx 会被拒 | **56 字节 hex 看起来像 HTTP 请求行** |
| 被中间人窃听后影响 | 明文密码直接泄露 | 只暴露 hash |

最关键是第三点——让"协议头"和"普通 HTTP 请求"在字节层面无法区分，才能做 fallback 到真网站。

**Trojan 的 fallback 机制**：

标准 Trojan 实现里，鉴权失败要**继续把流量喂给后端 nginx**：

```
56 字节对得上 → 解析后续 SOCKS5 地址头 → 出站代理
56 字节对不上 → 把已经读到的所有字节（包括那 56 字节本身）
              → 转发给本地 nginx → 返回真网页
```

这样探测者看到的就是个普通 HTTPS 网站，**完全分不出这是 Trojan 服务器还是真博客**。

**但 EdgeTunnel 没实现 fallback**——鉴权失败直接断（`_worker.js:754` 返回 `null`）。它的伪装机制由外层路由层（主入口的伪装页 + Cloudflare 外壳）承担，不在 Trojan 协议解析层做。

### 4.3 Shadowsocks AEAD 框架

代码位置：`_worker.js:1104-1257`（处理 SS 数据） + `_worker.js:1516-1519`（cipher 配置）

SS 与 VLESS/Trojan 完全不同——**整条流从第 0 字节起就是加密的**，没有明文协议头。流程：

1. 客户端在 WS URL 上加 `?enc=aes-128-gcm`（或类似）显式声明
2. 服务器用 `SS派生主密钥(yourUUID, keyLen)`（`_worker.js:1113`）派生主密钥——经典的 EVP_BytesToKey 风格 MD5 链（`_worker.js:1629`）
3. 客户端先发送 16 或 32 字节随机 salt。服务器拿到后用 HKDF-SHA1（info 串 `"ss-subkey"`）派生会话密钥
4. **多算法试解密**（`_worker.js:1110`）：先按 URL 指定的算法试，失败就遍历 `SS支持加密配置` 里其他算法逐一试，直到某个能成功 AEAD 解密第一个长度块为止
5. 此后每个数据块格式是 `[2 字节长度][16 字节 tag][payload][16 字节 tag]`，nonce 每块递增
6. 解密出来的明文里**才是 SOCKS5 风格的目标地址头**，后面才是真实数据

**支持的算法表**（`_worker.js:1516-1519`）：

```js
const SS支持加密配置 = {
    'aes-128-gcm': { keyLen: 16, saltLen: 16, maxChunk: 0x3fff, aesLength: 128 },
    'aes-256-gcm': { keyLen: 32, saltLen: 32, maxChunk: 0x3fff, aesLength: 256 },
};
```

只支持这两种 AES-GCM 变种——因为 Cloudflare Workers 的 Web Crypto **不支持 ChaCha20-Poly1305 作为 AEAD 算法**，所以入站 SS 不开 ChaCha 流派。

### 4.4 三种协议对比

| 维度 | **VLESS** | **Trojan** | **Shadowsocks** |
|---|---|---|---|
| 鉴权字段 | 16 字节二进制 UUID | 56 字节 ASCII hex (`SHA-224`) | AEAD 派生密钥 |
| 是否自带加密 | 否 | 否 | 是（AES-GCM） |
| 是否需要外层 TLS | 是 | 是 | 否（但通常套上） |
| 帧最小开销 | ~22 字节 | ~64 字节 | ~50 字节（含 salt） |
| 鉴权失败行为 | 直接断 | 标准实现转 nginx | 解密失败错误 |
| 协议扩展性 | 强（有 version + opt 字段） | 弱（无扩展点） | 弱 |
| 现代部署主推 | 是 | 衰退中 | 不推荐裸跑 |

**三个协议的设计哲学**：

- **Shadowsocks**：自包含——加密 + 鉴权 + 路由全在协议里。简单但易识别。
- **Trojan**：最小化加密但内置伪装机制（fallback nginx）。
- **VLESS**：极简，啥都不管——加密给 TLS、伪装给 Reality/CDN、流量整形给 Vision。这种"啥都外包"的设计让 VLESS 成为现代抗审查协议栈的标准载体。

---

## 第 5 章 加密层

EdgeTunnel 在 `_worker.js` 里手写了大量加密代码——一部分是 Web Crypto 不支持只能自己实现，一部分是协议要求自己控制实现细节。整个加密层占文件约 1/3 的篇幅。

### 5.1 用 Web Crypto API 完成的部分

通过 `crypto.subtle`（Cloudflare Workers 提供）：

| 功能 | 用途 | 行号 |
|---|---|---|
| AES-GCM 加解密 | Shadowsocks AEAD、TLS 1.2/1.3 AES 套件 | `_worker.js:2227-2231` |
| HMAC-SHA256/SHA384 | 各种 MAC 计算 | `_worker.js:2184` |
| HKDF-Extract / Expand-Label | TLS 1.3 密钥调度 | `_worker.js:2200-2225` |
| ECDH（X25519、P-256） | TLS 密钥协商 | `_worker.js:2216-2224` |
| MD5 | UUID 派生、订阅 token | `_worker.js:1629`, `_worker.js:3480` |
| SHA-256 | 各种摘要 | `_worker.js:2188` |

注：MD5 不在 W3C Web Crypto 规范里，**Cloudflare Workers 私有扩展**。

### 5.2 手写的纯 JS 加密

| 算法 | 行号 | 用途 |
|---|---|---|
| `chacha20Block` / `chacha20Xor` | `_worker.js:2240-2263` | ChaCha20 流加密核心 |
| `poly1305Mac` | `_worker.js:2265-2292` | Poly1305 MAC（BigInt 算 130-bit 模运算） |
| `chacha20Poly1305Encrypt/Decrypt` | `_worker.js:2294-2323` | ChaCha20-Poly1305 AEAD |
| `sha224` | `_worker.js:4367` | Trojan 密码哈希专用 |

**为什么必须手写 ChaCha20-Poly1305**：

Cloudflare Workers 的 Web Crypto **不支持** ChaCha20-Poly1305 作为 AEAD 算法（只支持 AES-GCM）。但 TLS 1.3 的常见套件 `TLS_CHACHA20_POLY1305_SHA256` 必须有它，否则连不上一些只支持 ChaCha 的服务器。

**为什么要 SHA-224**：

Web Crypto 不暴露 SHA-224，但 Trojan 协议规定密码哈希必须是 SHA-224。

### 5.3 完整的 TLS 1.2 + 1.3 客户端

最让人意外的部分——**项目内置了一个完整的 TLS 客户端**，类名 `TlsClient`（`_worker.js:2486+`）。

包括：

| 模块 | 行号 | 作用 |
|---|---|---|
| `buildClientHello` | `_worker.js:2446` | 构造 ClientHello（含 SNI、ALPN、X25519+P256 双 key share、TLS 1.2/1.3 同时 offer） |
| `TlsRecordParser` | `_worker.js:2338` | 解析 TLS 记录层 |
| `TlsHandshakeParser` | `_worker.js:2354` | 解析握手消息流 |
| `handshake()` | `_worker.js:2521` | 主握手入口 |
| `handshakeTls12()` | `_worker.js:2562` | TLS 1.2 完整握手 |
| `handshakeTls13()` | `_worker.js:2623` | TLS 1.3 完整握手（含密钥调度） |
| `tls12Prf` | `_worker.js:2189` | TLS 1.2 PRF |
| 记录层 AEAD 加解密 | `_worker.js:2700-2747` | 双向数据加密（ChaCha 用手写、AES 用 Web Crypto） |

**为什么要手写 TLS 客户端**：

Worker 通过 `connect()` 拿到的是**裸 TCP socket**，而 `fetch()` 没法暴露底层 socket。当出站要经过 TLS 包裹的代理（如 HTTPS CONNECT 代理、Trojan-over-TLS 上游）时，Worker 必须**自己在裸 socket 上完成 TLS 握手**，才能继续往里写明文协议数据。

**ChaCha 回退机制**（`_worker.js:2084`）：

```js
const 需要ChaCha回退 = (error) => /cipher|handshake|TLS Alert|...../i.test(error?.message);
```

如果 AES-GCM 握手失败，自动重试只 offer ChaCha 套件——应付一些只支持 ChaCha 的代理服务器。

### 5.4 加密层在项目里的实际使用场景

```
1. Shadowsocks 入站
   - 用 SS派生主密钥(UUID, keyLen) 从 UUID 派生主密钥
   - 用 HKDF-SHA1 派生会话密钥
   - AES-GCM 解密每个 chunk

2. 出站 TLS 握手
   - 当出站要经过 HTTPS 代理时
   - 自己用 TlsClient 在裸 TCP 上做完整 TLS 1.2/1.3 握手
   - 之后才能写代理协议数据

3. 鉴权与 token
   - MD5(管理员密码 + KEY) → 派生 userID（UUID 格式）
   - MD5(host + userID) → 订阅 token
   - SHA-224(userID) → Trojan 密码哈希（手写 sha224）
```

---

## 第 6 章 出站连接机制

### 6.1 cloudflare:sockets 的 connect() 是 Cloudflare 平台 API

代码第 5 行：

```js
import { connect } from 'cloudflare:sockets';
```

`cloudflare:sockets` 是 Cloudflare Workers 运行时的**内置虚拟模块**，类似 Node.js 的 `node:fs`。它是 Cloudflare 在 **2023 年 5 月**发布的 TCP Sockets API，让 Workers 能打开**原始 TCP 出站连接**。

**整个项目里只 import 一次**——`connect` 不是项目自己实现的。

签名大致是：

```typescript
import { connect } from 'cloudflare:sockets';

const socket: Socket = connect(
    { hostname: "www.example.com", port: 443 },
    {
        secureTransport: "off" | "on" | "starttls",
        allowHalfOpen: true | false,
    }
);

// socket.readable: ReadableStream<Uint8Array>
// socket.writable: WritableStream<Uint8Array>
// socket.close(): Promise<void>
// socket.startTls(): Socket
```

### 6.2 自己实现 connect() 复杂吗

| 场景 | 难度 |
|---|---|
| 在 Node.js / Deno / Bun 里复刻接口 | 30 行包装代码 |
| 在浏览器里实现 | 不可能（无原始 TCP） |
| 在 Cloudflare Workers 里抛开此 API | 不可能（V8 isolate 沙箱） |
| 从零写一个 TCP/IP 协议栈 | 几个月～几年 |

**复杂度不在 JS 接口上，而在底层平台是否提供 TCP 能力**。Cloudflare 内部实现涉及：
- 跨 V8 isolate 边界的零拷贝字节传输（capnp / KJ 框架）
- 流量计费 / 限流
- 安全策略（不能 connect 到内网、Cloudflare 内部 IP 等）
- DNS 缓存 / 故障转移
- TLS（如果开启 secureTransport）：BoringSSL 几十万行 C 代码

**这些只有 Cloudflare 自己能做**。

### 6.3 项目在 connect() 之上的层

虽然 `connect()` 是平台给的，**怎么用好它完全是项目自己写的**：

| 层级 | 项目自己实现 | 行号 |
|---|---|---|
| `connect({hostname, port})` | 否（平台 API） | `_worker.js:5`（import） |
| 重试 + ProxyIP 兜底 | 是 | `connectDirect()` `_worker.js:1682` |
| SOCKS5 客户端协商 | 是 | `socks5Connect()` `_worker.js:1984` |
| HTTP CONNECT 隧道 | 是 | `httpConnect()` `_worker.js:2020` |
| TLS 1.2/1.3 握手 | 是 | `TlsClient` 类 `_worker.js:2486` |
| 双向 pipe 调度 | 是 | `forwardataTCP` 等 `_worker.js:1700+` |

### 6.4 出站策略链

```
直连尝试（connectDirect, _worker.js:1682）
   │ 失败/特定域名
   ▼
SOCKS5 链（socks5Connect, _worker.js:1984）
   │ 失败/特定域名
   ▼
HTTP CONNECT 链（httpConnect, _worker.js:2020）
   │ 失败
   ▼
ProxyIP 兜底（针对 Cloudflare 内部 IP 不能直接 connect 的情况）
```

### 6.5 ProxyIP 机制

代码 `_worker.js:26-30`：

```js
if (env.PROXYIP) {
    const proxyIPs = await 整理成数组(env.PROXYIP);
    反代IP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
    启用反代兜底 = false;
} else {
    反代IP = (request.cf.colo + '.PrOxYIp.CmLiUsSsS.nEt').toLowerCase();
}
```

**为什么需要 ProxyIP**：Cloudflare 不允许 Worker 直接 `connect()` 到其他 Cloudflare 托管的 IP（端口 443、80 等）。所以要访问 Cloudflare 托管的目标，必须走"代理 IP"。

如果用户没设 `PROXYIP`，根据当前 Cloudflare 数据中心代码（`request.cf.colo`，比如 `LAX`、`HKG`）拼出 `lax.PrOxYIp.CmLiUsSsS.nEt` 这种域名作为默认反代入口。

### 6.6 SOCKS5 / HTTP 出站链的字节级实现

如果用户配置了 SOCKS5 或 HTTP 上游代理，Worker 自己用 `socket.writable.getWriter()` 一字节一字节写出 SOCKS5 / HTTP CONNECT 协议握手：

```js
// _worker.js:1984+ SOCKS5 简化逻辑
const socket = connect({ hostname: socks5Host, port: socks5Port });
const writer = socket.writable.getWriter();

await writer.write(new Uint8Array([0x05, 0x01, 0x00]));  // 方法协商
// ... 读 [0x05, 0x00] 响应 ...
await writer.write(new Uint8Array([0x05, 0x01, 0x00, atype, ...addr, port>>8, port&0xff]));
// ... 读连接响应 ...
// 隧道建立完毕，后续就是透明转发
```

### 6.7 BYOB 流式优化

代码 `_worker.js:1851-1854`：

```js
const BYOB缓冲区大小 = 512 * 1024;
const BYOB单次读取上限 = 64 * 1024;
const BYOB高吞吐阈值 = 50 * 1024 * 1024;
```

**BYOB**（Bring Your Own Buffer）是 ReadableStream 的一个高级模式，让消费者**复用预分配的缓冲区**，避免每个 chunk 都分配新内存。

特性：
- 512KB 预分配缓冲区
- 自适应 flush 间隔：低吞吐时 2ms（低延迟），超过 50 MB/s 切到 20ms（高吞吐）
- 不支持 BYOB 模式时回退到普通 ReadableStream

在视频流、大文件下载等高吞吐场景下能显著降低 CPU 占用。最近的 `beta2.1-BYOB` PR 就是这个特性的引入。

---

## 第 7 章 协议生态科普

### 7.1 VLESS / Trojan / SS / TLS 不是同一个层级

```
TLS                    = 传输层加密（怎么"安全地"运字节）
VLESS / Trojan / SS    = 代理协议（怎么"告诉服务器要去哪"）
```

它们是**互补关系**，不是同类。VLESS 和 Trojan 都不带加密，依赖外层 TLS；SS 自己带加密。

**典型分层组合**：

```
┌──────────────────┬─────────────────────┬────────────────────┐
│ 组合 A: VLESS    │ 组合 B: Trojan      │ 组合 C: SS         │
├──────────────────┼─────────────────────┼────────────────────┤
│ VLESS 帧（无加密）│ Trojan 帧（无加密）  │ SS AEAD（自带加密） │
│   ↓              │   ↓                 │   ↓                 │
│ WebSocket        │ TLS                 │ WebSocket            │
│   ↓              │   ↓                 │   ↓                  │
│ TLS              │ TCP                 │ TLS                  │
│   ↓              │                     │   ↓                  │
│ TCP              │                     │ TCP                  │
└──────────────────┴─────────────────────┴────────────────────┘
```

### 7.2 Reality 协议详解

Reality 是 2023 年初出现的**新一代抗审查传输协议**，由 Project X 团队（XTLS 作者 RPRX）设计。

#### 7.2.1 解决的痛点

老方案（VLESS+TLS、Trojan+TLS）的问题：
1. 必须自己买域名 + 申请证书
2. TLS 指纹被识别（JA3/JA4）
3. SNI 暴露目标
4. TLS-in-TLS 嵌套指纹

#### 7.2.2 核心思想：借大牌身份

服务器配置一个"目标网站"（dest）——通常是大型 CDN 站点：
- `www.microsoft.com`
- `www.apple.com`
- `gateway.icloud.com`

服务器假装这就是它自己的身份。

#### 7.2.3 工作流程

```
1. 客户端发起 TLS ClientHello
   - SNI = www.microsoft.com（假装去微软）
   - utls 完美复刻 Chrome TLS 指纹
   - ClientHello 扩展里偷偷塞入 X25519 ECDH 鉴权信息

2. 服务器决策
   用 X25519 私钥 + 客户端公钥 ECDH → 解密扩展鉴权信息
   ├ 鉴权通过 → 进入接管模式
   └ 鉴权失败 → 透明转发整个 TCP 连接给真微软

3. 接管模式（鉴权通过）
   服务器自己当 TLS 服务器完成握手
   - 用启动时预取的真微软证书做 ServerHello.Certificate
   - CertificateVerify 随便签（客户端因为是 Reality 模式跳过验证）
   - 身份的真正证明来自 X25519 ECDH（不是证书签名）
   - TLS 握手完成

4. 数据通道
   握手完成后通道里跑 VLESS 协议
   客户端发 [UUID][目标地址][数据]
   服务器解出来 connect() 转发
```

#### 7.2.4 为什么防御能力强

| GFW 攻击手段 | 能不能穿透 Reality |
|---|---|
| SNI 黑名单 | 穿不了（SNI 是微软） |
| TLS 指纹识别 | 穿不了（utls 复刻 Chrome） |
| 证书指纹识别 | 穿不了（用真微软证书） |
| 主动探测 | 穿不了（不带密钥探测会被转给真微软，得到真网页） |
| TLS-in-TLS 检测 | 穿不了（Reality 没有内层 TLS——VLESS 直接跑在派生密钥上） |

#### 7.2.5 Reality 的真实弱点：IP-Domain 一致性问题

Reality 有一个**真实存在的结构性弱点**：客户端连接的真实 IP（你的 VPS IP）跟它声称的 SNI（`www.microsoft.com`）完全没关系。理论上 GFW 可以做这个检查：

```
你的 Reality 服务器:
  IP: 1.2.3.4 (DigitalOcean 美西机房)
  TLS SNI: www.microsoft.com

GFW 一查:
  DNS query "www.microsoft.com" → 返回 [13.107.21.200, 23.46.234.93, ...]
  你的 IP 1.2.3.4 ∉ 上面那个列表
  → SNI 和真实 IP 不匹配 → 矛盾 → 可疑
```

这个攻击叫 **"IP-Domain Consistency Check"**（IP-域名一致性检查），技术上完全可行，做的方式有几种：

1. **离线 DNS 比对**：维护一份"主流域名→真实 IP 段"的映射，每次握手时查表
2. **实时反向 DNS**：握手时实时 PTR 查询 IP 的反向记录
3. **行为对照**：观察这个 IP 上其他流量是不是都"声称是 microsoft.com"

理论上 Reality 在这个检查面前是裸的——SNI 写的是微软，IP 不是微软，没法解释。

##### 为什么这个攻击没让 Reality 立刻完蛋

四个原因：

**原因 1：现代互联网 SNI 和 IP 本来就不严格对应**

20 年前一个网站 = 一个 IP，但现代互联网（CDN/anycast 时代）情况完全不同：

| 情况 | SNI 和 IP 关系 |
|---|---|
| 用 Cloudflare 的网站 | SNI = 客户域名，IP = Cloudflare anycast |
| 用 Akamai 的网站 | SNI = 客户域名，IP = Akamai 边缘 |
| 企业反向代理 | SNI = 公开域名，IP = 内部网关，DNS 根本查不到 |
| 镜像站 | 大公司有多个国家的私有镜像，DNS 不公开 |
| 私有 CDN | 比如 Microsoft 自己的 Azure Front Door |
| 测试/灰度环境 | SNI 是生产域名，IP 是 staging |

**结果**：很多大站用了 CDN/anycast 后，"IP 不在 DNS 列表里但 SNI 是这个站"是**完全正常的现象**——占据了现代互联网 50% 以上的合法流量。

**原因 2：误报代价太高**

```
全国每天 TLS 连接数: 数千亿级
其中走 CDN 的比例: ~50%+
其中"SNI 不在 DNS 列表里"的比例: ~10%+

误报量: 数百亿次/天
被误封的合法网站: 几乎所有用 CDN 的国际站
```

GFW 不能承受这种规模的误报——会引发大规模"为什么访问不了 GitHub/Discord/Stack Overflow"投诉。所以**这种检查不能作为通用一线规则部署**，只能用作**针对已经怀疑的特定可疑 IP 的二次确认**。

**原因 3：dest 选择的经验**

Reality 用户社区已经形成"选什么 dest 不容易被这个攻击杀死"的最佳实践：

推荐 dest 的特点：
- 用 CDN/anycast (Akamai, Cloudflare, Fastly) → IP 池大，"IP 不在 DNS 列表里"是正常现象
- 全球部署的大公司 → 真实 IP 数量多，难以维护完整列表
- 域名长期稳定 → 不会突然换证书或下线
- TLS 1.3 + HTTP/2 都支持 → Reality 必需
- 对源 IP 不敏感 → 任何 IP 来连都能正常握手

社区验证过的"白名单"：
```
gateway.icloud.com    （Apple - Akamai 后端）
www.yahoo.co.jp        （Yahoo Japan - 全球部署）
www.tesla.com          （Tesla - Akamai）
addons.mozilla.org     （Mozilla - CDN）
www.swift.com          （SWIFT 银行系统）
dl.google.com          （Google - 全球 CDN）
```

不推荐的 dest：
- 用单一 IP 的小站（DNS 一查就是固定几个 IP）
- 用自签证书的站（Reality 要真证书）
- TLS 1.2 only 的站
- 经常改证书或重启的小站

**原因 4：流量稀释效应**

即使 dest 是 microsoft.com，全球**真实**有多少 IP 在用 microsoft.com 这个 SNI？

```
microsoft.com 的真实部署:
  - 微软自己的 Azure 数据中心 (数千 IP)
  - Akamai CDN 节点 (数万 IP，给微软做加速)
  - 微软合作伙伴的 CDN
  - 微软私有镜像（不在公开 DNS 里）
  - 企业代理（公司网络中转 microsoft.com 的访问）
  - 测试环境 / 开发环境

真实"声称 SNI=microsoft.com 的 IP"数量: 远超 DNS 公开列表
```

GFW 维护一份**完整准确**的"microsoft.com 真实 IP 集合"在工程上几乎不可能——它每天都在变，企业内网不可见，CDN 边缘节点不公开。

##### 实际部署状况

基于公开信息：

- **2023 年中**：部分 Reality 节点被精准封 IP，有用户分析认为可能是 IP 行为画像检测，但没有证据特指"IP-domain 一致性检查"
- **2024 年**：随机抽查发现 GFW 对某些已经标记为可疑的 IP 做了 SNI 一致性的二次验证——但这是**针对个别可疑 IP**，不是大规模规则
- **没有任何证据**显示 GFW 对所有 TLS 流量做这种检查

实际部署的风险曲线：

```
日 1-30 :    新节点几乎不会被这种攻击发现（流量太小）
月 1-6 :     除非流量异常大，一般检测不到
年 1+ :      长期使用、流量稳定，开始有累积怀疑
被怀疑后 :   GFW 用 SNI/IP 检查二次确认 → 此时这个攻击致命
```

##### 防御策略

| 策略 | 做法 | 代价 |
|---|---|---|
| **选 CDN-fronted dest** | 用 Akamai/Cloudflare 后端的大站 | 推荐，无副作用 |
| **dest 轮换** | 每 3-6 个月换一个不同的大站 | 推荐 |
| **VPS 部署在 dest 同 ASN** | 比如 Azure 上跑代理，IP 在 AS8075 | Azure 流量贵，复杂度高 |
| **域前置（CDN 前置）** | Reality 部署在 Cloudflare 后面 | 失去 Reality 协议精巧机制 |
| **住宅 IP** | 部署在家庭宽带 | 部署复杂，稳定性差 |
| **多 dest 同 IP** | 同一台 VPS 用多个 dest | **不推荐**，反而更可疑 |

##### 这个攻击在 Reality 攻击向量里的优先级

把这个攻击放到 GFW 整个攻击工具包里看：

| 攻击 | 部署成本 | 误报率 | 实际部署可能性 |
|---|---|---|---|
| IP 段封锁（数据中心） | 极低 | 中 | 大规模部署 |
| TLS 指纹识别 | 低 | 低 | 大规模部署 |
| 主动探测 | 中 | 低 | 针对可疑 IP 部署 |
| 流量量级画像 | 中 | 中 | 针对高流量 IP |
| **IP-domain 一致性检查** | **中** | **极高** | **仅对已怀疑 IP 做二次确认** |
| TLS-in-TLS 模式分析 | 高 | 中 | 部分部署 |
| 用户群图谱 | 极高 | 中 | 推测部署 |

**结论**：IP-domain 一致性检查是 GFW 的"杀手锏"，但因为误报太高，它**不会作为通用规则部署**，只在已经怀疑你的时候用来"敲死"判定。所以：

- **新部署的 Reality 节点很少因这个被立刻发现**——通常先经历数月甚至数年的潜伏期
- **直到被其他信号触发怀疑**（流量量级、上下行比、行为时序）→ 这时一致性检查作为二次确认致命一击
- **流量越大、使用强度越高 → 触发怀疑的概率越高 → 这个攻击的命中率越高**

### 7.3 Vision 协议详解

Vision = `xtls-rprx-vision` flow，是 XTLS 协议家族的当家版本，解决 **TLS-in-TLS 检测**问题。

#### 7.3.1 TLS-in-TLS 问题

即使外层 TLS 完美伪装，内层用户的 HTTPS 流量会形成**双层 TLS 嵌套**：

```
应用数据 → 内层 TLS（用户 ↔ google.com）
        → VLESS 帧
        → 外层 TLS（用户 ↔ 代理服务器）
        → TCP
```

GFW 通过外层 TLS 记录的**大小序列**反推出"这里面在跑 TLS 握手"：

```
外层 TLS 记录大小: [517][89][1820][1840][92]...  ← TLS 握手指纹
                  ↑ ClientHello + ServerHello + Cert + ...
```

AEAD 加密只加 16 字节 tag，**不改变明文长度**，所以包大小特征几乎不变。

#### 7.3.2 Vision 的三张牌

**牌 1：握手期填充（Padding）**

在内层 TLS 握手发生时，主动给 VLESS 帧加随机长度的填充字节，让外层 TLS 记录大小分布**不再呈现 TLS 握手特征**：

```
没有 Vision: [517][89][1820][1840][92]   ← 看就是 TLS 握手
有 Vision:   [923][1456][2103][891]      ← 被打散
```

**牌 2：握手完成后切换到 Splice 模式**

Vision 的核心观察：**内层 TLS 已经加密了数据，外层再加密一次是冗余的——只要别让 GFW 看出"这是 TLS-in-TLS"就行**。

```
阶段 1（握手期）: 完整链路 内层TLS+外层TLS 双层加密 + padding
阶段 2（握手完成后）: 切到 Direct/Splice 模式
                     外层 TLS 不再对 application_data 加密
                     只当 TCP 通道用，让内层 TLS 字节直接穿过去
```

效果：
- 不再有 TLS-in-TLS 嵌套加密 → 大小特征消失
- 代理服务器 CPU 减半 → 不用做外层二次加解密
- 实测吞吐量提升 30%+

**牌 3：流量识别**

Vision 内部有个流量识别器，看 VLESS 帧前几个字节是不是内层 TLS ClientHello（`0x16 0x03 0x01/0x03`）：
- 是 → 启用 Vision 优化
- 不是（DNS、明文 HTTP、QUIC 等） → 退回普通 VLESS

### 7.4 当代抗审查协议栈推荐

| 方案 | 抗探测 | 性能 | 部署难度 | 适用 |
|---|---|---|---|---|
| **VLESS + Reality + Vision** | 极强 | 极强 | 中 | 自有 VPS，最强方案 |
| VLESS + WS + TLS + CDN | 强 | 中 | 中 | 有域名+CDN |
| **EdgeTunnel (VLESS+WS over CF)** | 强 | 中 | 极低 | 没 VPS，免费方案 |
| Trojan + WS + TLS | 中 | 中 | 中 | 老牌稳定 |
| Hysteria2 (基于 QUIC) | 强 | 极强 | 中 | 移动设备低延迟 |
| Shadowsocks 2022 | 中 | 强 | 低 | 不推荐裸跑 |

### 7.5 为什么 EdgeTunnel 用不了 Reality 和 Vision

Reality 和 Vision 都需要服务器**直接控制 TLS 握手行为**——拦截 ClientHello、决定接管或转发、精确插入 padding 等。

但 EdgeTunnel 跑在 Cloudflare Workers 上：
- TLS 在 Cloudflare 边缘终结，Worker 拿到的是 HTTP 应用层
- Worker 看不到原始 TLS 握手
- `cloudflare:sockets` 只能做出站连接，不能拦截入站 TLS

所以 **Reality / Vision 和 CDN-fronted 部署在原理上不兼容**。EdgeTunnel 选了另一条路——藏在 Cloudflare 后面（详见第 9 章）。

### 7.6 主要开源仓库

| 项目 | 仓库 | 角色 |
|---|---|---|
| Xray-core | https://github.com/XTLS/Xray-core | Reality + Vision 官方原产实现 |
| REALITY 文档 | https://github.com/XTLS/REALITY | 协议规范 |
| sing-box | https://github.com/SagerNet/sing-box | 第二大实现，跨平台 |
| utls | https://github.com/refraction-networking/utls | TLS 指纹库 |
| GFW Report | https://github.com/net4people/bbs | 监控 GFW 动态 |

**v2ray-core 没有 Reality 和 Vision**——只有 xray-core 和 sing-box 实现了。

---

## 第 8 章 抗审查能力分析

### 8.1 VLESS 协议本身是有特征的

VLESS 帧的固定结构：

```
[版本(1B)] [UUID(16B)] [optLen(1B)] [opt(N)] [cmd(1B)] [port(2B)] [atype(1B)] [addr] [data]
   ↑0x00     ↑随机          ↑常0      ↑空     ↑1或2     ↑大端     ↑1/2/3
```

如果**裸跑**（不套任何东西），GFW 用规则引擎几行代码就能识别：

```python
def is_vless(first_chunk):
    if len(first_chunk) < 22: return False
    if first_chunk[0] != 0x00: return False              # 版本字节
    if first_chunk[17] != 0x00: return False             # optLen
    if first_chunk[18] not in (0x01, 0x02): return False # cmd
    if first_chunk[21] not in (0x01, 0x02, 0x03): return False  # atype
    return True
```

**所以 VLESS 从设计开始就规定必须套 TLS 用**。

### 8.2 不同部署形态的特征暴露程度

| 部署形态 | 特征级别 | 主要软肋 |
|---|---|---|
| VLESS 裸跑（TCP 直发） | 致命 | 几乎所有特征都暴露 |
| VLESS + TLS（自签证书） | 很容易识别 | TLS 指纹 + 证书 + SNI |
| VLESS + WS + TLS + 自有域名 | 中等 | WS 路径 + TLS-in-TLS + 数据中心 IP |
| VLESS + WS + TLS + Cloudflare（**EdgeTunnel**） | 较低 | TLS-in-TLS 仍存在，靠流量稀释 |
| VLESS + Reality + Vision | 接近隐形 | 只剩流量画像、IP 画像等高成本攻击 |

### 8.3 GFW 实际用过的识别手段

基于 GFW Report、Censored Planet 等独立研究的观察：

#### 1. TLS 指纹聚类（已部署）

收集所有 TLS 握手指纹做 JA3/JA4 聚类。Go/Rust 写的代理工具有典型指纹，跟浏览器不重合。
**反制**：utls 库精确复刻浏览器指纹。

#### 2. 主动探测（已部署）

GFW 看到可疑 TLS 连接 → 自己用 SSL 客户端连过去发探测包。
**反制**：Trojan fallback 转 nginx；Reality 转发到真大站。

#### 3. TLS-in-TLS 检测（已部署）

通过外层 TLS 记录的大小序列识别内层 TLS 握手。
**反制**：Vision 的 padding + splice 机制。

#### 4. 包大小+时序的机器学习（部分部署）

学界论文已证明可行，准确率 90%+。
**反制**：multiplexing、流量整形、长连接化。

#### 5. SNI 黑名单（已部署）

直接封某个 SNI。
**反制**：Reality 用大公司 SNI。

#### 6. IP 黑名单 + IP 段封锁（已部署）

封整段数据中心 IP（DigitalOcean、Vultr 等都被大段封过）。
**反制**：CDN 不敢封。

#### 7. 流量模式聚合分析（推测部署）

长期看一个 IP 的流量量级、上下行比、连接数、连接时长。
**反制**：困难，需要降低使用强度、多 IP 分流。

### 8.4 现代抗审查的核心范式转变

```
2010 年代早期思路：
  "让代理流量看起来像随机字节，没有任何模式"
  失败原因：高熵随机字节本身就是特征

2020 年代主流思路：
  "让代理流量看起来像具体的某种合法流量"
  关键转变：不追求"无模式"，追求"具体模仿某种合法模式"
  GFW 想识别就要全封那种合法流量 → 不可承受
```

具体应用：
- Trojan 装作 HTTPS 网站
- Reality 装作访问微软
- EdgeTunnel 装作普通 Cloudflare 用户
- Hysteria 装作 QUIC 视频流

VLESS 在这个新范式里的角色就是"内层负载协议"——它不需要自己"无特征"，需要的是**让外层有东西可以伪装**。所以协议越简单越好。

### 8.5 VLESS+Reality+Vision 当前能否被破

#### 实际记录

截至 2025 年初的公开信息：
- 没有 Reality 协议被破解的公开案例
- 部分用户报告 VPS 节点被封——几乎都是 IP 行为画像或配置错误，不是协议被破
- GFW 部署过对特定 utls 版本指纹的针对性识别——utls 团队 24 小时内更新

#### 已知的弱点

1. **ClientHello 重放攻击**：GFW 录下合法客户端的 ClientHello 实时重放 → 能骗过鉴权（中等风险，新版有抗重放机制）
2. **dest 行为不一致**：你的 VPS IP 上"声称是 microsoft.com"但实际不在微软 DNS 列表里 → 理论上 GFW 能查（高风险，但全网执行成本巨大）
3. **utls 指纹滞后**：客户端 utls 版本过旧 → 反而成"过时浏览器"标志（高风险，常见攻击）
4. **流量量级统计**：你 IP 上"全去微软"但流量是真访问的 N 倍（高风险，针对高强度用户）
5. **用户群图谱**：可疑用户都连过你的 IP → 反推可疑（极高风险，几乎无解）

#### 真实的破口

实际"被破"的几乎都是：

| 真实破因 | 占比（凭感觉） |
|---|---|
| 用户配置错误（shortId、dest 选错、密码弱） | 40% |
| utls 指纹版本过时 | 20% |
| 流量画像 / IP 行为异常 | 20% |
| IP 段封锁（暴力） | 15% |
| 协议本身被精准识别 | < 5% |

**协议层是最坚固的，反而是用户使用层面最容易出问题**。

---

## 第 9 章 为什么 EdgeTunnel 行得通

理论上 EdgeTunnel 在 TLS-in-TLS、VLESS 协议特征、流量画像各方面都是有弱点的。但它实际能用的核心原因只有一个：

> **它把整个 Cloudflare 当成自己的伪装外壳——而 Cloudflare 大到 GFW 不敢封**。

### 9.1 核心：Cloudflare 是 too big to block

#### Cloudflare 的规模

- 每天处理 ~50 万亿次请求
- 覆盖 ~20% 全球互联网流量
- 数千万域名挂在它后面：GitHub、Discord、Reddit、Trustpilot、各国政府网站、医疗、金融...

#### 全面封锁 Cloudflare 的代价

- 国内访问 GitHub、Discord、Reddit、Stack Exchange 等大量服务受影响
- 大量国内企业的海外业务受影响
- 几百万海外华人用户被反向 GFW

**封 Cloudflare 的政治和经济代价大到不可承受**。

#### 历史佐证

- **2014 年 7 月**：GFW 短暂封过 Cloudflare 大段 IP，引发抗议，几天后解封
- **2020-2024 年**：偶尔个别 IP 段被针对，从未持续大规模封锁
- 形成了 GFW 跟 Cloudflare 之间**心照不宣的平衡**

### 9.2 EdgeTunnel 借了 Cloudflare 哪些身份

#### 借 IP 池

```
传统 VPS:
  IP: 123.45.67.89 (DigitalOcean 数据中心)
  GFW: "数据中心？多半是代理" → 直接封 IP 段

EdgeTunnel:
  IP: 104.21.x.x (Cloudflare 边缘)
  GFW: "Cloudflare？亿万站点用的，封不起" → 不能动
```

#### 借 TLS 证书

```
传统 + Let's Encrypt:
  证书: 小域名、申请 < 1 个月、用户极少 → 可疑

EdgeTunnel:
  证书: Cloudflare 的 CA 链
  → 跟数千万 Cloudflare 站点共用同一套证书生态
```

#### 借 TLS 指纹

```
传统 Trojan/VLESS+TLS:
  TLS 指纹: 自己 nginx/caddy 版本特定
  → 跟浏览器有微妙差别，可疑

EdgeTunnel:
  TLS 指纹: Cloudflare 自身（基于 BoringSSL）
  → 跟数百万真实站点共用 → 完美隐身
  → JA3/JA4 = 几乎所有 Cloudflare 站点共有
```

这是 Reality 想达到但还没完全做到的效果——Reality 要追着 Chrome 升级 utls，但 Cloudflare 的指纹**就是它本身在用的指纹**，永远跟它服务的所有真站点完全一致。

#### 借 SNI 海洋

```
传统:
  SNI: vpn.mydomain.com
  GFW: "没听过、没流量、刚注册" → 加入观察名单

EdgeTunnel:
  SNI: yourname.pages.dev 或 your-custom.com
  GFW: "数千万这种域名，看不过来" → 大概率忽略
```

GFW 当然可以建立 Cloudflare 域名画像，但成本巨大——数千万域名要逐个画像。

### 9.3 GFW 的成本-收益账本

| 方案 | 技术可行性 | 附带损害 | GFW 决策 |
|---|---|---|---|
| 封整个 Cloudflare IP 段 | 简单 | 砍掉 ~20% 海外服务 | 不可承受 |
| 封 `*.workers.dev` `*.pages.dev` | 可行 | 影响合法 CF 用户 | 太粗糙 |
| 被动 TLS 流量画像分类 | 学界已证 | 需要海量算力 | 部分采用 |
| 针对单个 Worker 域名画像 | 可行 | 用户换一个就失效 | 偶尔 |
| 主动探测每个 Worker 域名 | 可行但慢 | 探测百万域名 = 巨大算力 | 成本太高 |
| 限速 Cloudflare（不封） | 已部署 | 影响合法用户体验 | 在用 |

**最终现状**：GFW 选择了**限速 + 偶尔针对个别热门域名**这种中等强度策略。

### 9.4 跟 Reality 部署模型的对比

```
Reality 哲学：
   "我一个人，藏在大牌的影子里，做到完美不可区分"
   → 借真大站的证书、指纹、SNI
   → 主动探测会被转给真大站
   → 单点完美伪装

   适合：高强度个人用户、专业人士
   缺点：要 VPS、要懂配置、要持续维护

EdgeTunnel 哲学：
   "千千万万个人，一起藏在一棵大树后面，靠数量稀释危险"
   → 全部借 Cloudflare 的身份
   → 单个用户没那么完美，但跟亿万真实站点混在一起
   → 群体伪装

   适合：普通用户、零部署成本
   缺点：单个用户被重点盯上时防御弱
```

详细对比：

| 维度 | **VLESS+Reality+Vision** | **EdgeTunnel (VLESS+WS+CF)** |
|---|---|---|
| 伪装策略 | 借特定大站身份 | 借整个 Cloudflare 网络 |
| TLS 指纹 | utls 复刻 Chrome（要追版本） | Cloudflare 自身指纹（永远最新） |
| **IP-SNI 一致性** | **不一致**（VPS IP ≠ dest 真实 IP） | **完全一致**（IP 和 SNI 都是 CF 的） |
| TLS-in-TLS 防御 | Vision padding | Cloudflare 流量稀释 |
| 主动探测防御 | 转发到真大站 | 主路由返回伪装页 |
| 流量画像防御 | 限速 + 多 IP 分流 | 多 Worker 域名分散 |
| 部署难度 | 中（VPS + 配置） | 低（一键部署） |
| 持续维护 | 客户端要追 utls 版本 | 几乎不用维护 |
| 被精准盯上时 | 协议层防御强 | 协议层防御弱 |
| 大规模流量时 | 单 IP 容易被画像 | 海量 CF 用户分摊 |

**两者各有优劣，互为补充**：
- 一般用户用 EdgeTunnel 就够了
- 高需求用户上 Reality+Vision
- 对抗最严格审查时两者都会失效——需要 Tor、住宅 IP

#### 9.4.1 IP-SNI 一致性差异（呼应 7.2.5）

把 7.2.5 节讨论的 Reality "IP-Domain 一致性问题"放到这里对比，能看出两种部署模型的根本差异：

```
传统 Reality 部署的"借身份"模型：
  IP: 你的 VPS 数据中心 IP
  SNI: www.microsoft.com (借的身份)
  → 矛盾点：IP 和 SNI 不一致
  → 防御：依赖 GFW 不大规模部署一致性检查
        + 选 CDN-fronted dest 让矛盾不那么明显
        + 多 dest 轮换分散

EdgeTunnel 的"借平台"模型：
  IP: Cloudflare 边缘 IP
  SNI: 你的 Cloudflare 域名
  → 完全一致：DNS 查的就是这个 IP
  → 防御：根本没这个问题
  → 代价：失去 Reality 协议的精巧机制（Worker 拿不到原始 TLS）
```

具体看 GFW 检查 EdgeTunnel 的过程：

```
你的部署:
  Worker 域名: yourname.workers.dev (或自定义域)
  IP: 104.21.x.x (Cloudflare 边缘)
  SNI: yourname.workers.dev

GFW 查:
  DNS yourname.workers.dev → 104.21.x.x ✅ 一致
  IP 104.21.x.x → ASN 是 Cloudflare AS13335 → 跟数千万站点共享 ✅ 正常
```

**EdgeTunnel 的 SNI 和 IP 完全一致**——没有 Reality 那种"假装是另一个站点"的矛盾。所以 7.2.5 节描述的 IP-Domain 一致性检查攻击对 EdgeTunnel **完全无效**——它不需要装作是 microsoft.com，它就是个普通 Cloudflare Worker，和数千万其他 Workers 一样。

这是 EdgeTunnel 模型的一个意想不到的优势：**它不需要做"借大牌身份"的把戏，因为它真的就是 Cloudflare 自己**。代价是失去了 Reality 协议直接拿到 TLS ClientHello 的能力（Worker 在 Cloudflare 解 TLS 之后才拿到 HTTP 应用层），所以 Vision 这种 TLS-in-TLS 整形也用不了。

两种模型在面对 IP-Domain 一致性这个特定攻击时的根本差异：

| 对比点 | Reality 模型 | EdgeTunnel 模型 |
|---|---|---|
| 是否需要"装"成别人 | 是（dest 模仿） | 否（就是 CF 自己） |
| IP 和 SNI 是否一致 | 否 | 是 |
| 长期使用累积怀疑后致命攻击 | IP-Domain 检查二次确认 | 没有这个特定攻击面 |
| 防御复杂度 | 选 dest + 轮换 + 限流 | 几乎不用考虑 |
| 协议层精巧程度 | 高（X25519 + 借证书） | 低（普通 VLESS+WS） |

### 9.5 EdgeTunnel 的具体设计如何配合"借 CF"

#### 1. 用 WebSocket 而不是 gRPC 主推

WS 是 Cloudflare 上最常见的长连接技术——直播、聊天、协作编辑、IDE、Cloudflare Tunnels 自己都用。
你的 WS 流量混在数千万合法 WS 应用里，单独识别成本极高。

#### 2. 主路径返回 nginx 伪装页

不带正确鉴权的请求全部走伪装页（`_worker.js:434-461`）——主动探测者看到的是普通 nginx 站点。
**用 EdgeTunnel 的"主路由"做了 Trojan fallback 的事情**。

#### 3. UUID 从 ADMIN 派生

```js
const userID = MD5(管理员密码 + KEY);
```

不同部署者的 UUID 几乎不会重复——GFW 不能用扫描已知 UUID 来主动探测。

#### 4. 多协议支持但默认 VLESS

支持 VLESS / Trojan / SS 三种是最大化客户端兼容性。默认 VLESS 因为帧最小、混在 WS 里更难发现。

#### 5. ProxyIP 兜底机制

利用 Cloudflare 自己提供的 colo 信息选择就近代理 IP——让出站行为也借 Cloudflare 网络拓扑。

#### 6. BYOB 优化

减少 CPU 占用 → 单个 Worker 能承载更多用户 → 单个 Worker 域名的"代理特征"被合法流量稀释更彻底。

### 9.6 EdgeTunnel 的真实弱点

#### 1. TLS-in-TLS 模式仍然存在

没有 Vision，单条流量的大小序列还是有"TLS 嵌 TLS"特征。**靠 Cloudflare 流量稀释规避，不是真的解决**。

#### 2. 高强度用户会被画像

如果一个 Worker 域名每天跑 100GB+ 流量、24/7 不停，**单独画像识别还是可能的**。EdgeTunnel 适合**轻中度使用**。

#### 3. Cloudflare ToS 风险

Cloudflare Workers 的服务条款**禁止用作 VPN/代理服务**。理论上 Cloudflare 可以根据 Worker 内代码或流量模式封号。已有用户因此被封号的报告。

#### 4. 高敏感时期可能受影响

特殊时期 GFW 可能对 Cloudflare 加重限制——这时候 EdgeTunnel 会**短期内不可用**，但通常不会被永久封死。

#### 5. 不能做最敏感的通信

如果你做的事情真的会引起国家级关注（新闻调查、敏感抗议），EdgeTunnel 不够——那种场景需要 Tor + 桥接节点 + 住宅出口 IP 的组合方案。

### 9.7 行得通的四个支柱

```
                 ┌──────────────────────────┐
                 │     EdgeTunnel 可用性      │
                 └──────────────────────────┘
                            │
       ┌────────────────────┼────────────────────┐
       │                    │                    │
┌──────▼───────┐  ┌────────▼────────┐  ┌────────▼────────┐
│ 支柱 1:      │  │ 支柱 2:          │  │ 支柱 3:          │
│ Cloudflare 大│  │ 共享 CF 身份     │  │ 用户分散         │
│ 到不能封     │  │ (IP/证书/指纹/   │  │ (海量 Worker 域名│
│              │  │  SNI 全借 CF)    │  │  稀释画像)       │
└──────────────┘  └──────────────────┘  └──────────────────┘
                            │
                  ┌─────────▼─────────┐
                  │ 支柱 4:           │
                  │ Worker 路由设计   │
                  │ (WS/伪装页/       │
                  │  鉴权门槛)         │
                  └────────────────────┘
```

**四个支柱里 ⅔ 不是 EdgeTunnel 自己的功劳**——是 Cloudflare 的。它只是把这些资源用到极致。

---

## 第 10 章 总结与思考

### 10.1 EdgeTunnel 的核心哲学

EdgeTunnel 跟 Reality 走的是两条完全不同哲学的抗审查路径：

- **Reality 是个精巧的协议**——用密码学和工程技巧达到"借大站身份"的效果
- **EdgeTunnel 是个精巧的部署模式**——用普通协议（VLESS）跑在非常特殊的平台（Cloudflare）上，让平台本身成为伪装

两条路不是互斥的，是互补的——**EdgeTunnel 解决了"零成本、零运维、低强度日常使用"场景，Reality 解决了"专业部署、对抗最严格审查"场景**。

### 10.2 项目中几个值得关注的设计细节

#### 1. 协议解耦的扩展性

VLESS 帧的 `version` 字段 + `optLen + opt` 扩展字段是它能持续吸收 XTLS / Vision / Reality 等新功能的根本原因。Trojan 没有这种扩展点，所以演进基本停滞。

EdgeTunnel 用 VLESS 而不是 Trojan 作为默认协议，间接享受到了这种扩展性的好处——未来如果要支持新功能，VLESS 这条路不会被卡死。

#### 2. 反爬虫伪装

代码 `_worker.js:10` 那段超长的多语言"This JavaScript file is part of a legitimate, private..."注释、变量名 `魏烈思` / `木马`、`'vl'+'ess'` 字符串拼接、`'c'+'on'+'nect'` 之类的拆分，都是为了**绕过静态扫描**——尤其是 Cloudflare 自己的代码扫描和某些自动化封号工具。

#### 3. 控制面与数据面共域名

- 同一个域名同时承担代理流量和管理面板
- 管理面板 cookie 鉴权（`auth = MD5(UA + KEY + ADMIN)`），HttpOnly + Secure + SameSite=Strict
- `/sub` 订阅 token 是 `MD5(host + userID)`，不直接暴露 UUID
- 不带正确凭据的请求统一走伪装页

#### 4. 不依赖外部库

整个 4619 行单文件、零 npm 依赖。这种设计：
- 部署极简（粘贴一个文件就行）
- 无供应链攻击风险
- 但代价是大量手写代码（包括完整 TLS 客户端、ChaCha20-Poly1305、SHA-224 等）

### 10.3 修改/部署时的注意事项

#### 1. 单文件就是工作流

所有逻辑都在 `_worker.js`——没有构建步骤，编辑这个文件 = 工作流的全部。

#### 2. 标识符是中文

函数名 `处理WS请求`、`读取XHTTP首包`、`连接直连` 等。**搜索时用中文字符串，不是英文**。

#### 3. 没有测试套件

验证方法是"部署后试用"。没有 `package.json`、没有 jest、没有 vitest。

#### 4. 自定义加密代码不要随便重构

ChaCha20-Poly1305、TLS 1.2/1.3 客户端、MD5/SHA-224/HMAC/AES-GCM 等手写实现是**载重代码**，密码学敏感，不要做"看起来更优雅"的重构。

#### 5. 管理面板 UI 在另一个仓库

`https://edt-pages.github.io` 是 UI 仓库。如果管理面板看起来坏了但 Worker 代码正常，去那个仓库找问题。

#### 6. 上游同步陷阱

`.github/workflows/sync.yml` 每天定时从 `cmliu/edgetunnel` 拉取主分支。**如果在自己的 fork 上直接改 `_worker.js`，会和上游同步冲突**。要么 disable 这个 workflow，要么基于上游 rebase 维护 patch。

### 10.4 端到端验证

部署后可以用以下方式验证：

```bash
# 1. 版本接口
curl https://<domain>/version?uuid=<uuid>
# 期望：返回 JSON { Version: <数字> }

# 2. 伪装页
curl https://<domain>/
# 期望：返回 nginx 欢迎页 HTML

# 3. 登录
# 浏览器访问 https://<domain>/login
# 输入 ADMIN 密码 → 跳转到 /admin 管理面板

# 4. 订阅
curl "https://<domain>/sub?token=<MD5(host+userID)>"
# 期望：返回各种格式的订阅链接（Clash YAML、VLESS URL 等）

# 5. 实际代理流量
# 把订阅 URL 导入 Clash/Sing-box，连接后访问任意网站
```

### 10.5 一句话总结

**EdgeTunnel 是个精巧的工程作品**——它用一个普通的代理协议（VLESS）+ 一个标准的传输（WebSocket）+ 一个特殊的运行平台（Cloudflare Workers），通过把伪装责任完全外包给 Cloudflare 这个"too big to block"的 CDN 巨头，做到了"零成本、零运维、足够好"的抗审查效果。

它不是抗审查能力的天花板——那是 VLESS+Reality+Vision 的位置——但它是**普及性的天花板**：任何人 5 分钟就能部署一份自己的，不需要 VPS、不需要域名、不需要技术背景。

**它的安全边界完全取决于 Cloudflare 自己的政策稳定性**——只要 GFW 不全面封 CF、Cloudflare 不主动清理代理用户，这条路就能走。这恰恰是它的优势（无需自己维护伪装），也是它的脆弱点（完全依赖第三方）。

抗审查领域没有银弹——它本质是一场持续的工程对抗。EdgeTunnel 是这场对抗里"低成本群体伪装"流派的代表作品。

---

## 附录：关键代码位置速查

| 功能 | 文件位置 |
|---|---|
| 主入口 fetch handler | `_worker.js:11` |
| WS 处理 | `_worker.js:995` |
| gRPC 处理 | `_worker.js:765` |
| XHTTP 处理 | `_worker.js:461` |
| VLESS 解析（XHTTP 路径） | `_worker.js:609-663` |
| VLESS 解析（WS 路径） | `_worker.js:1480-1514` |
| Trojan 解析 | `_worker.js:666-724` |
| Shadowsocks AEAD 处理 | `_worker.js:1104-1257` |
| SS 加密配置表 | `_worker.js:1516-1519` |
| WS 字节模式嗅探 | `_worker.js:1354-1361` |
| XHTTP 缓冲式协议探测 | `_worker.js:606-763` |
| 直连出站 | `_worker.js:1682` |
| SOCKS5 客户端 | `_worker.js:1984` |
| HTTP CONNECT 隧道 | `_worker.js:2020` |
| ChaCha20 / Poly1305 / AEAD | `_worker.js:2236-2323` |
| AES-GCM (Web Crypto) | `_worker.js:2227-2231` |
| TLS Client 类 | `_worker.js:2486` |
| TLS 1.3 握手 | `_worker.js:2623` |
| TLS 1.2 握手 | `_worker.js:2562` |
| BYOB 流式优化 | `_worker.js:1851-1854` |
| ProxyIP 选择 | `_worker.js:26-30` |
| MD5 派生 UUID | `_worker.js:18-21` |
| formatIdentifier (UUID 格式化) | `_worker.js:1840-1843` |
| 订阅生成器 | `_worker.js:266-415` |
| 管理面板路由 | `_worker.js:74+` |
| nginx 伪装页 | `_worker.js:4501-4526` |
| sha224 手写实现 | `_worker.js:4367` |
