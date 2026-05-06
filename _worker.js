// Built from src/ - DO NOT EDIT directly. Edit source files in src/ instead.

// src/crypto/md5.ts
async function md5x2(text) {
  const encoder = new TextEncoder();
  const firstHash = await crypto.subtle.digest("MD5", encoder.encode(text));
  const firstHex = Array.from(new Uint8Array(firstHash)).map((byte) => byte.toString(16).padStart(2, "0")).join("");
  const secondHash = await crypto.subtle.digest(
    "MD5",
    encoder.encode(firstHex.slice(7, 27))
  );
  const secondHex = Array.from(new Uint8Array(secondHash)).map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return secondHex.toLowerCase();
}
function formatUuid(arr, offset = 0) {
  const hex = [...arr.slice(offset, offset + 16)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}

// src/utils/url.ts
function normalizeRequestUrl(rawUrl) {
  let url = rawUrl.replace(/%5[Cc]/g, "").replace(/\\/g, "");
  const fragmentIndex = url.indexOf("#");
  const body = fragmentIndex === -1 ? url : url.slice(0, fragmentIndex);
  if (body.includes("?") || !/%3f/i.test(body)) return url;
  const fragment = fragmentIndex === -1 ? "" : url.slice(fragmentIndex);
  return body.replace(/%3f/i, "?") + fragment;
}
function toArray(content) {
  let cleaned = content.replace(/[\t"'\r\n]+/g, ",").replace(/,+/g, ",");
  if (cleaned.charAt(0) === ",") cleaned = cleaned.slice(1);
  if (cleaned.charAt(cleaned.length - 1) === ",")
    cleaned = cleaned.slice(0, cleaned.length - 1);
  return cleaned.split(",");
}

// src/state.ts
function createDefaultContext() {
  return {
    proxyIP: "",
    socks5Mode: null,
    socks5GlobalEnabled: false,
    socks5Auth: "",
    parsedSocks5: { hostname: "", port: 0 },
    socks5Whitelist: [
      "*tapecontent.net",
      "*cloudatacdn.com",
      "*loadshare.org",
      "*cdn-centaurus.com",
      "scholar.google.com"
    ],
    proxyFallbackEnabled: true,
    cachedProxyIP: null,
    cachedProxyArray: null,
    cachedProxyIndex: 0,
    debugLogEnabled: false,
    configJson: null
  };
}

// src/utils/logger.ts
function makeLogger(ctx) {
  return (...args) => {
    if (ctx.debugLogEnabled) console.log(...args);
  };
}

// src/constants.ts
var PAGES_STATIC_URL = "https://edt-pages.github.io";
var TLS_VERSION_10 = 769;
var TLS_VERSION_12 = 771;
var TLS_VERSION_13 = 772;
var CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20;
var CONTENT_TYPE_ALERT = 21;
var CONTENT_TYPE_HANDSHAKE = 22;
var CONTENT_TYPE_APPLICATION_DATA = 23;
var HANDSHAKE_TYPE_CLIENT_HELLO = 1;
var HANDSHAKE_TYPE_SERVER_HELLO = 2;
var HANDSHAKE_TYPE_NEW_SESSION_TICKET = 4;
var HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS = 8;
var HANDSHAKE_TYPE_CERTIFICATE = 11;
var HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 12;
var HANDSHAKE_TYPE_CERTIFICATE_REQUEST = 13;
var HANDSHAKE_TYPE_SERVER_HELLO_DONE = 14;
var HANDSHAKE_TYPE_CERTIFICATE_VERIFY = 15;
var HANDSHAKE_TYPE_FINISHED = 20;
var HANDSHAKE_TYPE_KEY_UPDATE = 24;
var EXT_SERVER_NAME = 0;
var EXT_SUPPORTED_GROUPS = 10;
var EXT_EC_POINT_FORMATS = 11;
var EXT_SIGNATURE_ALGORITHMS = 13;
var EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16;
var EXT_SUPPORTED_VERSIONS = 43;
var EXT_PSK_KEY_EXCHANGE_MODES = 45;
var EXT_KEY_SHARE = 51;
var ALERT_CLOSE_NOTIFY = 0;
var ALERT_LEVEL_WARNING = 1;
var ALERT_UNRECOGNIZED_NAME = 112;
var TLS_MAX_PLAINTEXT_FRAGMENT = 16 * 1024;
var CIPHER_SUITES_BY_ID = /* @__PURE__ */ new Map([
  // TLS 1.3 suites
  [4865, { id: 4865, keyLen: 16, ivLen: 12, hash: "SHA-256", tls13: true }],
  // TLS_AES_128_GCM_SHA256
  [4866, { id: 4866, keyLen: 32, ivLen: 12, hash: "SHA-384", tls13: true }],
  // TLS_AES_256_GCM_SHA384
  [4867, { id: 4867, keyLen: 32, ivLen: 12, hash: "SHA-256", tls13: true, chacha: true }],
  // TLS_CHACHA20_POLY1305_SHA256
  // TLS 1.2 ECDHE-RSA suites
  [49199, { id: 49199, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE" }],
  [49200, { id: 49200, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE" }],
  [52392, { id: 52392, keyLen: 32, ivLen: 12, hash: "SHA-256", kex: "ECDHE", chacha: true }],
  // TLS 1.2 ECDHE-ECDSA suites
  [49195, { id: 49195, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE" }],
  [49196, { id: 49196, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE" }],
  [52393, { id: 52393, keyLen: 32, ivLen: 12, hash: "SHA-256", kex: "ECDHE", chacha: true }]
]);
var GROUPS_BY_ID = /* @__PURE__ */ new Map([
  [29, "X25519"],
  [23, "P-256"]
]);
var SUPPORTED_SIGNATURE_ALGORITHMS = [
  2052,
  2053,
  2054,
  1025,
  1281,
  1537,
  1027,
  1283,
  1539
];
var SS_CIPHERS = {
  "aes-128-gcm": {
    method: "aes-128-gcm",
    keyLen: 16,
    saltLen: 16,
    maxChunk: 16383,
    aesLength: 128
  },
  "aes-256-gcm": {
    method: "aes-256-gcm",
    keyLen: 32,
    saltLen: 32,
    maxChunk: 16383,
    aesLength: 256
  }
};
var SS_AEAD_TAG_LENGTH = 16;
var SS_NONCE_LENGTH = 12;
var SS_SUBKEY_INFO = new TextEncoder().encode("ss-subkey");

// src/handlers/login.ts
async function handleLogin(request, ua, adminPassword, encryptKey) {
  const cookies = request.headers.get("Cookie") || "";
  const authCookie = cookies.split(";").find((c) => c.trim().startsWith("auth="))?.split("=")[1];
  const expectedCookie = await md5x2(ua + encryptKey + adminPassword);
  if (authCookie == expectedCookie) {
    return new Response("Redirecting...", {
      status: 302,
      headers: { Location: "/admin" }
    });
  }
  if (request.method === "POST") {
    const formData = await request.text();
    const params = new URLSearchParams(formData);
    const inputPassword = params.get("password");
    if (inputPassword === adminPassword) {
      const response = new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: { "Content-Type": "application/json;charset=utf-8" }
      });
      response.headers.set(
        "Set-Cookie",
        `auth=${expectedCookie}; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Strict`
      );
      return response;
    }
  }
  return fetch(PAGES_STATIC_URL + "/login");
}
async function verifyAuthCookie(request, ua, adminPassword, encryptKey) {
  const cookies = request.headers.get("Cookie") || "";
  const authCookie = cookies.split(";").find((c) => c.trim().startsWith("auth="))?.split("=")[1];
  if (!authCookie) return false;
  const expected = await md5x2(ua + encryptKey + adminPassword);
  return authCookie === expected;
}

// src/utils/log.ts
function maskSensitive(text, prefixLen = 3, suffixLen = 2) {
  if (!text || typeof text !== "string") return text;
  if (text.length <= prefixLen + suffixLen) return text;
  const prefix = text.slice(0, prefixLen);
  const suffix = text.slice(-suffixLen);
  const stars = text.length - prefixLen - suffixLen;
  return `${prefix}${"*".repeat(stars)}${suffix}`;
}
var KV_SIZE_LIMIT_MB = 4;
async function logRequest(env, request, accessIP, requestType = "Get_SUB", configJson, writeToKV = true) {
  try {
    const now = /* @__PURE__ */ new Date();
    const entry = {
      TYPE: requestType,
      IP: accessIP,
      ASN: `AS${request.cf?.asn || "0"} ${request.cf?.asOrganization || "Unknown"}`,
      CC: `${request.cf?.country || "N/A"} ${request.cf?.city || "N/A"}`,
      URL: request.url,
      UA: request.headers.get("User-Agent") || "Unknown",
      TIME: now.getTime()
    };
    if (configJson.TG?.enabled) {
      try {
        const tgText = await env.KV.get("tg.json");
        const tgJson = tgText ? JSON.parse(tgText) : null;
        if (tgJson?.BotToken && tgJson?.ChatID) {
          const requestTime = new Date(entry.TIME).toLocaleString("zh-CN", {
            timeZone: "Asia/Shanghai"
          });
          const requestUrl = new URL(entry.URL);
          const subname = configJson["preferredSub"]?.SUBNAME || "";
          const usage = configJson.CF?.Usage;
          const usageLine = usage?.success ? `\u{1F4CA} <b>\u8BF7\u6C42\u7528\u91CF\uFF1A</b>${usage.total}/${usage.max} <b>${((usage.total || 0) / (usage.max || 1) * 100).toFixed(2)}%</b>
` : "";
          const msg = `<b>#${subname} \u65E5\u5FD7\u901A\u77E5</b>

\u{1F4CC} <b>\u7C7B\u578B\uFF1A</b>#${entry.TYPE}
\u{1F310} <b>IP\uFF1A</b><code>${entry.IP}</code>
\u{1F4CD} <b>\u4F4D\u7F6E\uFF1A</b>${entry.CC}
\u{1F3E2} <b>ASN\uFF1A</b>${entry.ASN}
\u{1F517} <b>\u57DF\u540D\uFF1A</b><code>${requestUrl.host}</code>
\u{1F50D} <b>\u8DEF\u5F84\uFF1A</b><code>${requestUrl.pathname + requestUrl.search}</code>
\u{1F916} <b>UA\uFF1A</b><code>${entry.UA}</code>
\u{1F4C5} <b>\u65F6\u95F4\uFF1A</b>${requestTime}
` + usageLine;
          await fetch(
            `https://api.telegram.org/bot${tgJson.BotToken}/sendMessage?chat_id=${tgJson.ChatID}&parse_mode=HTML&text=${encodeURIComponent(msg)}`,
            {
              method: "GET",
              headers: {
                Accept: "text/html,application/xhtml+xml,application/xml;",
                "Accept-Encoding": "gzip, deflate, br",
                "User-Agent": entry.UA || "Unknown"
              }
            }
          );
        }
      } catch (error) {
        console.error(`tg.json error: ${error.message}`);
      }
    }
    const finalWriteToKV = ["1", "true"].includes(env.OFF_LOG || "") ? false : writeToKV;
    if (!finalWriteToKV) return;
    let logArray = [];
    const existing = await env.KV.get("log.json");
    if (existing) {
      try {
        logArray = JSON.parse(existing);
        if (!Array.isArray(logArray)) {
          logArray = [entry];
        } else if (requestType !== "Get_SUB") {
          const thirtyMinAgo = now.getTime() - 30 * 60 * 1e3;
          const dup = logArray.some(
            (l) => l.TYPE !== "Get_SUB" && l.IP === accessIP && l.URL === request.url && l.UA === entry.UA && l.TIME >= thirtyMinAgo
          );
          if (dup) return;
          logArray.push(entry);
          while (JSON.stringify(logArray, null, 2).length > KV_SIZE_LIMIT_MB * 1024 * 1024 && logArray.length > 0) {
            logArray.shift();
          }
        } else {
          logArray.push(entry);
          while (JSON.stringify(logArray, null, 2).length > KV_SIZE_LIMIT_MB * 1024 * 1024 && logArray.length > 0) {
            logArray.shift();
          }
        }
      } catch (e) {
        logArray = [entry];
      }
    } else {
      logArray = [entry];
    }
    await env.KV.put("log.json", JSON.stringify(logArray, null, 2));
  } catch (error) {
    console.error(`logRequest failed: ${error.message}`);
  }
}

// src/admin/cloudflare-api.ts
var CF_API_BASE = "https://api.cloudflare.com/client/v4";
var FREE_TIER_LIMIT = 1e5;
var sumRequests = (groups) => groups?.reduce((total, item) => total + (item?.sum?.requests || 0), 0) || 0;
async function getCloudflareUsage(email, globalApiKey, accountId, apiToken, log = () => {
}) {
  const baseHeaders = { "Content-Type": "application/json" };
  const fallback = () => ({
    success: false,
    pages: 0,
    workers: 0,
    total: 0,
    max: FREE_TIER_LIMIT
  });
  try {
    if (!accountId && (!email || !globalApiKey)) return fallback();
    if (!accountId) {
      const r = await fetch(`${CF_API_BASE}/accounts`, {
        method: "GET",
        headers: { ...baseHeaders, "X-AUTH-EMAIL": email, "X-AUTH-KEY": globalApiKey }
      });
      if (!r.ok) throw new Error(`account fetch failed: ${r.status}`);
      const d = await r.json();
      if (!d?.result?.length) throw new Error("No accounts found");
      const idx = d.result.findIndex(
        (a) => a.name?.toLowerCase().startsWith(email.toLowerCase())
      );
      accountId = d.result[idx >= 0 ? idx : 0]?.id;
    }
    const startOfDay = /* @__PURE__ */ new Date();
    startOfDay.setUTCHours(0, 0, 0, 0);
    const authHeaders = apiToken ? { ...baseHeaders, Authorization: `Bearer ${apiToken}` } : { ...baseHeaders, "X-AUTH-EMAIL": email, "X-AUTH-KEY": globalApiKey };
    const res = await fetch(`${CF_API_BASE}/graphql`, {
      method: "POST",
      headers: authHeaders,
      body: JSON.stringify({
        query: `query getBillingMetrics($AccountID: String!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) {
          viewer { accounts(filter: {accountTag: $AccountID}) {
            pagesFunctionsInvocationsAdaptiveGroups(limit: 1000, filter: $filter) { sum { requests } }
            workersInvocationsAdaptive(limit: 10000, filter: $filter) { sum { requests } }
          } }
        }`,
        variables: {
          AccountID: accountId,
          filter: {
            datetime_geq: startOfDay.toISOString(),
            datetime_leq: (/* @__PURE__ */ new Date()).toISOString()
          }
        }
      })
    });
    if (!res.ok) throw new Error(`query failed: ${res.status}`);
    const result = await res.json();
    if (result.errors?.length) throw new Error(result.errors[0].message);
    const acc = result?.data?.viewer?.accounts?.[0];
    if (!acc) throw new Error("No account data");
    const pages = sumRequests(acc.pagesFunctionsInvocationsAdaptiveGroups);
    const workers = sumRequests(acc.workersInvocationsAdaptive);
    const total = pages + workers;
    log(`Cloudflare usage: pages=${pages}, workers=${workers}, total=${total}, max=${FREE_TIER_LIMIT}`);
    return { success: true, pages, workers, total, max: FREE_TIER_LIMIT };
  } catch (error) {
    console.error("getCloudflareUsage error:", error.message);
    return fallback();
  }
}

// src/utils/path.ts
var COMMON_PATH_SEGMENTS = [
  "about",
  "account",
  "acg",
  "act",
  "activity",
  "ad",
  "ads",
  "ajax",
  "album",
  "albums",
  "anime",
  "api",
  "app",
  "apps",
  "archive",
  "archives",
  "article",
  "articles",
  "ask",
  "auth",
  "avatar",
  "bbs",
  "bd",
  "blog",
  "blogs",
  "book",
  "books",
  "bt",
  "buy",
  "cart",
  "category",
  "categories",
  "cb",
  "channel",
  "channels",
  "chat",
  "china",
  "city",
  "class",
  "classify",
  "clip",
  "clips",
  "club",
  "cn",
  "code",
  "collect",
  "collection",
  "comic",
  "comics",
  "community",
  "company",
  "config",
  "contact",
  "content",
  "course",
  "courses",
  "cp",
  "data",
  "detail",
  "details",
  "dh",
  "directory",
  "discount",
  "discuss",
  "dl",
  "dload",
  "doc",
  "docs",
  "document",
  "documents",
  "doujin",
  "download",
  "downloads",
  "drama",
  "edu",
  "en",
  "ep",
  "episode",
  "episodes",
  "event",
  "events",
  "f",
  "faq",
  "favorite",
  "favourites",
  "favs",
  "feedback",
  "file",
  "files",
  "film",
  "films",
  "forum",
  "forums",
  "friend",
  "friends",
  "game",
  "games",
  "gif",
  "go",
  "go.html",
  "go.php",
  "group",
  "groups",
  "help",
  "home",
  "hot",
  "htm",
  "html",
  "image",
  "images",
  "img",
  "index",
  "info",
  "intro",
  "item",
  "items",
  "ja",
  "jp",
  "jump",
  "jump.html",
  "jump.php",
  "jumping",
  "knowledge",
  "lang",
  "lesson",
  "lessons",
  "lib",
  "library",
  "link",
  "links",
  "list",
  "live",
  "lives",
  "m",
  "mag",
  "magnet",
  "mall",
  "manhua",
  "map",
  "member",
  "members",
  "message",
  "messages",
  "mobile",
  "movie",
  "movies",
  "music",
  "my",
  "new",
  "news",
  "note",
  "novel",
  "novels",
  "online",
  "order",
  "out",
  "out.html",
  "out.php",
  "outbound",
  "p",
  "page",
  "pages",
  "pay",
  "payment",
  "pdf",
  "photo",
  "photos",
  "pic",
  "pics",
  "picture",
  "pictures",
  "play",
  "player",
  "playlist",
  "post",
  "posts",
  "product",
  "products",
  "program",
  "programs",
  "project",
  "qa",
  "question",
  "rank",
  "ranking",
  "read",
  "readme",
  "redirect",
  "redirect.html",
  "redirect.php",
  "reg",
  "register",
  "res",
  "resource",
  "retrieve",
  "sale",
  "search",
  "season",
  "seasons",
  "section",
  "seller",
  "series",
  "service",
  "services",
  "setting",
  "settings",
  "share",
  "shop",
  "show",
  "shows",
  "site",
  "soft",
  "sort",
  "source",
  "special",
  "star",
  "stars",
  "static",
  "stock",
  "store",
  "stream",
  "streaming",
  "streams",
  "student",
  "study",
  "tag",
  "tags",
  "task",
  "teacher",
  "team",
  "tech",
  "temp",
  "test",
  "thread",
  "tool",
  "tools",
  "topic",
  "topics",
  "torrent",
  "trade",
  "travel",
  "tv",
  "txt",
  "type",
  "u",
  "upload",
  "uploads",
  "url",
  "urls",
  "user",
  "users",
  "v",
  "version",
  "video",
  "videos",
  "view",
  "vip",
  "vod",
  "watch",
  "web",
  "wenku",
  "wiki",
  "work",
  "www",
  "zh",
  "zh-cn",
  "zh-tw",
  "zip"
];
function randomPath(fullNodePath = "/") {
  const count = Math.floor(Math.random() * 3 + 1);
  const sampled = [...COMMON_PATH_SEGMENTS].sort(() => 0.5 - Math.random()).slice(0, count).join("/");
  if (fullNodePath === "/") return `/${sampled}`;
  return `/${sampled + fullNodePath.replace("/?", "?")}`;
}
function replaceAsterisks(content) {
  if (typeof content !== "string" || !content.includes("*")) return content;
  const charset = "abcdefghijklmnopqrstuvwxyz0123456789";
  return content.replace(/\*/g, () => {
    let s = "";
    const length = Math.floor(Math.random() * 14) + 3;
    for (let i = 0; i < length; i++) {
      s += charset[Math.floor(Math.random() * charset.length)];
    }
    return s;
  });
}
function bulkReplaceDomains(content, hosts, groupSize = 2) {
  const shuffledHosts = [...hosts].sort(() => Math.random() - 0.5);
  let count = 0;
  let currentRandomHost = null;
  return content.replace(/example\.com/g, () => {
    if (count % groupSize === 0) {
      const originalHost = shuffledHosts[Math.floor(count / groupSize) % shuffledHosts.length];
      currentRandomHost = replaceAsterisks(originalHost);
    }
    count++;
    return currentRandomHost;
  });
}

// src/admin/transport.ts
function getTransportConfig(config = {}) {
  const isGrpc = config.transport === "grpc";
  return {
    type: isGrpc ? config.grpcMode === "multi" ? "grpc&mode=multi" : "grpc&mode=gun" : config.transport === "xhttp" ? "xhttp&mode=stream-one" : "ws",
    pathField: isGrpc ? "serviceName" : "path",
    hostField: isGrpc ? "authority" : "host"
  };
}
function getTransportPath(config = {}, nodePath = "/", asPreferredSubGenerator = false) {
  const pathValue = asPreferredSubGenerator ? "/" : config.randomPath ? randomPath(nodePath) : nodePath;
  if (config.transport !== "grpc") return pathValue;
  return pathValue.split("?")[0] || "/";
}

// src/admin/config-schema.ts
var PROTOCOLS = ["vless", "trojan", "ss"];
var TRANSPORTS = ["ws", "xhttp", "grpc"];
var GRPC_MODES = ["gun", "multi"];
var TLS_FRAGMENTS = ["Shadowrocket", "Happ"];
function describe(value) {
  if (value === null) return "null";
  if (value === void 0) return "undefined";
  if (Array.isArray(value)) return `array(length=${value.length})`;
  if (typeof value === "object") return "object";
  if (typeof value === "string") return `string ${JSON.stringify(value)}`;
  return `${typeof value} ${String(value)}`;
}
function validateConfig(input) {
  const issues = [];
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    issues.push({
      path: "",
      message: `expected object at root, got ${describe(input)} \u2014 replaced with empty config`
    });
    return { config: {}, issues };
  }
  const c = input;
  const enumField = (parent, key, allowed, deflt, path) => {
    if (parent[key] === void 0 || parent[key] === null) return;
    if (typeof parent[key] !== "string" || !allowed.includes(parent[key])) {
      issues.push({
        path,
        message: `expected one of [${allowed.join(", ")}], got ${describe(parent[key])} \u2014 replaced with '${deflt}'`
      });
      parent[key] = deflt;
    }
  };
  const boolField = (parent, key, deflt, path) => {
    if (parent[key] === void 0 || parent[key] === null) return;
    if (typeof parent[key] !== "boolean") {
      issues.push({
        path,
        message: `expected boolean, got ${describe(parent[key])} \u2014 replaced with ${deflt}`
      });
      parent[key] = deflt;
    }
  };
  const intField = (parent, key, min, max, deflt, path) => {
    if (parent[key] === void 0 || parent[key] === null) return;
    const v = parent[key];
    if (typeof v !== "number" || !Number.isInteger(v) || v < min || v > max) {
      issues.push({
        path,
        message: `expected integer in [${min}, ${max}], got ${describe(v)} \u2014 replaced with ${deflt}`
      });
      parent[key] = deflt;
    }
  };
  const stringField = (parent, key, deflt, path) => {
    if (parent[key] === void 0 || parent[key] === null) return;
    if (typeof parent[key] !== "string") {
      issues.push({
        path,
        message: `expected string, got ${describe(parent[key])} \u2014 replaced with '${deflt}'`
      });
      parent[key] = deflt;
    }
  };
  const stringArrayField = (parent, key, deflt, path) => {
    if (parent[key] === void 0 || parent[key] === null) return;
    if (!Array.isArray(parent[key]) || !parent[key].every((x) => typeof x === "string")) {
      issues.push({
        path,
        message: `expected string[], got ${describe(parent[key])} \u2014 replaced with [${deflt.join(", ")}]`
      });
      parent[key] = deflt.slice();
    }
  };
  enumField(c, "protocol", PROTOCOLS, "vless", "protocol");
  enumField(c, "transport", TRANSPORTS, "ws", "transport");
  enumField(c, "grpcMode", GRPC_MODES, "gun", "grpcMode");
  boolField(c, "enable0RTT", false, "enable0RTT");
  boolField(c, "randomPath", false, "randomPath");
  boolField(c, "skipCertVerify", false, "skipCertVerify");
  boolField(c, "ECH", false, "ECH");
  stringField(c, "PATH", "/", "PATH");
  stringField(c, "Fingerprint", "chrome", "Fingerprint");
  stringArrayField(c, "HOSTS", [], "HOSTS");
  if (c.tlsFragment !== void 0 && c.tlsFragment !== null) {
    if (typeof c.tlsFragment !== "string" || !TLS_FRAGMENTS.includes(c.tlsFragment)) {
      issues.push({
        path: "tlsFragment",
        message: `expected one of [${TLS_FRAGMENTS.join(", ")}] or null, got ${describe(c.tlsFragment)} \u2014 replaced with null`
      });
      c.tlsFragment = null;
    }
  }
  if (c.SS !== void 0 && c.SS !== null) {
    if (typeof c.SS !== "object" || Array.isArray(c.SS)) {
      issues.push({
        path: "SS",
        message: `expected object, got ${describe(c.SS)} \u2014 replaced with default`
      });
      c.SS = { cipher: "aes-128-gcm", TLS: true };
    } else {
      boolField(c.SS, "TLS", true, "SS.TLS");
      stringField(c.SS, "cipher", "aes-128-gcm", "SS.cipher");
    }
  }
  if (c.preferredSub !== void 0 && c.preferredSub !== null) {
    if (typeof c.preferredSub !== "object" || Array.isArray(c.preferredSub)) {
      issues.push({
        path: "preferredSub",
        message: `expected object, got ${describe(c.preferredSub)} \u2014 sub-object not validated`
      });
    } else {
      const ps = c.preferredSub;
      boolField(ps, "local", true, "preferredSub.local");
      intField(ps, "SUBUpdateTime", 1, 24 * 30, 3, "preferredSub.SUBUpdateTime");
      stringField(ps, "SUBNAME", "edgetunnel", "preferredSub.SUBNAME");
      if (ps.localIP !== void 0 && ps.localIP !== null) {
        if (typeof ps.localIP !== "object" || Array.isArray(ps.localIP)) {
          issues.push({
            path: "preferredSub.localIP",
            message: `expected object, got ${describe(ps.localIP)} \u2014 sub-object not validated`
          });
        } else {
          boolField(ps.localIP, "randomIP", true, "preferredSub.localIP.randomIP");
          intField(ps.localIP, "count", 1, 1024, 16, "preferredSub.localIP.count");
          intField(ps.localIP, "port", -1, 65535, -1, "preferredSub.localIP.port");
        }
      }
    }
  }
  return { config: c, issues };
}
function formatIssues(issues) {
  if (issues.length === 0) return "";
  const lines = issues.map((i) => `  - ${i.path || "<root>"}: ${i.message}`);
  return `config.json validation: ${issues.length} issue(s)
${lines.join("\n")}`;
}

// src/admin/config.ts
var PROXYIP_KEY = atob("UFJPWFlJUA==");
var SCHEMA_MIGRATION = {
  "\u534F\u8BAE\u7C7B\u578B": "protocol",
  "\u4F20\u8F93\u534F\u8BAE": "transport",
  "gRPC\u6A21\u5F0F": "grpcMode",
  "\u968F\u673A\u8DEF\u5F84": "randomPath",
  "\u8DF3\u8FC7\u8BC1\u4E66\u9A8C\u8BC1": "skipCertVerify",
  "\u542F\u75280RTT": "enable0RTT",
  "TLS\u5206\u7247": "tlsFragment",
  "\u5B8C\u6574\u8282\u70B9\u8DEF\u5F84": "fullNodePath",
  "\u52A0\u8F7D\u65F6\u95F4": "loadTime",
  "\u52A0\u5BC6\u65B9\u5F0F": "cipher",
  "\u4F18\u9009\u8BA2\u9605\u751F\u6210": "preferredSub",
  "\u672C\u5730IP\u5E93": "localIP",
  "\u968F\u673AIP": "randomIP",
  "\u968F\u673A\u6570\u91CF": "count",
  "\u6307\u5B9A\u7AEF\u53E3": "port",
  "\u8BA2\u9605\u8F6C\u6362\u914D\u7F6E": "subConverter",
  "\u53CD\u4EE3": "proxy",
  "\u8DEF\u5F84\u6A21\u677F": "template",
  "\u5168\u5C40": "global",
  "\u6807\u51C6": "standard",
  "\u8D26\u53F7": "auth",
  "\u767D\u540D\u5355": "whitelist"
};
var SCOPED_MIGRATION = {
  TG: { "\u542F\u7528": "enabled" },
  SOCKS5: { "\u542F\u7528": "mode" }
};
function migrateLegacySchema(value, parentKey = "") {
  if (Array.isArray(value)) return value.map((v) => migrateLegacySchema(v, ""));
  if (!value || typeof value !== "object") return value;
  const out = {};
  const scoped = SCOPED_MIGRATION[parentKey];
  for (const [k, v] of Object.entries(value)) {
    const newKey = scoped?.[k] ?? SCHEMA_MIGRATION[k] ?? k;
    out[newKey] = migrateLegacySchema(v, newKey);
  }
  return out;
}
async function readConfigJson(ctx, env, hostname, userID, ua = "Mozilla/5.0", resetConfig = false) {
  const host = hostname;
  const aliDoH = "https://dns.alidns.com/dns-query";
  const echSni = "cloudflare-ech.com";
  const placeholder = "{{IP:PORT}}";
  const startTime = performance.now();
  const defaultConfig = {
    TIME: (/* @__PURE__ */ new Date()).toISOString(),
    HOST: host,
    HOSTS: [hostname],
    UUID: userID,
    PATH: "/",
    protocol: "vless",
    transport: "ws",
    grpcMode: "gun",
    gRPCUserAgent: ua,
    skipCertVerify: false,
    enable0RTT: false,
    tlsFragment: null,
    randomPath: false,
    ECH: false,
    ECHConfig: { DNS: aliDoH, SNI: echSni },
    SS: { cipher: "aes-128-gcm", TLS: true },
    Fingerprint: "chrome",
    preferredSub: {
      local: true,
      localIP: { randomIP: true, count: 16, port: -1 },
      SUB: null,
      SUBNAME: "edgetunnel",
      SUBUpdateTime: 3,
      TOKEN: await md5x2(hostname + userID)
    },
    subConverter: {
      SUBAPI: "https://SUBAPI.cmliussss.net",
      SUBCONFIG: "https://raw.githubusercontent.com/cmliu/ACL4SSR/refs/heads/main/Clash/config/ACL4SSR_Online_Mini_MultiMode_CF.ini",
      SUBEMOJI: false
    },
    proxy: {
      [PROXYIP_KEY]: "auto",
      SOCKS5: {
        mode: ctx.socks5Mode,
        global: ctx.socks5GlobalEnabled,
        auth: ctx.socks5Auth,
        whitelist: ctx.socks5Whitelist
      },
      template: {
        [PROXYIP_KEY]: "proxyip=" + placeholder,
        SOCKS5: { global: "socks5://" + placeholder, standard: "socks5=" + placeholder },
        HTTP: { global: "http://" + placeholder, standard: "http=" + placeholder },
        HTTPS: { global: "https://" + placeholder, standard: "https=" + placeholder }
      }
    },
    TG: { enabled: false, BotToken: null, ChatID: null },
    CF: {
      Email: null,
      GlobalAPIKey: null,
      AccountID: null,
      APIToken: null,
      UsageAPI: null,
      Usage: { success: false, pages: 0, workers: 0, total: 0, max: 1e5 }
    }
  };
  let configJson;
  let validationIssues = [];
  try {
    const stored = await env.KV.get("config.json");
    if (!stored || resetConfig) {
      await env.KV.put("config.json", JSON.stringify(defaultConfig, null, 2));
      configJson = defaultConfig;
    } else {
      const parsed = JSON.parse(stored);
      const migrated = migrateLegacySchema(parsed);
      const { config: validated, issues } = validateConfig(migrated);
      validationIssues = issues;
      if (issues.length > 0) {
        console.warn(formatIssues(issues));
      }
      configJson = validated;
      if (JSON.stringify(parsed) !== JSON.stringify(validated)) {
        await env.KV.put("config.json", JSON.stringify(validated, null, 2));
      }
    }
  } catch (error) {
    console.error(`readConfigJson error: ${error.message}`);
    configJson = defaultConfig;
  }
  ctx.configJson = configJson;
  configJson.__validation = { issues: validationIssues };
  if (!configJson.gRPCUserAgent) configJson.gRPCUserAgent = ua;
  configJson.HOST = host;
  if (!configJson.HOSTS) configJson.HOSTS = [hostname];
  if (env.HOST) {
    configJson.HOSTS = toArray(env.HOST).map(
      (h) => h.toLowerCase().replace(/^https?:\/\//, "").split("/")[0].split(":")[0]
    );
  }
  configJson.UUID = userID;
  if (!configJson.randomPath) configJson.randomPath = false;
  if (!configJson.enable0RTT) configJson.enable0RTT = false;
  if (env.PATH) {
    configJson.PATH = env.PATH.startsWith("/") ? env.PATH : "/" + env.PATH;
  } else if (!configJson.PATH) {
    configJson.PATH = "/";
  }
  if (!configJson.grpcMode) configJson.grpcMode = "gun";
  if (!configJson.SS) configJson.SS = { cipher: "aes-128-gcm", TLS: false };
  if (!configJson.proxy.template?.[PROXYIP_KEY]) {
    configJson.proxy.template = {
      [PROXYIP_KEY]: "proxyip=" + placeholder,
      SOCKS5: { global: "socks5://" + placeholder, standard: "socks5=" + placeholder },
      HTTP: { global: "http://" + placeholder, standard: "http=" + placeholder }
    };
  }
  if (!configJson.proxy.template.HTTPS) {
    configJson.proxy.template.HTTPS = {
      global: "https://" + placeholder,
      standard: "https=" + placeholder
    };
  }
  const proxyTemplate = configJson.proxy.template[configJson.proxy.SOCKS5.mode?.toUpperCase()];
  let pathProxyParam = "";
  if (proxyTemplate && configJson.proxy.SOCKS5.auth) {
    pathProxyParam = (configJson.proxy.SOCKS5.global ? proxyTemplate.global : proxyTemplate.standard).replace(placeholder, configJson.proxy.SOCKS5.auth);
  } else if (configJson.proxy[PROXYIP_KEY] !== "auto") {
    pathProxyParam = configJson.proxy.template[PROXYIP_KEY].replace(
      placeholder,
      configJson.proxy[PROXYIP_KEY]
    );
  }
  let proxyQuery = "";
  if (pathProxyParam.includes("?")) {
    const [pathPart2, queryPart2] = pathProxyParam.split("?");
    pathProxyParam = pathPart2;
    proxyQuery = queryPart2;
  }
  configJson.PATH = configJson.PATH.replace(pathProxyParam, "").replace("//", "/");
  const normalizedPath = configJson.PATH === "/" ? "" : configJson.PATH.replace(/\/+(?=\?|$)/, "").replace(/\/+$/, "");
  const [pathPart, ...queryParts] = normalizedPath.split("?");
  const queryPart = queryParts.length ? "?" + queryParts.join("?") : "";
  const finalQuery = proxyQuery ? queryPart ? queryPart + "&" + proxyQuery : "?" + proxyQuery : queryPart;
  configJson.fullNodePath = (pathPart || "/") + (pathPart && pathProxyParam ? "/" : "") + pathProxyParam + finalQuery + (configJson.enable0RTT ? (finalQuery ? "&" : "?") + "ed=2560" : "");
  if (!configJson.tlsFragment && configJson.tlsFragment !== null) configJson.tlsFragment = null;
  const tlsFragmentParam = configJson.tlsFragment == "Shadowrocket" ? `&fragment=${encodeURIComponent("1,40-60,30-50,tlshello")}` : configJson.tlsFragment == "Happ" ? `&fragment=${encodeURIComponent("3,1,tlshello")}` : "";
  if (!configJson.Fingerprint) configJson.Fingerprint = "chrome";
  if (!configJson.ECH) configJson.ECH = false;
  if (!configJson.ECHConfig) configJson.ECHConfig = { DNS: aliDoH, SNI: echSni };
  const echLinkParam = configJson.ECH ? `&ech=${encodeURIComponent((configJson.ECHConfig.SNI ? configJson.ECHConfig.SNI + "+" : "") + configJson.ECHConfig.DNS)}` : "";
  const { type: transportProto, pathField: pathFieldName, hostField: hostFieldName } = getTransportConfig(configJson);
  const transportPathValue = getTransportPath(configJson, configJson.fullNodePath);
  configJson.LINK = configJson.protocol === "ss" ? `${configJson.protocol}://${btoa(configJson.SS.cipher + ":" + userID)}@${host}:${configJson.SS.TLS ? "443" : "80"}?plugin=v2${encodeURIComponent(
    `ray-plugin;mode=websocket;host=${host};path=${(configJson.fullNodePath.includes("?") ? configJson.fullNodePath.replace("?", "?enc=" + configJson.SS.cipher + "&") : configJson.fullNodePath + "?enc=" + configJson.SS.cipher) + (configJson.SS.TLS ? ";tls" : "")};mux=0`
  ) + echLinkParam}#${encodeURIComponent(configJson.preferredSub.SUBNAME)}` : `${configJson.protocol}://${userID}@${host}:443?security=tls&type=${transportProto + echLinkParam}&${hostFieldName}=${host}&fp=${configJson.Fingerprint}&sni=${host}&${pathFieldName}=${encodeURIComponent(transportPathValue) + tlsFragmentParam}&encryption=none${configJson.skipCertVerify ? "&insecure=1&allowInsecure=1" : ""}#${encodeURIComponent(configJson.preferredSub.SUBNAME)}`;
  configJson.preferredSub.TOKEN = await md5x2(hostname + userID);
  const initTgJson = { BotToken: null, ChatID: null };
  configJson.TG = {
    enabled: configJson.TG.enabled ? configJson.TG.enabled : false,
    ...initTgJson
  };
  try {
    const tgText = await env.KV.get("tg.json");
    if (!tgText) {
      await env.KV.put("tg.json", JSON.stringify(initTgJson, null, 2));
    } else {
      const tg = JSON.parse(tgText);
      configJson.TG.ChatID = tg.ChatID ? tg.ChatID : null;
      configJson.TG.BotToken = tg.BotToken ? maskSensitive(tg.BotToken) : null;
    }
  } catch (error) {
    console.error(`tg.json read error: ${error.message}`);
  }
  const initCfJson = {
    Email: null,
    GlobalAPIKey: null,
    AccountID: null,
    APIToken: null,
    UsageAPI: null
  };
  configJson.CF = {
    ...initCfJson,
    Usage: { success: false, pages: 0, workers: 0, total: 0, max: 1e5 }
  };
  try {
    const cfText = await env.KV.get("cf.json");
    if (!cfText) {
      await env.KV.put("cf.json", JSON.stringify(initCfJson, null, 2));
    } else {
      const cf = JSON.parse(cfText);
      if (cf.UsageAPI) {
        try {
          const response = await fetch(cf.UsageAPI);
          configJson.CF.Usage = await response.json();
        } catch (err) {
          console.error(`UsageAPI fetch failed: ${err.message}`);
        }
      } else {
        configJson.CF.Email = cf.Email ? cf.Email : null;
        configJson.CF.GlobalAPIKey = cf.GlobalAPIKey ? maskSensitive(cf.GlobalAPIKey) : null;
        configJson.CF.AccountID = cf.AccountID ? maskSensitive(cf.AccountID) : null;
        configJson.CF.APIToken = cf.APIToken ? maskSensitive(cf.APIToken) : null;
        configJson.CF.UsageAPI = null;
        configJson.CF.Usage = await getCloudflareUsage(
          cf.Email,
          cf.GlobalAPIKey,
          cf.AccountID,
          cf.APIToken
        );
      }
    }
  } catch (error) {
    console.error(`cf.json read error: ${error.message}`);
  }
  configJson.loadTime = (performance.now() - startTime).toFixed(2) + "ms";
  ctx.configJson = configJson;
  return configJson;
}

// src/admin/random-ip.ts
var ISP_BY_ASN = {
  "9808": { file: "cmcc", name: "CF\u79FB\u52A8\u4F18\u9009" },
  "4837": { file: "cu", name: "CF\u8054\u901A\u4F18\u9009" },
  "17623": { file: "cu", name: "CF\u8054\u901A\u4F18\u9009" },
  "17816": { file: "cu", name: "CF\u8054\u901A\u4F18\u9009" },
  "4134": { file: "ct", name: "CF\u7535\u4FE1\u4F18\u9009" }
};
var TLS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
var NOTLS_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];
var CIDR_BASE_URL = "https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR";
var FALLBACK_CIDR = ["104.16.0.0/13"];
function generateRandomIPFromCIDR(cidr) {
  const [baseIP, prefixLength] = cidr.split("/");
  const prefix = parseInt(prefixLength, 10);
  const hostBits = 32 - prefix;
  const ipInt = baseIP.split(".").reduce((a, p, i) => a | parseInt(p, 10) << 24 - i * 8, 0);
  const randomOffset = Math.floor(Math.random() * Math.pow(2, hostBits));
  const mask = 4294967295 << hostBits >>> 0;
  const randomIP = ((ipInt & mask) >>> 0) + randomOffset >>> 0;
  return [
    randomIP >>> 24 & 255,
    randomIP >>> 16 & 255,
    randomIP >>> 8 & 255,
    randomIP & 255
  ].join(".");
}
async function generateRandomIPs(request, count = 16, fixedPort = -1, tls = true) {
  const asn = String(request.cf?.asn || "");
  const isp = ISP_BY_ASN[asn];
  const cidrUrl = isp ? `${CIDR_BASE_URL}/${isp.file}.txt` : `${CIDR_BASE_URL}.txt`;
  const cfname = isp?.name || "CF\u5B98\u65B9\u4F18\u9009";
  const cfport = tls ? TLS_PORTS : NOTLS_PORTS;
  let cidrList = [];
  try {
    const res = await fetch(cidrUrl);
    cidrList = res.ok ? toArray(await res.text()) : FALLBACK_CIDR;
  } catch {
    cidrList = FALLBACK_CIDR;
  }
  if (cidrList.length === 0) cidrList = FALLBACK_CIDR;
  const randomIPs = Array.from({ length: count }, (_, index) => {
    const ip = generateRandomIPFromCIDR(cidrList[Math.floor(Math.random() * cidrList.length)]);
    let targetPort;
    if (fixedPort === -1) {
      targetPort = cfport[Math.floor(Math.random() * cfport.length)];
    } else if (tls) {
      targetPort = fixedPort;
    } else {
      const tlsIndex = TLS_PORTS.indexOf(Number(fixedPort));
      targetPort = tlsIndex >= 0 ? NOTLS_PORTS[tlsIndex] : fixedPort;
    }
    return `${ip}:${targetPort}#${cfname}${index + 1}`;
  });
  return [randomIPs, randomIPs.join("\n")];
}

// src/admin/preferred-sub.ts
async function fetchPreferredSubData(generatorHost) {
  const preferredIPs = [];
  let otherNodeLinks = "";
  let formattedHost = generatorHost.replace(/^sub:\/\//i, "https://").split("#")[0].split("?")[0];
  if (!/^https?:\/\//i.test(formattedHost)) formattedHost = `https://${formattedHost}`;
  try {
    const u = new URL(formattedHost);
    formattedHost = u.origin;
  } catch (error) {
    preferredIPs.push(`127.0.0.1:1234#${generatorHost}generator format error: ${error.message}`);
    return [preferredIPs, otherNodeLinks];
  }
  const generatorURL = `${formattedHost}/sub?host=example.com&uuid=00000000-0000-4000-8000-000000000000`;
  try {
    const response = await fetch(generatorURL, {
      headers: {
        "User-Agent": "v2rayN/edgetunnel (https://github.com/cmliu/edgetunnel)"
      }
    });
    if (!response.ok) {
      preferredIPs.push(`127.0.0.1:1234#${generatorHost}generator error: ${response.statusText}`);
      return [preferredIPs, otherNodeLinks];
    }
    const subContent = atob(await response.text());
    const lines = subContent.includes("\r\n") ? subContent.split("\r\n") : subContent.split("\n");
    for (const line of lines) {
      if (!line.trim()) continue;
      if (line.includes("00000000-0000-4000-8000-000000000000") && line.includes("example.com")) {
        const match = line.match(/:\/\/[^@]+@([^?]+)/);
        if (match) {
          let addrPort = match[1];
          let remark = "";
          const remarkMatch = line.match(/#(.+)$/);
          if (remarkMatch) remark = "#" + decodeURIComponent(remarkMatch[1]);
          preferredIPs.push(addrPort + remark);
        }
      } else {
        otherNodeLinks += line + "\n";
      }
    }
  } catch (error) {
    preferredIPs.push(`127.0.0.1:1234#${generatorHost}generator error: ${error.message}`);
  }
  return [preferredIPs, otherNodeLinks];
}
async function requestPreferredApi(urls, defaultPort = "443", timeoutMs = 3e3) {
  if (!urls?.length) return [[], [], [], []];
  const results = /* @__PURE__ */ new Set();
  const proxyIPPool = /* @__PURE__ */ new Set();
  let plaintextLinks = "";
  const needConvertUrls = [];
  const IPV6_PATTERN = /^[^\[\]]*:[^\[\]]*:[^\[\]]/;
  await Promise.allSettled(
    urls.map(async (url) => {
      const hashIndex = url.indexOf("#");
      const urlWithoutHash = hashIndex > -1 ? url.substring(0, hashIndex) : url;
      const apiRemark = hashIndex > -1 ? decodeURIComponent(url.substring(hashIndex + 1)) : null;
      const ipsAsProxyIP = url.toLowerCase().includes("proxyip=true");
      if (urlWithoutHash.toLowerCase().startsWith("sub://")) {
        try {
          const [preferredIPs, otherLinks] = await fetchPreferredSubData(urlWithoutHash);
          if (apiRemark) {
            for (const ip of preferredIPs) {
              const tagged = ip.includes("#") ? `${ip} [${apiRemark}]` : `${ip}#[${apiRemark}]`;
              results.add(tagged);
              if (ipsAsProxyIP) proxyIPPool.add(ip.split("#")[0]);
            }
          } else {
            for (const ip of preferredIPs) {
              results.add(ip);
              if (ipsAsProxyIP) proxyIPPool.add(ip.split("#")[0]);
            }
          }
          if (otherLinks && typeof otherLinks === "string" && apiRemark) {
            const taggedLinks = otherLinks.replace(
              /([a-z][a-z0-9+\-.]*:\/\/[^\r\n]*?)(\r?\n|$)/gi,
              (match, link, lineEnd) => {
                const full = link.includes("#") ? `${link}${encodeURIComponent(` [${apiRemark}]`)}` : `${link}${encodeURIComponent(`#[${apiRemark}]`)}`;
                return `${full}${lineEnd}`;
              }
            );
            plaintextLinks += taggedLinks;
          } else if (otherLinks && typeof otherLinks === "string") {
            plaintextLinks += otherLinks;
          }
        } catch (e) {
        }
        return;
      }
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
        const response = await fetch(urlWithoutHash, { signal: controller.signal });
        clearTimeout(timeoutId);
        let text = "";
        try {
          const buffer = await response.arrayBuffer();
          const contentType = (response.headers.get("content-type") || "").toLowerCase();
          const charset = contentType.match(/charset=([^\s;]+)/i)?.[1]?.toLowerCase() || "";
          let decoders = ["utf-8", "gb2312"];
          if (charset.includes("gb") || charset.includes("gbk") || charset.includes("gb2312")) {
            decoders = ["gb2312", "utf-8"];
          }
          let decodeSuccess = false;
          for (const dec of decoders) {
            try {
              const decoded = new TextDecoder(dec).decode(buffer);
              if (decoded && decoded.length > 0 && !decoded.includes("\uFFFD")) {
                text = decoded;
                decodeSuccess = true;
                break;
              }
            } catch (e) {
              continue;
            }
          }
          if (!decodeSuccess) text = await response.text();
          if (!text || text.trim().length === 0) return;
        } catch (e) {
          console.error("Failed to decode response:", e);
          return;
        }
        let processedText = text;
        const cleanText = typeof text === "string" ? text.replace(/\s/g, "") : "";
        if (cleanText.length > 0 && cleanText.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(cleanText)) {
          try {
            const bytes = new Uint8Array(atob(cleanText).split("").map((c) => c.charCodeAt(0)));
            processedText = new TextDecoder("utf-8").decode(bytes);
          } catch {
          }
        }
        if (processedText.split("#")[0].includes("://")) {
          if (apiRemark) {
            const tagged = processedText.replace(
              /([a-z][a-z0-9+\-.]*:\/\/[^\r\n]*?)(\r?\n|$)/gi,
              (match, link, lineEnd) => {
                const full = link.includes("#") ? `${link}${encodeURIComponent(` [${apiRemark}]`)}` : `${link}${encodeURIComponent(`#[${apiRemark}]`)}`;
                return `${full}${lineEnd}`;
              }
            );
            plaintextLinks += tagged + "\n";
          } else {
            plaintextLinks += processedText + "\n";
          }
          return;
        }
        const lines = text.trim().split("\n").map((l) => l.trim()).filter((l) => l);
        const isCSV = lines.length > 1 && lines[0].includes(",");
        const parsedUrl = new URL(urlWithoutHash);
        if (!isCSV) {
          lines.forEach((line) => {
            const lineHashIndex = line.indexOf("#");
            const [hostPart, remark] = lineHashIndex > -1 ? [line.substring(0, lineHashIndex), line.substring(lineHashIndex)] : [line, ""];
            let hasPort = false;
            if (hostPart.startsWith("[")) {
              hasPort = /\]:(\d+)$/.test(hostPart);
            } else {
              const colonIndex = hostPart.lastIndexOf(":");
              hasPort = colonIndex > -1 && /^\d+$/.test(hostPart.substring(colonIndex + 1));
            }
            const port = parsedUrl.searchParams.get("port") || defaultPort;
            const ipItem = hasPort ? line : `${hostPart}:${port}${remark}`;
            if (apiRemark) {
              const tagged = ipItem.includes("#") ? `${ipItem} [${apiRemark}]` : `${ipItem}#[${apiRemark}]`;
              results.add(tagged);
            } else {
              results.add(ipItem);
            }
            if (ipsAsProxyIP) proxyIPPool.add(ipItem.split("#")[0]);
          });
        } else {
          const headers = lines[0].split(",").map((h) => h.trim());
          const dataLines = lines.slice(1);
          if (headers.includes("IP\u5730\u5740") && headers.includes("\u7AEF\u53E3") && headers.includes("\u6570\u636E\u4E2D\u5FC3")) {
            const ipIdx = headers.indexOf("IP\u5730\u5740");
            const portIdx = headers.indexOf("\u7AEF\u53E3");
            const remarkIdx = headers.indexOf("\u56FD\u5BB6") > -1 ? headers.indexOf("\u56FD\u5BB6") : headers.indexOf("\u57CE\u5E02") > -1 ? headers.indexOf("\u57CE\u5E02") : headers.indexOf("\u6570\u636E\u4E2D\u5FC3");
            const tlsIdx = headers.indexOf("TLS");
            dataLines.forEach((line) => {
              const cols = line.split(",").map((c) => c.trim());
              if (tlsIdx !== -1 && cols[tlsIdx]?.toLowerCase() !== "true") return;
              const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
              const ipItem = `${wrappedIP}:${cols[portIdx]}#${cols[remarkIdx]}`;
              if (apiRemark) {
                results.add(`${ipItem} [${apiRemark}]`);
              } else {
                results.add(ipItem);
              }
              if (ipsAsProxyIP) proxyIPPool.add(`${wrappedIP}:${cols[portIdx]}`);
            });
          } else if (headers.some((h) => h.includes("IP")) && headers.some((h) => h.includes("\u5EF6\u8FDF")) && headers.some((h) => h.includes("\u4E0B\u8F7D\u901F\u5EA6"))) {
            const ipIdx = headers.findIndex((h) => h.includes("IP"));
            const delayIdx = headers.findIndex((h) => h.includes("\u5EF6\u8FDF"));
            const speedIdx = headers.findIndex((h) => h.includes("\u4E0B\u8F7D\u901F\u5EA6"));
            const port = parsedUrl.searchParams.get("port") || defaultPort;
            dataLines.forEach((line) => {
              const cols = line.split(",").map((c) => c.trim());
              const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
              const ipItem = `${wrappedIP}:${port}#CF\u4F18\u9009 ${cols[delayIdx]}ms ${cols[speedIdx]}MB/s`;
              if (apiRemark) {
                results.add(`${ipItem} [${apiRemark}]`);
              } else {
                results.add(ipItem);
              }
              if (ipsAsProxyIP) proxyIPPool.add(`${wrappedIP}:${port}`);
            });
          }
        }
      } catch (e) {
      }
    })
  );
  const linkArray = plaintextLinks.trim() ? [...new Set(plaintextLinks.split(/\r?\n/).filter((line) => line.trim() !== ""))] : [];
  return [Array.from(results), linkArray, needConvertUrls, Array.from(proxyIPPool)];
}

// src/handlers/admin.ts
var json = (obj, status = 200) => new Response(JSON.stringify(obj, null, 2), {
  status,
  headers: { "Content-Type": "application/json;charset=utf-8" }
});
async function handleAdmin(ctx, env, request, url, caseInsensitivePath, casePreservingPath, host, userID, ua, accessIP, workerCtx) {
  if (caseInsensitivePath === "admin/log.json") {
    const logContent = await env.KV.get("log.json") || "[]";
    return new Response(logContent, {
      status: 200,
      headers: { "Content-Type": "application/json;charset=utf-8" }
    });
  }
  if (casePreservingPath === "admin/getCloudflareUsage") {
    try {
      const usage = await getCloudflareUsage(
        url.searchParams.get("Email"),
        url.searchParams.get("GlobalAPIKey"),
        url.searchParams.get("AccountID"),
        url.searchParams.get("APIToken")
      );
      return json(usage);
    } catch (err) {
      return json({ msg: "getCloudflareUsage failed: " + err.message, error: err.message }, 500);
    }
  }
  if (casePreservingPath === "admin/getADDAPI") {
    if (url.searchParams.get("url")) {
      const testUrl = url.searchParams.get("url");
      try {
        new URL(testUrl);
        const result = await requestPreferredApi(
          [testUrl],
          url.searchParams.get("port") || "443"
        );
        let apiIPs = result[0].length > 0 ? result[0] : result[1];
        apiIPs = apiIPs.map(
          (item) => item.replace(/#(.+)$/, (_, remark) => "#" + decodeURIComponent(remark))
        );
        return json({ success: true, data: apiIPs });
      } catch (err) {
        return json({ msg: "getADDAPI failed: " + err.message, error: err.message }, 500);
      }
    }
    return json({ success: false, data: [] }, 403);
  }
  if (caseInsensitivePath === "admin/check") {
    return json({ error: "proxy check not implemented in modular build" }, 501);
  }
  let config = await readConfigJson(ctx, env, host, userID, ua);
  if (caseInsensitivePath === "admin/init") {
    try {
      config = await readConfigJson(ctx, env, host, userID, ua, true);
      workerCtx.waitUntil(
        logRequest(env, request, accessIP, "Init_Config", config)
      );
      config.init = "configuration reset to defaults";
      return json(config);
    } catch (err) {
      return json({ msg: "config reset failed: " + err.message, error: err.message }, 500);
    }
  }
  if (request.method === "POST") {
    if (caseInsensitivePath === "admin/config.json") {
      try {
        const newConfig = await request.json();
        if (!newConfig.UUID || !newConfig.HOST) {
          return json({ error: "incomplete configuration" }, 400);
        }
        await env.KV.put("config.json", JSON.stringify(newConfig, null, 2));
        workerCtx.waitUntil(
          logRequest(env, request, accessIP, "Save_Config", config)
        );
        return json({ success: true, message: "configuration saved" });
      } catch (error) {
        console.error("save config failed:", error);
        return json({ error: "save config failed: " + error.message }, 500);
      }
    }
    if (caseInsensitivePath === "admin/cf.json") {
      try {
        const newConfig = await request.json();
        const cfJson = {
          Email: null,
          GlobalAPIKey: null,
          AccountID: null,
          APIToken: null,
          UsageAPI: null
        };
        if (!newConfig.init || newConfig.init !== true) {
          if (newConfig.Email && newConfig.GlobalAPIKey) {
            cfJson.Email = newConfig.Email;
            cfJson.GlobalAPIKey = newConfig.GlobalAPIKey;
          } else if (newConfig.AccountID && newConfig.APIToken) {
            cfJson.AccountID = newConfig.AccountID;
            cfJson.APIToken = newConfig.APIToken;
          } else if (newConfig.UsageAPI) {
            cfJson.UsageAPI = newConfig.UsageAPI;
          } else {
            return json({ error: "incomplete configuration" }, 400);
          }
        }
        await env.KV.put("cf.json", JSON.stringify(cfJson, null, 2));
        workerCtx.waitUntil(
          logRequest(env, request, accessIP, "Save_Config", config)
        );
        return json({ success: true, message: "configuration saved" });
      } catch (error) {
        return json({ error: "save config failed: " + error.message }, 500);
      }
    }
    if (caseInsensitivePath === "admin/tg.json") {
      try {
        const newConfig = await request.json();
        if (newConfig.init && newConfig.init === true) {
          const tgJson = { BotToken: null, ChatID: null };
          await env.KV.put("tg.json", JSON.stringify(tgJson, null, 2));
        } else {
          if (!newConfig.BotToken || !newConfig.ChatID) {
            return json({ error: "incomplete configuration" }, 400);
          }
          await env.KV.put("tg.json", JSON.stringify(newConfig, null, 2));
        }
        workerCtx.waitUntil(
          logRequest(env, request, accessIP, "Save_Config", config)
        );
        return json({ success: true, message: "configuration saved" });
      } catch (error) {
        return json({ error: "save config failed: " + error.message }, 500);
      }
    }
    if (casePreservingPath === "admin/ADD.txt") {
      try {
        const customIPs = await request.text();
        await env.KV.put("ADD.txt", customIPs);
        workerCtx.waitUntil(
          logRequest(env, request, accessIP, "Save_Custom_IPs", config)
        );
        return json({ success: true, message: "custom IPs saved" });
      } catch (error) {
        return json({ error: "save custom IPs failed: " + error.message }, 500);
      }
    }
    return json({ error: "unsupported POST path" }, 404);
  }
  if (caseInsensitivePath === "admin/config.json") {
    return json(config);
  }
  if (casePreservingPath === "admin/ADD.txt") {
    let customIPs = await env.KV.get("ADD.txt") || "null";
    if (customIPs == "null") {
      customIPs = (await generateRandomIPs(
        request,
        config.preferredSub.localIP.count,
        config.preferredSub.localIP.port,
        config.protocol === "ss" ? config.SS.TLS : true
      ))[1];
    }
    return new Response(customIPs, {
      status: 200,
      headers: {
        "Content-Type": "text/plain;charset=utf-8",
        asn: String(request.cf?.asn || "")
      }
    });
  }
  if (caseInsensitivePath === "admin/cf.json") {
    return json(request.cf || {});
  }
  workerCtx.waitUntil(
    logRequest(env, request, accessIP, "Admin_Login", config)
  );
  return fetch(PAGES_STATIC_URL + "/admin" + url.search);
}

// src/subscription/clash.ts
var BASE_DNS_BLOCK = `dns:
  enable: true
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
    - 114.114.114.114
  use-hosts: true
  nameserver:
    - https://sm2.doh.pub/dns-query
    - https://dns.alidns.com/dns-query
  fallback:
    - 8.8.4.4
    - 208.67.220.220
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4
      - 127.0.0.1/32
      - 0.0.0.0/32
    domain:
      - '+.google.com'
      - '+.facebook.com'
      - '+.youtube.com'
`;
function patchClashSubscription(originalYaml, config = {}) {
  const uuid = config?.UUID || null;
  const echEnabled = Boolean(config?.ECH);
  const hosts = Array.isArray(config?.HOSTS) ? [...config.HOSTS] : [];
  const echSni = config?.ECHConfig?.SNI || null;
  const echDns = config?.ECHConfig?.DNS;
  const needEch = Boolean(uuid && echEnabled);
  const grpcUserAgent = typeof config?.gRPCUserAgent === "string" && config.gRPCUserAgent.trim() ? config.gRPCUserAgent.trim() : null;
  const needGrpc = config?.transport === "grpc" && Boolean(grpcUserAgent);
  const grpcUserAgentYaml = grpcUserAgent ? JSON.stringify(grpcUserAgent) : null;
  let yaml = originalYaml.replace(/mode:\s*Rule\b/g, "mode: rule");
  const addInlineGrpcUserAgent = (text) => text.replace(/grpc-opts:\s*\{([\s\S]*?)\}/i, (all, inner) => {
    if (/grpc-user-agent\s*:/i.test(inner)) return all;
    let content = inner.trim();
    if (content.endsWith(",")) content = content.slice(0, -1).trim();
    const patched = content ? `${content}, grpc-user-agent: ${grpcUserAgentYaml}` : `grpc-user-agent: ${grpcUserAgentYaml}`;
    return `grpc-opts: {${patched}}`;
  });
  const matchesGrpcNetwork = (text) => /(?:^|[,{])\s*network:\s*(?:"grpc"|'grpc'|grpc)(?=\s*(?:[,}\n#]|$))/im.test(text);
  const getNodeType = (nodeText) => nodeText.match(/type:\s*(\w+)/)?.[1] || "vless";
  const getCredentialValue = (nodeText, isFlowStyle) => {
    const credentialField = getNodeType(nodeText) === "trojan" ? "password" : "uuid";
    const pattern = new RegExp(
      `${credentialField}:\\s*${isFlowStyle ? "([^,}\\n]+)" : "([^\\n]+)"}`
    );
    return nodeText.match(pattern)?.[1]?.trim() || null;
  };
  const insertNameserverPolicy = (yamlIn, hostsEntries) => {
    if (/^\s{2}nameserver-policy:\s*(?:\n|$)/m.test(yamlIn)) {
      return yamlIn.replace(
        /^(\s{2}nameserver-policy:\s*\n)/m,
        `$1${hostsEntries}
`
      );
    }
    const lines2 = yamlIn.split("\n");
    let dnsBlockEndIndex = -1;
    let inDnsBlock = false;
    for (let i2 = 0; i2 < lines2.length; i2++) {
      const line = lines2[i2];
      if (/^dns:\s*$/.test(line)) {
        inDnsBlock = true;
        continue;
      }
      if (inDnsBlock && /^[a-zA-Z]/.test(line)) {
        dnsBlockEndIndex = i2;
        break;
      }
    }
    const block = `  nameserver-policy:
${hostsEntries}`;
    if (dnsBlockEndIndex !== -1) lines2.splice(dnsBlockEndIndex, 0, block);
    else lines2.push(block);
    return lines2.join("\n");
  };
  const addFlowGrpcUserAgent = (nodeText) => {
    if (!matchesGrpcNetwork(nodeText) || /grpc-user-agent\s*:/i.test(nodeText)) return nodeText;
    if (/grpc-opts:\s*\{/i.test(nodeText)) return addInlineGrpcUserAgent(nodeText);
    return nodeText.replace(
      /\}(\s*)$/,
      `, grpc-opts: {grpc-user-agent: ${grpcUserAgentYaml}}}$1`
    );
  };
  const addBlockGrpcUserAgent = (nodeLines, topLevelIndent) => {
    const topIndent = " ".repeat(topLevelIndent);
    let grpcOptsIndex = -1;
    for (let idx = 0; idx < nodeLines.length; idx++) {
      const line = nodeLines[idx];
      if (!line.trim()) continue;
      const indent = line.search(/\S/);
      if (indent !== topLevelIndent) continue;
      if (/^\s*grpc-opts:\s*(?:#.*)?$/.test(line) || /^\s*grpc-opts:\s*\{.*\}\s*(?:#.*)?$/.test(line)) {
        grpcOptsIndex = idx;
        break;
      }
    }
    if (grpcOptsIndex === -1) {
      let insertIndex = -1;
      for (let j = nodeLines.length - 1; j >= 0; j--) {
        if (nodeLines[j].trim()) {
          insertIndex = j;
          break;
        }
      }
      if (insertIndex >= 0) {
        nodeLines.splice(
          insertIndex + 1,
          0,
          `${topIndent}grpc-opts:`,
          `${topIndent}  grpc-user-agent: ${grpcUserAgentYaml}`
        );
      }
      return nodeLines;
    }
    const grpcLine = nodeLines[grpcOptsIndex];
    if (/^\s*grpc-opts:\s*\{.*\}\s*(?:#.*)?$/.test(grpcLine)) {
      if (!/grpc-user-agent\s*:/i.test(grpcLine)) {
        nodeLines[grpcOptsIndex] = addInlineGrpcUserAgent(grpcLine);
      }
      return nodeLines;
    }
    let blockEndIndex = nodeLines.length;
    let childIndent = topLevelIndent + 2;
    let hasGrpcUserAgent = false;
    for (let idx = grpcOptsIndex + 1; idx < nodeLines.length; idx++) {
      const line = nodeLines[idx];
      const trimmed = line.trim();
      if (!trimmed) continue;
      const indent = line.search(/\S/);
      if (indent <= topLevelIndent) {
        blockEndIndex = idx;
        break;
      }
      if (indent > topLevelIndent && childIndent === topLevelIndent + 2) childIndent = indent;
      if (/^grpc-user-agent\s*:/.test(trimmed)) {
        hasGrpcUserAgent = true;
        break;
      }
    }
    if (!hasGrpcUserAgent) {
      nodeLines.splice(
        blockEndIndex,
        0,
        `${" ".repeat(childIndent)}grpc-user-agent: ${grpcUserAgentYaml}`
      );
    }
    return nodeLines;
  };
  const addBlockEchOpts = (nodeLines, topLevelIndent) => {
    let insertIndex = -1;
    for (let j = nodeLines.length - 1; j >= 0; j--) {
      if (nodeLines[j].trim()) {
        insertIndex = j;
        break;
      }
    }
    if (insertIndex < 0) return nodeLines;
    const indent = " ".repeat(topLevelIndent);
    const echLines = [`${indent}ech-opts:`, `${indent}  enable: true`];
    if (echSni) echLines.push(`${indent}  query-server-name: ${echSni}`);
    nodeLines.splice(insertIndex + 1, 0, ...echLines);
    return nodeLines;
  };
  if (!/^dns:\s*(?:\n|$)/m.test(yaml)) yaml = BASE_DNS_BLOCK + yaml;
  if (echSni && !hosts.includes(echSni)) hosts.push(echSni);
  if (echEnabled && hosts.length > 0) {
    const hostsEntries = hosts.map((h) => `    "${h}": ${echDns ? echDns : ""}`).join("\n");
    yaml = insertNameserverPolicy(yaml, hostsEntries);
  }
  if (!needEch && !needGrpc) return yaml;
  const lines = yaml.split("\n");
  const processed = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.trim();
    if (trimmed.startsWith("- {")) {
      let fullNode = line;
      let braceCount = (line.match(/\{/g) || []).length - (line.match(/\}/g) || []).length;
      while (braceCount > 0 && i + 1 < lines.length) {
        i++;
        fullNode += "\n" + lines[i];
        braceCount += (lines[i].match(/\{/g) || []).length - (lines[i].match(/\}/g) || []).length;
      }
      if (needGrpc) fullNode = addFlowGrpcUserAgent(fullNode);
      if (needEch && getCredentialValue(fullNode, true) === uuid.trim()) {
        fullNode = fullNode.replace(
          /\}(\s*)$/,
          `, ech-opts: {enable: true${echSni ? `, query-server-name: ${echSni}` : ""}}}$1`
        );
      }
      processed.push(fullNode);
      i++;
    } else if (trimmed.startsWith("- name:")) {
      let nodeLines = [line];
      const baseIndent = line.search(/\S/);
      const topLevelIndent = baseIndent + 2;
      i++;
      while (i < lines.length) {
        const nextLine = lines[i];
        const nextTrimmed = nextLine.trim();
        if (!nextTrimmed) {
          nodeLines.push(nextLine);
          i++;
          break;
        }
        const nextIndent = nextLine.search(/\S/);
        if (nextIndent <= baseIndent && nextTrimmed.startsWith("- ")) break;
        if (nextIndent < baseIndent && nextTrimmed) break;
        nodeLines.push(nextLine);
        i++;
      }
      let nodeText = nodeLines.join("\n");
      if (needGrpc && matchesGrpcNetwork(nodeText)) {
        nodeLines = addBlockGrpcUserAgent(nodeLines, topLevelIndent);
        nodeText = nodeLines.join("\n");
      }
      if (needEch && getCredentialValue(nodeText, false) === uuid.trim()) {
        nodeLines = addBlockEchOpts(nodeLines, topLevelIndent);
      }
      processed.push(...nodeLines);
    } else {
      processed.push(line);
      i++;
    }
  }
  return processed.join("\n");
}

// src/subscription/singbox.ts
var DNS_PROTOCOL_MAP = {
  "tcp:": "tcp",
  "udp:": "udp",
  "tls:": "tls",
  "quic:": "quic",
  "https:": "https",
  "h3:": "h3"
};
var RCODE_MAP = {
  success: "NOERROR",
  format_error: "FORMERR",
  server_failure: "SERVFAIL",
  name_error: "NXDOMAIN",
  not_implemented: "NOTIMP",
  refused: "REFUSED"
};
async function patchSingboxSubscription(originalContent, configIn = {}) {
  const uuid = configIn?.UUID || null;
  const fingerprint = configIn?.Fingerprint || "chrome";
  const echEnabled = Boolean(configIn?.ECH);
  const echSni = configIn?.ECHConfig?.SNI || "cloudflare-ech.com";
  const sbJsonText = originalContent.replace("1.1.1.1", "8.8.8.8").replace("1.0.0.1", "8.8.4.4");
  try {
    const config = JSON.parse(sbJsonText);
    const arrayify = (v) => v === void 0 || v === null ? [] : Array.isArray(v) ? v : [v];
    const ensureRoute = () => {
      config.route = config.route && typeof config.route === "object" ? config.route : {};
      return config.route;
    };
    const getDnsRuleServer = (rule) => rule && typeof rule === "object" && !Array.isArray(rule) && typeof rule.server === "string" ? rule.server : null;
    const addRuleSet = (type, code) => {
      if (!code || typeof code !== "string") return null;
      const route = ensureRoute();
      const tag = `${type}-${code}`;
      const ruleSet = Array.isArray(route.rule_set) ? route.rule_set : arrayify(route.rule_set);
      if (!ruleSet.some((item) => item?.tag === tag)) {
        const legacyOptions = type === "geoip" ? route.geoip : route.geosite;
        ruleSet.push({
          tag,
          type: "remote",
          format: "binary",
          url: `https://raw.githubusercontent.com/SagerNet/sing-${type}/rule-set/${tag}.srs`,
          ...legacyOptions?.download_detour ? { download_detour: legacyOptions.download_detour } : {}
        });
        config.experimental = config.experimental && typeof config.experimental === "object" ? config.experimental : {};
        config.experimental.cache_file = config.experimental.cache_file && typeof config.experimental.cache_file === "object" ? config.experimental.cache_file : {};
        config.experimental.cache_file.enabled ??= true;
      }
      route.rule_set = ruleSet;
      return tag;
    };
    const migrateRuleSetFields = (rule) => {
      if (!rule || typeof rule !== "object" || Array.isArray(rule)) return rule;
      if (rule.type === "logical" && Array.isArray(rule.rules)) {
        rule.rules = rule.rules.map(migrateRuleSetFields);
        return rule;
      }
      const tags = [];
      for (const geoip of arrayify(rule.geoip)) {
        if (typeof geoip !== "string") continue;
        if (geoip.toLowerCase() === "private") rule.ip_is_private = true;
        else tags.push(addRuleSet("geoip", geoip));
      }
      for (const sourceGeoip of arrayify(rule.source_geoip)) {
        if (typeof sourceGeoip !== "string") continue;
        tags.push(addRuleSet("geoip", sourceGeoip));
        rule.rule_set_ip_cidr_match_source = true;
      }
      for (const geosite of arrayify(rule.geosite)) {
        if (typeof geosite === "string") tags.push(addRuleSet("geosite", geosite));
      }
      if (tags.length) {
        rule.rule_set = [...new Set([...arrayify(rule.rule_set), ...tags].filter(Boolean))];
      }
      delete rule.geoip;
      delete rule.source_geoip;
      delete rule.geosite;
      return rule;
    };
    const migrateDnsRule = (rule, rcodeServerMap) => {
      rule = migrateRuleSetFields(rule);
      if (!rule || typeof rule !== "object" || Array.isArray(rule)) return rule;
      if (rule.type === "logical" && Array.isArray(rule.rules)) {
        rule.rules = rule.rules.map((c) => migrateDnsRule(c, rcodeServerMap));
        return rule;
      }
      const serverTag = getDnsRuleServer(rule);
      if (serverTag && rcodeServerMap.has(serverTag)) {
        for (const key of [
          "server",
          "strategy",
          "disable_cache",
          "rewrite_ttl",
          "client_subnet",
          "timeout"
        ]) delete rule[key];
        rule.action = "predefined";
        rule.rcode = rcodeServerMap.get(serverTag);
      } else if (serverTag && !rule.action) {
        rule.action = "route";
      }
      return rule;
    };
    if (Array.isArray(config.inbounds)) {
      for (const inbound of config.inbounds) {
        if (!inbound || typeof inbound !== "object" || inbound.type !== "tun") continue;
        for (const migration of [
          { targetKey: "address", sourceKeys: ["inet4_address", "inet6_address"] },
          { targetKey: "route_address", sourceKeys: ["inet4_route_address", "inet6_route_address"] },
          {
            targetKey: "route_exclude_address",
            sourceKeys: ["inet4_route_exclude_address", "inet6_route_exclude_address"]
          }
        ]) {
          const values = arrayify(inbound[migration.targetKey]);
          for (const sourceKey of migration.sourceKeys) values.push(...arrayify(inbound[sourceKey]));
          if (values.length) inbound[migration.targetKey] = [...new Set(values)];
          for (const sourceKey of migration.sourceKeys) delete inbound[sourceKey];
        }
        if (inbound.tag) {
          const addedRules = [];
          if (inbound.domain_strategy) {
            addedRules.push({ inbound: inbound.tag, action: "resolve", strategy: inbound.domain_strategy });
          }
          if (inbound.sniff) {
            const sniffRule = { inbound: inbound.tag, action: "sniff" };
            if (inbound.sniff_timeout) sniffRule.timeout = inbound.sniff_timeout;
            addedRules.push(sniffRule);
          }
          if (addedRules.length) {
            const route = ensureRoute();
            route.rules = [...addedRules, ...arrayify(route.rules)];
          }
        }
        delete inbound.sniff;
        delete inbound.sniff_timeout;
        delete inbound.domain_strategy;
      }
    }
    if (config?.route && typeof config.route === "object" && Array.isArray(config.route.rules)) {
      const patchRoute = (rule) => {
        rule = migrateRuleSetFields(rule);
        if (rule?.type === "logical" && Array.isArray(rule.rules)) {
          rule.rules = rule.rules.map(patchRoute);
        } else if (rule && typeof rule === "object" && !Array.isArray(rule) && rule.outbound && !rule.action) {
          rule.action = "route";
        }
        return rule;
      };
      config.route.rules = config.route.rules.map(patchRoute);
    }
    const dns = config?.dns;
    if (dns && typeof dns === "object") {
      const legacyFakeIP = dns.fakeip && typeof dns.fakeip === "object" ? dns.fakeip : null;
      const rcodeServerMap = /* @__PURE__ */ new Map();
      let hasFakeIPServer = false;
      if (Array.isArray(dns.servers)) {
        const migratedServers = [];
        for (const originalServer of dns.servers) {
          if (!originalServer || typeof originalServer !== "object" || Array.isArray(originalServer)) {
            migratedServers.push(originalServer);
            continue;
          }
          const server = { ...originalServer };
          let parsedAddress = null;
          let parsedRCode = "";
          const rawAddress = typeof server.address === "string" ? server.address.trim() : "";
          if (rawAddress) {
            const lower = rawAddress.toLowerCase();
            if (lower === "fakeip") parsedAddress = { type: "fakeip" };
            else if (lower === "local") parsedAddress = { type: "local" };
            else if (lower.startsWith("rcode://")) {
              parsedAddress = { type: "rcode" };
              parsedRCode = rawAddress.slice("rcode://".length).toLowerCase();
            } else if (lower.startsWith("dhcp://")) {
              const iface = rawAddress.slice("dhcp://".length);
              parsedAddress = iface && iface.toLowerCase() !== "auto" ? { type: "dhcp", interface: iface } : { type: "dhcp" };
            } else {
              try {
                const u = new URL(rawAddress);
                const t = DNS_PROTOCOL_MAP[u.protocol.toLowerCase()];
                if (t) {
                  const ps = u.hostname?.startsWith("[") && u.hostname.endsWith("]") ? u.hostname.slice(1, -1) : u.hostname;
                  parsedAddress = {
                    type: t,
                    server: ps || u.host || rawAddress,
                    ...u.port ? { server_port: Number(u.port) } : {},
                    ...(t === "https" || t === "h3") && u.pathname && u.pathname !== "/dns-query" ? { path: u.pathname } : {}
                  };
                }
              } catch (_) {
              }
              if (!parsedAddress) parsedAddress = { type: "udp", server: rawAddress };
            }
          }
          if (parsedAddress?.type === "rcode") {
            const rcode = RCODE_MAP[parsedRCode] || "NOERROR";
            if (typeof server.tag === "string" && server.tag) {
              rcodeServerMap.set(server.tag, rcode);
              rcodeServerMap.set(
                server.tag.startsWith("dns_") ? server.tag.slice(4) : `dns_${server.tag}`,
                rcode
              );
            }
            continue;
          }
          if (parsedAddress) {
            delete server.address;
            Object.assign(server, parsedAddress);
          }
          if (server.address_resolver !== void 0 && server.domain_resolver === void 0)
            server.domain_resolver = server.address_resolver;
          if (server.address_strategy !== void 0 && server.domain_strategy === void 0)
            server.domain_strategy = server.address_strategy;
          delete server.address_resolver;
          delete server.address_strategy;
          if (server.detour === "DIRECT") delete server.detour;
          if (server.type === "fakeip") {
            hasFakeIPServer = true;
            if (legacyFakeIP) {
              for (const key of ["inet4_range", "inet6_range"]) {
                if (legacyFakeIP[key] !== void 0 && server[key] === void 0)
                  server[key] = legacyFakeIP[key];
              }
            }
          }
          migratedServers.push(server);
        }
        dns.servers = migratedServers;
      }
      if (legacyFakeIP && !hasFakeIPServer && legacyFakeIP.enabled !== false) {
        const fakeIPServer = { type: "fakeip", tag: "fakeip" };
        for (const rule of Array.isArray(dns.rules) ? dns.rules : []) {
          const serverTag = getDnsRuleServer(rule);
          if (serverTag && serverTag.toLowerCase().includes("fakeip")) {
            fakeIPServer.tag = serverTag;
            break;
          }
        }
        for (const key of ["inet4_range", "inet6_range"]) {
          if (legacyFakeIP[key] !== void 0) fakeIPServer[key] = legacyFakeIP[key];
        }
        if (Array.isArray(dns.servers)) dns.servers.push(fakeIPServer);
        else dns.servers = [fakeIPServer];
      }
      if (Array.isArray(dns.rules)) {
        const dnsRouteFields = /* @__PURE__ */ new Set([
          "outbound",
          "server",
          "action",
          "strategy",
          "disable_cache",
          "rewrite_ttl",
          "client_subnet",
          "timeout"
        ]);
        const migratedRules = [];
        for (const rule of dns.rules) {
          const serverTag = getDnsRuleServer(rule);
          const outbound = arrayify(rule?.outbound);
          const isOutboundAnyDNSRule = rule && typeof rule === "object" && !Array.isArray(rule) && rule.type !== "logical" && serverTag && outbound.includes("any") && Object.keys(rule).every((key) => dnsRouteFields.has(key));
          if (isOutboundAnyDNSRule) {
            const route = ensureRoute();
            if (route.default_domain_resolver === void 0) {
              const resolver = { server: serverTag };
              for (const key of [
                "strategy",
                "disable_cache",
                "rewrite_ttl",
                "client_subnet",
                "timeout"
              ]) {
                if (rule[key] !== void 0) resolver[key] = rule[key];
              }
              route.default_domain_resolver = Object.keys(resolver).length === 1 ? resolver.server : resolver;
            }
            continue;
          }
          migratedRules.push(migrateDnsRule(rule, rcodeServerMap));
        }
        dns.rules = migratedRules;
      }
      delete dns.fakeip;
      delete dns.independent_cache;
    }
    if (config?.route && typeof config.route === "object") {
      delete config.route.geoip;
      delete config.route.geosite;
    }
    if (config?.ntp?.detour === "DIRECT") delete config.ntp.detour;
    if (Array.isArray(config.outbounds)) {
      const outboundTags = new Set(
        config.outbounds.map((o) => o?.tag).filter(Boolean)
      );
      const refsReject = (value) => value === "REJECT" || value && typeof value === "object" && (Array.isArray(value) ? value.some(refsReject) : Object.values(value).some(refsReject));
      if (!outboundTags.has("REJECT") && refsReject({ outbounds: config.outbounds, route: config.route })) {
        config.outbounds.push({ type: "block", tag: "REJECT" });
      }
    }
    if (uuid) {
      config.outbounds?.forEach((outbound) => {
        if (outbound.uuid && outbound.uuid === uuid || outbound.password && outbound.password === uuid) {
          if (!outbound.tls) outbound.tls = { enabled: true };
          if (fingerprint) {
            outbound.tls.utls = { enabled: true, fingerprint };
          }
          if (echEnabled) {
            outbound.tls.ech = { enabled: true, query_server_name: echSni };
          }
        }
      });
    }
    return JSON.stringify(config, null, 2);
  } catch (e) {
    console.error("Singbox patch failed:", e);
    return JSON.stringify(JSON.parse(sbJsonText), null, 2);
  }
}

// src/subscription/surge.ts
function patchSurgeSubscription(content, url, config) {
  const lines = content.includes("\r\n") ? content.split("\r\n") : content.split("\n");
  const fullPath = config.randomPath ? randomPath(config.fullNodePath || "/") : config.fullNodePath || "/";
  let output = "";
  for (const x of lines) {
    if (x.includes("= trojan,") && !x.includes("ws=true") && !x.includes("ws-path=")) {
      const host = x.split("sni=")[1].split(",")[0];
      const orig = `sni=${host}, skip-cert-verify=${config.skipCertVerify}`;
      const fixed = `sni=${host}, skip-cert-verify=${config.skipCertVerify}, ws=true, ws-path=${fullPath.replace(/,/g, "%2C")}, ws-headers=Host:"${host}"`;
      output += x.replace(new RegExp(orig, "g"), fixed).replace("[", "").replace("]", "") + "\n";
    } else {
      output += x + "\n";
    }
  }
  const updateHours = config["preferredSub"]?.SUBUpdateTime ?? 6;
  output = `#!MANAGED-CONFIG ${url} interval=${updateHours * 60 * 60} strict=false` + output.substring(output.indexOf("\n"));
  return output;
}

// src/handlers/sub.ts
var PLACEHOLDER_UUID = "00000000-0000-4000-8000-000000000000";
var EXPIRE = 4102329600;
async function handleSubscription(ctx, env, request, url, host, userID, ua, accessIP, workerCtx) {
  const subToken = await md5x2(host + userID);
  const asPreferredSubGenerator = ["1", "true"].includes(env.BEST_SUB || "") && url.searchParams.get("host") === "example.com" && url.searchParams.get("uuid") === PLACEHOLDER_UUID && ua.toLowerCase().includes("tunnel (https://github.com/cmliu/edge");
  if (url.searchParams.get("token") !== subToken && !asPreferredSubGenerator) {
    return null;
  }
  const config = await readConfigJson(ctx, env, host, userID, ua);
  if (asPreferredSubGenerator) {
    workerCtx.waitUntil(
      logRequest(env, request, accessIP, "Get_Best_SUB", config, false)
    );
  } else {
    workerCtx.waitUntil(logRequest(env, request, accessIP, "Get_SUB", config));
  }
  const uaLower = ua.toLowerCase();
  const now = Date.now();
  const today = new Date(now);
  today.setHours(0, 0, 0, 0);
  const UD = Math.floor((now - today.getTime()) / 864e5 * 24 * 1099511627776 / 2);
  let pagesSum = UD;
  let workersSum = UD;
  let total = 24 * 1099511627776;
  if (config.CF.Usage.success) {
    pagesSum = config.CF.Usage.pages;
    workersSum = config.CF.Usage.workers;
    total = Number.isFinite(config.CF.Usage.max) ? config.CF.Usage.max / 1e3 * 1024 : 1024 * 100;
  }
  const responseHeaders = {
    "content-type": "text/plain; charset=utf-8",
    "Profile-Update-Interval": String(config.preferredSub.SUBUpdateTime),
    "Profile-web-page-url": url.protocol + "//" + url.host + "/admin",
    "Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${EXPIRE}`,
    "Cache-Control": "no-store"
  };
  const isSubConverterRequest = url.searchParams.has("b64") || url.searchParams.has("base64") || !!request.headers.get("subconverter-request") || !!request.headers.get("subconverter-version") || uaLower.includes("subconverter") || uaLower.includes("CF-Workers-SUB".toLowerCase()) || asPreferredSubGenerator;
  const subType = isSubConverterRequest ? "mixed" : url.searchParams.has("target") ? url.searchParams.get("target") : url.searchParams.has("clash") || uaLower.includes("clash") || uaLower.includes("meta") || uaLower.includes("mihomo") ? "clash" : url.searchParams.has("sb") || url.searchParams.has("singbox") || uaLower.includes("singbox") || uaLower.includes("sing-box") ? "singbox" : url.searchParams.has("surge") || uaLower.includes("surge") ? "surge&ver=4" : url.searchParams.has("quanx") || uaLower.includes("quantumult") ? "quanx" : url.searchParams.has("loon") || uaLower.includes("loon") ? "loon" : "mixed";
  if (!uaLower.includes("mozilla")) {
    responseHeaders["Content-Disposition"] = `attachment; filename*=utf-8''${encodeURIComponent(
      config.preferredSub.SUBNAME
    )}`;
  }
  const protoType = (url.searchParams.has("surge") || uaLower.includes("surge")) && config.protocol !== "ss" ? "trojan" : config.protocol;
  let subContent = "";
  if (subType === "mixed") {
    const tlsFragmentParam = config.tlsFragment == "Shadowrocket" ? `&fragment=${encodeURIComponent("1,40-60,30-50,tlshello")}` : config.tlsFragment == "Happ" ? `&fragment=${encodeURIComponent("3,1,tlshello")}` : "";
    let fullPreferredIPs = [];
    let otherNodeLinks = "";
    let proxyIPPool = [];
    if (!url.searchParams.has("sub") && config.preferredSub.local) {
      const fullList = config.preferredSub.localIP.randomIP ? (await generateRandomIPs(
        request,
        config.preferredSub.localIP.count,
        config.preferredSub.localIP.port,
        protoType === "ss" ? config.SS.TLS : true
      ))[0] : await env.KV.get("ADD.txt") ? toArray(await env.KV.get("ADD.txt") || "") : (await generateRandomIPs(
        request,
        config.preferredSub.localIP.count,
        config.preferredSub.localIP.port,
        protoType === "ss" ? config.SS.TLS : true
      ))[0];
      const apiList = [];
      const ipList = [];
      const otherNodes = [];
      for (const item of fullList) {
        if (item.toLowerCase().startsWith("sub://")) {
          apiList.push(item);
        } else {
          const subMatch = item.match(/sub\s*=\s*([^\s&#]+)/i);
          if (subMatch && subMatch[1].trim().includes(".")) {
            const asProxyIP = item.toLowerCase().includes("proxyip=true");
            if (asProxyIP) {
              apiList.push(
                "sub://" + subMatch[1].trim() + "?proxyip=true" + (item.includes("#") ? "#" + item.split("#")[1] : "")
              );
            } else {
              apiList.push(
                "sub://" + subMatch[1].trim() + (item.includes("#") ? "#" + item.split("#")[1] : "")
              );
            }
          } else if (item.toLowerCase().startsWith("https://")) {
            apiList.push(item);
          } else if (item.toLowerCase().includes("://")) {
            if (item.includes("#")) {
              const [addr, remark] = item.split("#");
              otherNodes.push(addr + "#" + encodeURIComponent(decodeURIComponent(remark)));
            } else {
              otherNodes.push(item);
            }
          } else {
            const hashIdx = item.indexOf("#");
            const addrPart = hashIdx > -1 ? item.slice(0, hashIdx) : item;
            if (addrPart.includes("*")) {
              const remarkPart = hashIdx > -1 ? item.slice(hashIdx) : "";
              ipList.push(replaceAsterisks(addrPart) + remarkPart);
            } else {
              ipList.push(item);
            }
          }
        }
      }
      const apiResult = await requestPreferredApi(
        apiList,
        protoType === "ss" && !config.SS.TLS ? "80" : "443"
      );
      const mergedOtherNodes = [...new Set(otherNodes.concat(apiResult[1]))];
      otherNodeLinks = mergedOtherNodes.length > 0 ? mergedOtherNodes.join("\n") + "\n" : "";
      const apiIPs = apiResult[0];
      proxyIPPool = apiResult[3] || [];
      fullPreferredIPs = [...new Set(ipList.concat(apiIPs))];
    } else {
      const generatorHost = url.searchParams.get("sub") || config.preferredSub.SUB;
      const [genIPs, genOtherNodes] = await fetchPreferredSubData(generatorHost);
      fullPreferredIPs = fullPreferredIPs.concat(genIPs);
      otherNodeLinks += genOtherNodes;
    }
    const echLinkParam = config.ECH ? `&ech=${encodeURIComponent(
      (config.ECHConfig.SNI ? config.ECHConfig.SNI + "+" : "") + config.ECHConfig.DNS
    )}` : "";
    const isLoonOrSurge = uaLower.includes("loon") || uaLower.includes("surge");
    const { type: transportProto, pathField, hostField } = getTransportConfig(config);
    subContent = otherNodeLinks + fullPreferredIPs.map((rawAddr) => {
      const regex = /^(\[[\da-fA-F:]+\]|[\d.]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(?::(\d+))?(?:#(.+))?$/;
      const match = rawAddr.match(regex);
      let nodeAddr;
      let nodePort = "443";
      let nodeRemark;
      if (match) {
        nodeAddr = match[1];
        nodePort = match[2] || (protoType === "ss" && !config.SS.TLS ? "80" : "443");
        nodeRemark = match[3] || nodeAddr;
      } else {
        console.warn(`[sub] invalid format ignored: ${rawAddr}`);
        return null;
      }
      let fullPath = config.fullNodePath;
      if (proxyIPPool.length > 0) {
        const matchedProxy = proxyIPPool.find((p) => p.includes(nodeAddr));
        if (matchedProxy) {
          fullPath = `${config.PATH}/proxyip=${matchedProxy}`.replace(/\/\//g, "/") + (config.enable0RTT ? "?ed=2560" : "");
        }
      }
      if (isLoonOrSurge) fullPath = fullPath.replace(/,/g, "%2C");
      if (protoType === "ss" && !asPreferredSubGenerator) {
        fullPath = (fullPath.includes("?") ? fullPath.replace("?", "?enc=" + config.SS.cipher + "&") : fullPath + "?enc=" + config.SS.cipher).replace(/([=,])/g, "\\$1");
        if (!isSubConverterRequest) fullPath = fullPath + ";mux=0";
        return `${protoType}://${btoa(config.SS.cipher + ":" + PLACEHOLDER_UUID)}@${nodeAddr}:${nodePort}?plugin=v2${encodeURIComponent(
          "ray-plugin;mode=websocket;host=example.com;path=" + (config.randomPath ? randomPath(fullPath) : fullPath) + (config.SS.TLS ? ";tls" : "")
        ) + echLinkParam + tlsFragmentParam}#${encodeURIComponent(nodeRemark)}`;
      } else {
        const transportPathValue = getTransportPath(
          config,
          fullPath,
          asPreferredSubGenerator
        );
        return `${protoType}://${PLACEHOLDER_UUID}@${nodeAddr}:${nodePort}?security=tls&type=${transportProto + echLinkParam}&${hostField}=example.com&fp=${config.Fingerprint}&sni=example.com&${pathField}=${encodeURIComponent(transportPathValue) + tlsFragmentParam}&encryption=none${config.skipCertVerify ? "&insecure=1&allowInsecure=1" : ""}#${encodeURIComponent(nodeRemark)}`;
      }
    }).filter((item) => item !== null).join("\n");
  } else {
    const subConvertURL = `${config.subConverter.SUBAPI}/sub?target=${subType}&url=${encodeURIComponent(
      url.protocol + "//" + url.host + "/sub?target=mixed&token=" + subToken + (url.searchParams.has("sub") && url.searchParams.get("sub") != "" ? `&sub=${url.searchParams.get("sub")}` : "")
    )}&config=${encodeURIComponent(config.subConverter.SUBCONFIG)}&emoji=${config.subConverter.SUBEMOJI}&scv=${config.skipCertVerify}`;
    try {
      const response = await fetch(subConvertURL, {
        headers: {
          "User-Agent": "Subconverter for " + subType + " edgetunnel (https://github.com/cmliu/edgetunnel)"
        }
      });
      if (response.ok) {
        subContent = await response.text();
        if (url.searchParams.has("surge") || uaLower.includes("surge")) {
          subContent = patchSurgeSubscription(
            subContent,
            url.protocol + "//" + url.host + "/sub?token=" + subToken + "&surge",
            config
          );
        }
      } else {
        return new Response("Subconverter backend error: " + response.statusText, {
          status: response.status
        });
      }
    } catch (error) {
      return new Response("Subconverter backend error: " + error.message, {
        status: 403
      });
    }
  }
  if (!uaLower.includes("subconverter") && !asPreferredSubGenerator) {
    subContent = bulkReplaceDomains(
      subContent.replace(/00000000-0000-4000-8000-000000000000/g, config.UUID).replace(/MDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDAw/g, btoa(config.UUID)),
      config.HOSTS
    );
  }
  if (subType === "mixed" && (!uaLower.includes("mozilla") || url.searchParams.has("b64") || url.searchParams.has("base64"))) {
    subContent = btoa(subContent);
  }
  if (subType === "singbox") {
    subContent = await patchSingboxSubscription(subContent, config);
    responseHeaders["content-type"] = "application/json; charset=utf-8";
  } else if (subType === "clash") {
    subContent = patchClashSubscription(subContent, config);
    responseHeaders["content-type"] = "application/x-yaml; charset=utf-8";
  }
  return new Response(subContent, { status: 200, headers: responseHeaders });
}

// src/utils/bytes.ts
var EMPTY_BYTES = new Uint8Array(0);
var textEncoder = new TextEncoder();
var textDecoder = new TextDecoder();
var tlsBytes = (...parts) => {
  const flatten = (values) => values.flatMap(
    (value) => value instanceof Uint8Array ? Array.from(value) : Array.isArray(value) ? flatten(value) : typeof value === "number" ? [value] : []
  );
  return new Uint8Array(flatten(parts));
};
var uint16be = (value) => [
  value >> 8 & 255,
  value & 255
];
var uint64be = (value) => {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, value, false);
  return bytes;
};
var readUint16 = (buffer, offset) => buffer[offset] << 8 | buffer[offset + 1];
var readUint24 = (buffer, offset) => buffer[offset] << 16 | buffer[offset + 1] << 8 | buffer[offset + 2];
var concatBytes = (...chunks) => {
  const nonEmpty = chunks.filter((c) => !!c && c.length > 0);
  const length = nonEmpty.reduce((total, c) => total + c.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const chunk of nonEmpty) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
};
var randomBytes = (length) => crypto.getRandomValues(new Uint8Array(length));
var constantTimeEqual = (left, right) => {
  if (!left || !right || left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i++) diff |= left[i] ^ right[i];
  return diff === 0;
};
var toUint8Array = (data) => {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  return new Uint8Array(data || 0);
};
var concatByteArrays = (...chunks) => {
  if (!chunks || chunks.length === 0) return EMPTY_BYTES;
  const normalised = chunks.map(toUint8Array);
  const total = normalised.reduce((sum, c) => sum + c.byteLength, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const c of normalised) {
    result.set(c, offset);
    offset += c.byteLength;
  }
  return result;
};
var byteLength = (data) => {
  if (!data) return 0;
  if (typeof data.byteLength === "number") return data.byteLength;
  if (typeof data.length === "number") return data.length;
  return 0;
};

// src/utils/hostname.ts
function stripIPv6Brackets(hostname = "") {
  const host = String(hostname || "").trim();
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}
function isIPHostname(hostname = "") {
  const host = stripIPv6Brackets(hostname);
  const ipv4Regex = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
  if (ipv4Regex.test(host)) return true;
  if (!host.includes(":")) return false;
  try {
    new URL(`http://[${host}]/`);
    return true;
  } catch (e) {
    return false;
  }
}
function isSpeedTestSite(hostname) {
  const speedTestDomains = [atob("c3BlZWQuY2xvdWRmbGFyZS5jb20=")];
  if (speedTestDomains.includes(hostname)) return true;
  for (const domain of speedTestDomains) {
    if (hostname.endsWith("." + domain) || hostname === domain) return true;
  }
  return false;
}

// src/protocols/vless.ts
function parseVlessRequest(chunk, token) {
  const buffer = chunk instanceof Uint8Array ? chunk.buffer.slice(chunk.byteOffset, chunk.byteOffset + chunk.byteLength) : chunk;
  if (buffer.byteLength < 24) return { hasError: true, message: "Invalid data" };
  const version = new Uint8Array(buffer.slice(0, 1));
  if (formatUuid(new Uint8Array(buffer.slice(1, 17))) !== token) {
    return { hasError: true, message: "Invalid uuid" };
  }
  const optLen = new Uint8Array(buffer.slice(17, 18))[0];
  const cmd = new Uint8Array(buffer.slice(18 + optLen, 19 + optLen))[0];
  let isUDP = false;
  if (cmd === 1) {
  } else if (cmd === 2) isUDP = true;
  else return { hasError: true, message: "Invalid command" };
  const portIdx = 19 + optLen;
  const port = new DataView(buffer.slice(portIdx, portIdx + 2)).getUint16(0);
  const addrTypeIdx = portIdx + 2;
  let addrValIdx = addrTypeIdx + 1;
  let addrLen = 0;
  let hostname = "";
  const addressType = new Uint8Array(buffer.slice(addrTypeIdx, addrValIdx))[0];
  switch (addressType) {
    case 1:
      addrLen = 4;
      hostname = new Uint8Array(buffer.slice(addrValIdx, addrValIdx + addrLen)).join(".");
      break;
    case 2:
      addrLen = new Uint8Array(buffer.slice(addrValIdx, addrValIdx + 1))[0];
      addrValIdx += 1;
      hostname = new TextDecoder().decode(buffer.slice(addrValIdx, addrValIdx + addrLen));
      break;
    case 3: {
      addrLen = 16;
      const view = new DataView(buffer.slice(addrValIdx, addrValIdx + addrLen));
      const groups = [];
      for (let i = 0; i < 8; i++) groups.push(view.getUint16(i * 2).toString(16));
      hostname = groups.join(":");
      break;
    }
    default:
      return { hasError: true, message: `Invalid address type: ${addressType}` };
  }
  if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` };
  return {
    hasError: false,
    addressType,
    port,
    hostname,
    isUDP,
    rawIndex: addrValIdx + addrLen,
    version
  };
}
function tryParseVlessFirstPacket(data, token) {
  const length = data.byteLength;
  if (length < 18) return { status: "need_more" };
  if (formatUuid(data.subarray(1, 17)) !== token) return { status: "invalid" };
  const optLen = data[17];
  const cmdIndex = 18 + optLen;
  if (length < cmdIndex + 1) return { status: "need_more" };
  const cmd = data[cmdIndex];
  if (cmd !== 1 && cmd !== 2) return { status: "invalid" };
  const portIndex = cmdIndex + 1;
  if (length < portIndex + 3) return { status: "need_more" };
  const port = data[portIndex] << 8 | data[portIndex + 1];
  const addressType = data[portIndex + 2];
  const addressIndex = portIndex + 3;
  let headerLen = -1;
  let hostname = "";
  if (addressType === 1) {
    if (length < addressIndex + 4) return { status: "need_more" };
    hostname = `${data[addressIndex]}.${data[addressIndex + 1]}.${data[addressIndex + 2]}.${data[addressIndex + 3]}`;
    headerLen = addressIndex + 4;
  } else if (addressType === 2) {
    if (length < addressIndex + 1) return { status: "need_more" };
    const domainLen = data[addressIndex];
    if (length < addressIndex + 1 + domainLen) return { status: "need_more" };
    hostname = new TextDecoder().decode(data.subarray(addressIndex + 1, addressIndex + 1 + domainLen));
    headerLen = addressIndex + 1 + domainLen;
  } else if (addressType === 3) {
    if (length < addressIndex + 16) return { status: "need_more" };
    const groups = [];
    for (let i = 0; i < 8; i++) {
      const base = addressIndex + i * 2;
      groups.push((data[base] << 8 | data[base + 1]).toString(16));
    }
    hostname = groups.join(":");
    headerLen = addressIndex + 16;
  } else {
    return { status: "invalid" };
  }
  if (!hostname) return { status: "invalid" };
  return {
    status: "ok",
    result: {
      protocol: "vless",
      hostname,
      port,
      isUDP: cmd === 2,
      rawData: data.subarray(headerLen),
      respHeader: new Uint8Array([data[0], 0])
    }
  };
}

// src/crypto/sha224.ts
var K = [
  1116352408,
  1899447441,
  3049323471,
  3921009573,
  961987163,
  1508970993,
  2453635748,
  2870763221,
  3624381080,
  310598401,
  607225278,
  1426881987,
  1925078388,
  2162078206,
  2614888103,
  3248222580,
  3835390401,
  4022224774,
  264347078,
  604807628,
  770255983,
  1249150122,
  1555081692,
  1996064986,
  2554220882,
  2821834349,
  2952996808,
  3210313671,
  3336571891,
  3584528711,
  113926993,
  338241895,
  666307205,
  773529912,
  1294757372,
  1396182291,
  1695183700,
  1986661051,
  2177026350,
  2456956037,
  2730485921,
  2820302411,
  3259730800,
  3345764771,
  3516065817,
  3600352804,
  4094571909,
  275423344,
  430227734,
  506948616,
  659060556,
  883997877,
  958139571,
  1322822218,
  1537002063,
  1747873779,
  1955562222,
  2024104815,
  2227730452,
  2361852424,
  2428436474,
  2756734187,
  3204031479,
  3329325298
];
var rotr = (n, b) => (n >>> b | n << 32 - b) >>> 0;
function sha224(input) {
  let s = unescape(encodeURIComponent(input));
  const messageLengthBits = s.length * 8;
  s += String.fromCharCode(128);
  while (s.length * 8 % 512 !== 448) s += String.fromCharCode(0);
  const h = [
    3238371032,
    914150663,
    812702999,
    4144912697,
    4290775857,
    1750603025,
    1694076839,
    3204075428
  ];
  const hi = Math.floor(messageLengthBits / 4294967296);
  const lo = messageLengthBits & 4294967295;
  s += String.fromCharCode(
    hi >>> 24 & 255,
    hi >>> 16 & 255,
    hi >>> 8 & 255,
    hi & 255,
    lo >>> 24 & 255,
    lo >>> 16 & 255,
    lo >>> 8 & 255,
    lo & 255
  );
  const w = [];
  for (let i = 0; i < s.length; i += 4) {
    w.push(
      s.charCodeAt(i) << 24 | s.charCodeAt(i + 1) << 16 | s.charCodeAt(i + 2) << 8 | s.charCodeAt(i + 3)
    );
  }
  for (let i = 0; i < w.length; i += 16) {
    const x = new Array(64).fill(0);
    for (let j = 0; j < 16; j++) x[j] = w[i + j];
    for (let j = 16; j < 64; j++) {
      const s0 = rotr(x[j - 15], 7) ^ rotr(x[j - 15], 18) ^ x[j - 15] >>> 3;
      const s1 = rotr(x[j - 2], 17) ^ rotr(x[j - 2], 19) ^ x[j - 2] >>> 10;
      x[j] = x[j - 16] + s0 + x[j - 7] + s1 >>> 0;
    }
    let [a, b, c, d, e, f, g, h0] = h;
    for (let j = 0; j < 64; j++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = e & f ^ ~e & g;
      const t1 = h0 + S1 + ch + K[j] + x[j] >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = a & b ^ a & c ^ b & c;
      const t2 = S0 + maj >>> 0;
      h0 = g;
      g = f;
      f = e;
      e = d + t1 >>> 0;
      d = c;
      c = b;
      b = a;
      a = t1 + t2 >>> 0;
    }
    const updates = [a, b, c, d, e, f, g, h0];
    for (let j = 0; j < 8; j++) {
      h[j] = h[j] + updates[j] >>> 0;
    }
  }
  let hex = "";
  for (let i = 0; i < 7; i++) {
    for (let j = 24; j >= 0; j -= 8) {
      hex += (h[i] >>> j & 255).toString(16).padStart(2, "0");
    }
  }
  return hex;
}

// src/protocols/trojan.ts
function parseTrojanRequest(buffer, password) {
  const buf = buffer instanceof Uint8Array ? buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength) : buffer;
  const expectedHash = sha224(password);
  if (buf.byteLength < 56) return { hasError: true, message: "invalid data" };
  const crLfIndex = 56;
  const byte56 = new Uint8Array(buf.slice(56, 57))[0];
  const byte57 = new Uint8Array(buf.slice(57, 58))[0];
  if (byte56 !== 13 || byte57 !== 10) {
    return { hasError: true, message: "invalid header format" };
  }
  const presentedHash = new TextDecoder().decode(buf.slice(0, crLfIndex));
  if (presentedHash !== expectedHash) {
    return { hasError: true, message: "invalid password" };
  }
  const socks5DataBuffer = buf.slice(crLfIndex + 2);
  if (socks5DataBuffer.byteLength < 6) {
    return { hasError: true, message: "invalid S5 request data" };
  }
  const view = new DataView(socks5DataBuffer);
  const cmd = view.getUint8(0);
  if (cmd !== 1 && cmd !== 3) {
    return { hasError: true, message: "unsupported command, only TCP/UDP is allowed" };
  }
  const isUDP = cmd === 3;
  const atype = view.getUint8(1);
  let addressLength = 0;
  let addressIndex = 2;
  let address = "";
  switch (atype) {
    case 1:
      addressLength = 4;
      address = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)).join(".");
      break;
    case 3:
      addressLength = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + 1))[0];
      addressIndex += 1;
      address = new TextDecoder().decode(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
      break;
    case 4: {
      addressLength = 16;
      const dataView = new DataView(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
      const groups = [];
      for (let i = 0; i < 8; i++) groups.push(dataView.getUint16(i * 2).toString(16));
      address = groups.join(":");
      break;
    }
    default:
      return { hasError: true, message: `invalid addressType is ${atype}` };
  }
  if (!address) {
    return { hasError: true, message: `address is empty, addressType is ${atype}` };
  }
  const portIndex = addressIndex + addressLength;
  const portBuffer = socks5DataBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);
  return {
    hasError: false,
    addressType: atype,
    port: portRemote,
    hostname: address,
    isUDP,
    rawClientData: socks5DataBuffer.slice(portIndex + 4)
  };
}
function tryParseTrojanFirstPacket(data, password) {
  const expectedHash = sha224(password);
  const expectedHashBytes = new TextEncoder().encode(expectedHash);
  const length = data.byteLength;
  if (length < 58) return { status: "need_more" };
  if (data[56] !== 13 || data[57] !== 10) return { status: "invalid" };
  for (let i = 0; i < 56; i++) {
    if (data[i] !== expectedHashBytes[i]) return { status: "invalid" };
  }
  const socksStart = 58;
  if (length < socksStart + 2) return { status: "need_more" };
  const cmd = data[socksStart];
  if (cmd !== 1 && cmd !== 3) return { status: "invalid" };
  const isUDP = cmd === 3;
  const atype = data[socksStart + 1];
  let cursor = socksStart + 2;
  let hostname = "";
  if (atype === 1) {
    if (length < cursor + 4) return { status: "need_more" };
    hostname = `${data[cursor]}.${data[cursor + 1]}.${data[cursor + 2]}.${data[cursor + 3]}`;
    cursor += 4;
  } else if (atype === 3) {
    if (length < cursor + 1) return { status: "need_more" };
    const domainLen = data[cursor];
    if (length < cursor + 1 + domainLen) return { status: "need_more" };
    hostname = new TextDecoder().decode(data.subarray(cursor + 1, cursor + 1 + domainLen));
    cursor += 1 + domainLen;
  } else if (atype === 4) {
    if (length < cursor + 16) return { status: "need_more" };
    const groups = [];
    for (let i = 0; i < 8; i++) {
      const base = cursor + i * 2;
      groups.push((data[base] << 8 | data[base + 1]).toString(16));
    }
    hostname = groups.join(":");
    cursor += 16;
  } else {
    return { status: "invalid" };
  }
  if (!hostname) return { status: "invalid" };
  if (length < cursor + 4) return { status: "need_more" };
  const port = data[cursor] << 8 | data[cursor + 1];
  if (data[cursor + 2] !== 13 || data[cursor + 3] !== 10) return { status: "invalid" };
  const dataOffset = cursor + 4;
  return {
    status: "ok",
    result: {
      protocol: "trojan",
      hostname,
      port,
      isUDP,
      rawData: data.subarray(dataOffset),
      respHeader: null
    }
  };
}

// src/transports/direct.ts
import { connect as connect3 } from "cloudflare:sockets";

// src/transports/socks5.ts
import { connect } from "cloudflare:sockets";
async function socks5Connect(ctx, targetHost, targetPort, initialData) {
  const { username, password, hostname, port } = ctx.parsedSocks5;
  const socket = connect({ hostname, port });
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  try {
    const authMethods = username && password ? new Uint8Array([5, 2, 0, 2]) : new Uint8Array([5, 1, 0]);
    await writer.write(authMethods);
    let response = await reader.read();
    if (response.done || response.value.byteLength < 2) {
      throw new Error("S5 method selection failed");
    }
    const selectedMethod = new Uint8Array(response.value)[1];
    if (selectedMethod === 2) {
      if (!username || !password) throw new Error("S5 requires authentication");
      const userBytes = new TextEncoder().encode(username);
      const passBytes = new TextEncoder().encode(password);
      const authPacket = new Uint8Array([
        1,
        userBytes.length,
        ...userBytes,
        passBytes.length,
        ...passBytes
      ]);
      await writer.write(authPacket);
      response = await reader.read();
      if (response.done || new Uint8Array(response.value)[1] !== 0) {
        throw new Error("S5 authentication failed");
      }
    } else if (selectedMethod !== 0) {
      throw new Error(`S5 unsupported auth method: ${selectedMethod}`);
    }
    const hostBytes = new TextEncoder().encode(targetHost);
    const connectPacket = new Uint8Array([
      5,
      1,
      0,
      3,
      hostBytes.length,
      ...hostBytes,
      targetPort >> 8,
      targetPort & 255
    ]);
    await writer.write(connectPacket);
    response = await reader.read();
    if (response.done || new Uint8Array(response.value)[1] !== 0) {
      throw new Error("S5 connection failed");
    }
    if (byteLength(initialData) > 0 && initialData) {
      await writer.write(initialData);
    }
    writer.releaseLock();
    reader.releaseLock();
    return socket;
  } catch (error) {
    try {
      writer.releaseLock();
    } catch (e) {
    }
    try {
      reader.releaseLock();
    } catch (e) {
    }
    try {
      socket.close();
    } catch (e) {
    }
    throw error;
  }
}

// src/transports/http-connect.ts
import { connect as connect2 } from "cloudflare:sockets";
async function httpConnect(ctx, targetHost, targetPort, initialData, httpsProxy = false) {
  const { username, password, hostname, port } = ctx.parsedSocks5;
  const socket = httpsProxy ? connect2({ hostname, port }, { secureTransport: "on", allowHalfOpen: false }) : connect2({ hostname, port });
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  try {
    if (httpsProxy) await socket.opened;
    const auth = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r
` : "";
    const request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r
Host: ${targetHost}:${targetPort}\r
` + auth + `User-Agent: Mozilla/5.0\r
Connection: keep-alive\r
\r
`;
    await writer.write(encoder.encode(request));
    writer.releaseLock();
    let responseBuffer = new Uint8Array(0);
    let headerEndIndex = -1;
    let bytesRead = 0;
    while (headerEndIndex === -1 && bytesRead < 8192) {
      const { done, value } = await reader.read();
      if (done || !value) {
        throw new Error(
          `${httpsProxy ? "HTTPS" : "HTTP"} proxy closed connection before CONNECT response`
        );
      }
      responseBuffer = new Uint8Array([...responseBuffer, ...value]);
      bytesRead = responseBuffer.length;
      const idx = responseBuffer.findIndex(
        (_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 13 && responseBuffer[i + 1] === 10 && responseBuffer[i + 2] === 13 && responseBuffer[i + 3] === 10
      );
      if (idx !== -1) headerEndIndex = idx + 4;
    }
    if (headerEndIndex === -1) {
      throw new Error("Proxy CONNECT response too long or invalid");
    }
    const statusLine = decoder.decode(responseBuffer.slice(0, headerEndIndex)).split("\r\n")[0];
    const statusMatch = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
    const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
    if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) {
      throw new Error(`Connection failed: HTTP ${statusCode}`);
    }
    reader.releaseLock();
    if (byteLength(initialData) > 0 && initialData) {
      const w = socket.writable.getWriter();
      await w.write(initialData);
      w.releaseLock();
    }
    if (bytesRead > headerEndIndex) {
      const { readable, writable } = new TransformStream();
      const transformWriter = writable.getWriter();
      await transformWriter.write(responseBuffer.subarray(headerEndIndex, bytesRead));
      transformWriter.releaseLock();
      socket.readable.pipeTo(writable).catch(() => {
      });
      return {
        readable,
        writable: socket.writable,
        closed: socket.closed,
        close: () => socket.close()
      };
    }
    return socket;
  } catch (error) {
    try {
      writer.releaseLock();
    } catch (e) {
    }
    try {
      reader.releaseLock();
    } catch (e) {
    }
    try {
      socket.close();
    } catch (e) {
    }
    throw error;
  }
}

// src/transports/socket-utils.ts
var CONNECT_TIMEOUT_MS = 1e3;
function closeSocketQuietly(socket) {
  try {
    if (socket?.readyState === WebSocket.OPEN || socket?.readyState === WebSocket.CLOSING) {
      socket.close();
    }
  } catch (error) {
  }
}
async function wsSendAndWait(webSocket, payload) {
  const sendResult = webSocket.send(payload);
  if (sendResult && typeof sendResult.then === "function") await sendResult;
}
async function waitConnect(remoteSock, timeoutMs = CONNECT_TIMEOUT_MS) {
  await Promise.race([
    remoteSock.opened,
    new Promise(
      (_, reject) => setTimeout(() => reject(new Error("connection timeout")), timeoutMs)
    )
  ]);
}

// src/transports/byob-stream.ts
var BYOB_BUFFER_SIZE = 512 * 1024;
var BYOB_READ_LIMIT = 64 * 1024;
var BYOB_HIGH_THROUGHPUT_THRESHOLD = 50 * 1024 * 1024;
var NORMAL_AGGREGATION_THRESHOLD = 128 * 1024;
var NORMAL_FLUSH_INTERVAL = 2;
var BYOB_SLOW_FLUSH_INTERVAL = 20;
var BYOB_FAST_FLUSH_INTERVAL = 2;
var BYOB_SAFE_THRESHOLD = BYOB_BUFFER_SIZE - BYOB_READ_LIMIT;
async function connectStreams(remoteSocket, webSocket, headerData, retryFunc, log = () => {
}) {
  let header = headerData;
  let hasData = false;
  let reader;
  let useBYOB = false;
  const sendChunk = async (chunk) => {
    if (webSocket.readyState !== WebSocket.OPEN) throw new Error("ws.readyState is not open");
    if (header) {
      const merged = new Uint8Array(header.length + chunk.byteLength);
      merged.set(header, 0);
      merged.set(chunk, header.length);
      await wsSendAndWait(webSocket, merged.buffer);
      header = null;
    } else {
      await wsSendAndWait(webSocket, chunk);
    }
  };
  try {
    reader = remoteSocket.readable.getReader({ mode: "byob" });
    useBYOB = true;
  } catch (e) {
    reader = remoteSocket.readable.getReader();
  }
  try {
    if (!useBYOB) {
      await runNormalLoop(reader, sendChunk, webSocket, () => {
        hasData = true;
      });
    } else {
      await runByobLoop(reader, sendChunk, webSocket, log, () => {
        hasData = true;
      });
    }
  } catch (err) {
    closeSocketQuietly(webSocket);
  } finally {
    try {
      reader.cancel();
    } catch (e) {
    }
    try {
      reader.releaseLock();
    } catch (e) {
    }
  }
  if (!hasData && retryFunc) await retryFunc();
}
async function runNormalLoop(reader, sendChunk, webSocket, markHasData) {
  let pendingChunks = [];
  let pendingBytes = 0;
  let flushTimer = null;
  let flushTask = null;
  const flush = async () => {
    if (flushTask) return flushTask;
    flushTask = (async () => {
      if (flushTimer) {
        clearTimeout(flushTimer);
        flushTimer = null;
      }
      if (pendingBytes <= 0) return;
      const chunks = pendingChunks;
      const bytes = pendingBytes;
      pendingChunks = [];
      pendingBytes = 0;
      const payload = chunks.length === 1 ? chunks[0] : concatByteArrays(...chunks);
      if (payload.byteLength || bytes > 0) await sendChunk(payload);
    })().finally(() => {
      flushTask = null;
    });
    return flushTask;
  };
  const pushChunk = async (chunk) => {
    const bytes = toUint8Array(chunk);
    if (!bytes.byteLength) return;
    pendingChunks.push(bytes);
    pendingBytes += bytes.byteLength;
    if (pendingBytes >= NORMAL_AGGREGATION_THRESHOLD) {
      await flush();
      if (pendingBytes >= NORMAL_AGGREGATION_THRESHOLD) await flush();
    } else if (!flushTimer) {
      flushTimer = setTimeout(() => {
        flush().catch(() => closeSocketQuietly(webSocket));
      }, NORMAL_FLUSH_INTERVAL);
    }
  };
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value || value.byteLength === 0) continue;
    markHasData();
    await pushChunk(value);
  }
  await flush();
}
async function runByobLoop(reader, sendChunk, webSocket, log, markHasData) {
  let mainBuf = new ArrayBuffer(BYOB_BUFFER_SIZE);
  let offset = 0;
  let totalBytes = 0;
  let flushIntervalMs = BYOB_FAST_FLUSH_INTERVAL;
  let flushTimer = null;
  let resumeFlush = null;
  let isReading = false;
  let pendingFlushDuringRead = false;
  const flush = async () => {
    if (isReading) {
      pendingFlushDuringRead = true;
      return;
    }
    try {
      if (offset > 0) {
        const payload = new Uint8Array(mainBuf.slice(0, offset));
        offset = 0;
        await sendChunk(payload);
      }
    } finally {
      pendingFlushDuringRead = false;
      if (flushTimer) {
        clearTimeout(flushTimer);
        flushTimer = null;
      }
      if (resumeFlush) {
        const r = resumeFlush;
        resumeFlush = null;
        r();
      }
    }
  };
  while (true) {
    isReading = true;
    const { done, value } = await reader.read(new Uint8Array(mainBuf, offset, BYOB_READ_LIMIT));
    isReading = false;
    if (done) break;
    if (!value || value.byteLength === 0) {
      if (pendingFlushDuringRead) await flush();
      continue;
    }
    markHasData();
    mainBuf = value.buffer;
    const len = value.byteLength;
    if (value.byteOffset !== offset) {
      log(`[BYOB] offset mismatch: expected=${offset}, actual=${value.byteOffset}`);
      await sendChunk(new Uint8Array(value.buffer, value.byteOffset, len).slice());
      mainBuf = new ArrayBuffer(BYOB_BUFFER_SIZE);
      offset = 0;
      totalBytes = 0;
      continue;
    }
    if (len < BYOB_READ_LIMIT) {
      flushIntervalMs = BYOB_FAST_FLUSH_INTERVAL;
      if (len < 4096) totalBytes = 0;
      if (offset > 0) {
        offset += len;
        await flush();
      } else {
        await sendChunk(value.slice());
      }
    } else {
      totalBytes += len;
      offset += len;
      if (!flushTimer) {
        flushTimer = setTimeout(() => {
          flush().catch(() => closeSocketQuietly(webSocket));
        }, flushIntervalMs);
      }
      if (pendingFlushDuringRead) await flush();
      if (offset > BYOB_SAFE_THRESHOLD) {
        if (totalBytes > BYOB_HIGH_THROUGHPUT_THRESHOLD) {
          flushIntervalMs = BYOB_SLOW_FLUSH_INTERVAL;
        }
        await new Promise((r) => {
          resumeFlush = r;
        });
      }
    }
  }
  isReading = false;
  await flush();
  if (flushTimer) {
    clearTimeout(flushTimer);
    flushTimer = null;
  }
}

// src/transports/direct.ts
async function connectDirect(ctx, log, ws, address, port, data = null, proxyArray = null, fallbackToDirect = true) {
  let remoteSock;
  if (proxyArray && proxyArray.length > 0) {
    for (let i = 0; i < proxyArray.length; i++) {
      const idx = (ctx.cachedProxyIndex + i) % proxyArray.length;
      const [proxyHost, proxyPort] = proxyArray[idx];
      try {
        log(`[proxy] connect attempt: ${proxyHost}:${proxyPort} (idx=${idx})`);
        remoteSock = connect3({ hostname: proxyHost, port: proxyPort });
        await waitConnect(remoteSock);
        if (byteLength(data) > 0 && data) {
          const w = remoteSock.writable.getWriter();
          await w.write(data);
          w.releaseLock();
        }
        log(`[proxy] connected to: ${proxyHost}:${proxyPort}`);
        ctx.cachedProxyIndex = idx;
        return remoteSock;
      } catch (err) {
        log(`[proxy] connect failed: ${proxyHost}:${proxyPort}, error: ${err?.message}`);
        try {
          remoteSock?.close?.();
        } catch (e) {
        }
        continue;
      }
    }
  }
  if (fallbackToDirect) {
    remoteSock = connect3({ hostname: address, port });
    await waitConnect(remoteSock);
    if (byteLength(data) > 0 && data) {
      const w = remoteSock.writable.getWriter();
      await w.write(data);
      w.releaseLock();
    }
    return remoteSock;
  }
  closeSocketQuietly(ws);
  throw new Error("[proxy] all proxy connections failed and fallback disabled");
}
function matchSocks5Whitelist(hostname, whitelist) {
  return whitelist.some((pattern) => {
    const regex = new RegExp(`^${pattern.replace(/\*/g, ".*")}$`, "i");
    return regex.test(hostname);
  });
}
async function forwardTcp(deps, host, portNum, rawData, ws, respHeader, remoteConnWrapper, yourUUID) {
  const { ctx, log, resolveProxyIPs, httpsConnect: httpsConnectImpl } = deps;
  log(
    `[TCP] target: ${host}:${portNum} | proxyIP: ${ctx.proxyIP} | fallback: ${ctx.proxyFallbackEnabled ? "yes" : "no"} | mode: ${ctx.socks5Mode || "proxyip"} | global: ${ctx.socks5GlobalEnabled ? "yes" : "no"}`
  );
  let firstPacketSentViaProxy = false;
  async function connectThroughProxy(allowSendFirstPacket = true) {
    if (remoteConnWrapper.connectingPromise) {
      await remoteConnWrapper.connectingPromise;
      return;
    }
    const sendFirstThisAttempt = allowSendFirstPacket && !firstPacketSentViaProxy && byteLength(rawData) > 0;
    const firstPacketData = sendFirstThisAttempt ? rawData : null;
    const task = (async () => {
      let newSocket;
      if (ctx.socks5Mode === "socks5") {
        log(`[SOCKS5] forwarding to: ${host}:${portNum}`);
        newSocket = await socks5Connect(ctx, host, portNum, firstPacketData);
      } else if (ctx.socks5Mode === "http") {
        log(`[HTTP-CONNECT] forwarding to: ${host}:${portNum}`);
        newSocket = await httpConnect(ctx, host, portNum, firstPacketData);
      } else if (ctx.socks5Mode === "https") {
        log(`[HTTPS-CONNECT] forwarding to: ${host}:${portNum}`);
        if (!httpsConnectImpl) {
          throw new Error("HTTPS-CONNECT not configured (Phase 4 dependency)");
        }
        newSocket = isIPHostname(ctx.parsedSocks5.hostname) ? await httpsConnectImpl(ctx, host, portNum, firstPacketData) : await httpConnect(ctx, host, portNum, firstPacketData, true);
      } else {
        log(`[proxyIP] forwarding to: ${host}:${portNum}`);
        const proxyArray = await resolveProxyIPs(ctx.proxyIP, host, yourUUID);
        const placeholderHost = atob("UFJPWFlJUC50cDEuMDkwMjI3Lnh5eg==");
        newSocket = await connectDirect(
          ctx,
          log,
          ws,
          placeholderHost,
          1,
          firstPacketData,
          proxyArray,
          ctx.proxyFallbackEnabled
        );
      }
      if (sendFirstThisAttempt) firstPacketSentViaProxy = true;
      remoteConnWrapper.socket = newSocket;
      newSocket.closed.catch(() => {
      }).finally(() => closeSocketQuietly(ws));
      connectStreams(newSocket, ws, respHeader, null, log);
    })();
    remoteConnWrapper.connectingPromise = task;
    try {
      await task;
    } finally {
      if (remoteConnWrapper.connectingPromise === task) {
        remoteConnWrapper.connectingPromise = null;
      }
    }
  }
  remoteConnWrapper.retryConnect = async () => connectThroughProxy(!firstPacketSentViaProxy);
  const useProxyChain = ctx.socks5Mode && (ctx.socks5GlobalEnabled || matchSocks5Whitelist(host, ctx.socks5Whitelist));
  if (useProxyChain) {
    log("[TCP] using SOCKS5/HTTP/HTTPS proxy chain");
    try {
      await connectThroughProxy();
    } catch (err) {
      log(`[TCP] proxy chain failed: ${err?.message}`);
      throw err;
    }
  } else {
    try {
      log(`[TCP] direct connect: ${host}:${portNum}`);
      const initialSocket = await connectDirect(ctx, log, ws, host, portNum, rawData);
      remoteConnWrapper.socket = initialSocket;
      connectStreams(initialSocket, ws, respHeader, async () => {
        if (remoteConnWrapper.socket !== initialSocket) return;
        await connectThroughProxy();
      }, log);
    } catch (err) {
      log(`[TCP] direct connect failed ${host}:${portNum}: ${err?.message}`);
      await connectThroughProxy();
    }
  }
}

// src/transports/udp.ts
import { connect as connect4 } from "cloudflare:sockets";
async function forwardUdpToDns(udpChunk, webSocket, respHeader, responseWrapper = null, log = () => {
}) {
  const requestData = toUint8Array(udpChunk);
  const requestBytes = requestData.byteLength;
  log(`[UDP] DNS query: ${requestBytes}B -> 8.8.4.4:53`);
  try {
    const tcpSocket = connect4({ hostname: "8.8.4.4", port: 53 });
    let pendingHeader = respHeader;
    const writer = tcpSocket.writable.getWriter();
    await writer.write(requestData);
    log(`[UDP] DNS query written: ${requestBytes}B`);
    writer.releaseLock();
    await tcpSocket.readable.pipeTo(
      new WritableStream({
        async write(chunk) {
          const rawResponse = toUint8Array(chunk);
          log(`[UDP] DNS response: ${rawResponse.byteLength}B`);
          const wrapped = responseWrapper ? await responseWrapper(rawResponse) : rawResponse;
          const fragments = Array.isArray(wrapped) ? wrapped : [wrapped];
          if (!fragments.length) return;
          if (webSocket.readyState !== WebSocket.OPEN) return;
          for (const fragment of fragments) {
            const out = toUint8Array(fragment);
            if (!out.byteLength) continue;
            if (pendingHeader) {
              const merged = new Uint8Array(pendingHeader.length + out.byteLength);
              merged.set(pendingHeader, 0);
              merged.set(out, pendingHeader.length);
              await wsSendAndWait(webSocket, merged.buffer);
              pendingHeader = null;
            } else {
              await wsSendAndWait(webSocket, out);
            }
          }
        }
      })
    );
  } catch (error) {
    log(`[UDP] DNS forwarding failed: ${error?.message || error}`);
  }
}
async function forwardTrojanUdp(chunk, webSocket, ctx, log = () => {
}) {
  const currentChunk = toUint8Array(chunk);
  const cached = ctx?.buffer instanceof Uint8Array ? ctx.buffer : new Uint8Array(0);
  const input = cached.byteLength ? concatByteArrays(cached, currentChunk) : currentChunk;
  let cursor = 0;
  while (cursor < input.byteLength) {
    const packetStart = cursor;
    const atype = input[cursor];
    let addrCursor = cursor + 1;
    let addrLen = 0;
    if (atype === 1) addrLen = 4;
    else if (atype === 4) addrLen = 16;
    else if (atype === 3) {
      if (input.byteLength < addrCursor + 1) break;
      addrLen = 1 + input[addrCursor];
    } else {
      throw new Error(`invalid trojan udp addressType: ${atype}`);
    }
    const portCursor = addrCursor + addrLen;
    if (input.byteLength < portCursor + 6) break;
    const port = input[portCursor] << 8 | input[portCursor + 1];
    const payloadLength = input[portCursor + 2] << 8 | input[portCursor + 3];
    if (input[portCursor + 4] !== 13 || input[portCursor + 5] !== 10) {
      throw new Error("invalid trojan udp delimiter");
    }
    const payloadStart = portCursor + 6;
    const payloadEnd = payloadStart + payloadLength;
    if (input.byteLength < payloadEnd) break;
    const addrPortHeader = input.slice(packetStart, portCursor + 2);
    const payload = input.slice(payloadStart, payloadEnd);
    cursor = payloadEnd;
    if (port !== 53) throw new Error("UDP is not supported");
    if (!payload.byteLength) continue;
    let tcpDnsQuery = payload;
    if (payload.byteLength < 2 || (payload[0] << 8 | payload[1]) !== payload.byteLength - 2) {
      tcpDnsQuery = new Uint8Array(payload.byteLength + 2);
      tcpDnsQuery[0] = payload.byteLength >>> 8 & 255;
      tcpDnsQuery[1] = payload.byteLength & 255;
      tcpDnsQuery.set(payload, 2);
    }
    const responseCtx = { buffer: new Uint8Array(0) };
    await forwardUdpToDns(
      tcpDnsQuery,
      webSocket,
      null,
      (dnsRespChunk) => {
        const respChunk = toUint8Array(dnsRespChunk);
        const respInput = responseCtx.buffer.byteLength ? concatByteArrays(responseCtx.buffer, respChunk) : respChunk;
        const frames = [];
        let respCursor = 0;
        while (respCursor + 2 <= respInput.byteLength) {
          const dnsLen = respInput[respCursor] << 8 | respInput[respCursor + 1];
          const dnsStart = respCursor + 2;
          const dnsEnd = dnsStart + dnsLen;
          if (dnsEnd > respInput.byteLength) break;
          const dnsPayload = respInput.slice(dnsStart, dnsEnd);
          const frame = new Uint8Array(addrPortHeader.byteLength + 4 + dnsPayload.byteLength);
          frame.set(addrPortHeader, 0);
          frame[addrPortHeader.byteLength] = dnsPayload.byteLength >>> 8 & 255;
          frame[addrPortHeader.byteLength + 1] = dnsPayload.byteLength & 255;
          frame[addrPortHeader.byteLength + 2] = 13;
          frame[addrPortHeader.byteLength + 3] = 10;
          frame.set(dnsPayload, addrPortHeader.byteLength + 4);
          frames.push(frame);
          respCursor = dnsEnd;
        }
        responseCtx.buffer = respInput.slice(respCursor);
        return frames.length ? frames : new Uint8Array(0);
      },
      log
    );
  }
  if (ctx) ctx.buffer = input.slice(cursor);
}

// src/protocols/shadowsocks.ts
var ssTextEncoder = new TextEncoder();
var masterKeyCache = /* @__PURE__ */ new Map();
function ssIncrementNonce(counter) {
  for (let i = 0; i < counter.length; i++) {
    counter[i] = counter[i] + 1 & 255;
    if (counter[i] !== 0) return;
  }
}
async function ssDeriveMasterKey(passwordText, keyLen) {
  const cacheKey = `${keyLen}:${passwordText}`;
  const cached = masterKeyCache.get(cacheKey);
  if (cached) return cached;
  const task = (async () => {
    const pwBytes = ssTextEncoder.encode(passwordText || "");
    let prev = new Uint8Array(0);
    let result = new Uint8Array(0);
    while (result.byteLength < keyLen) {
      const input = new Uint8Array(prev.byteLength + pwBytes.byteLength);
      input.set(prev, 0);
      input.set(pwBytes, prev.byteLength);
      prev = new Uint8Array(await crypto.subtle.digest("MD5", input));
      result = concatByteArrays(result, prev);
    }
    return result.slice(0, keyLen);
  })();
  masterKeyCache.set(cacheKey, task);
  try {
    return await task;
  } catch (err) {
    masterKeyCache.delete(cacheKey);
    throw err;
  }
}
async function ssDeriveSessionKey(config, masterKey, salt, usages) {
  const hmacOpts = { name: "HMAC", hash: "SHA-1" };
  const saltKey = await crypto.subtle.importKey("raw", salt, hmacOpts, false, ["sign"]);
  const prk = new Uint8Array(await crypto.subtle.sign("HMAC", saltKey, masterKey));
  const prkKey = await crypto.subtle.importKey("raw", prk, hmacOpts, false, ["sign"]);
  const subKey = new Uint8Array(config.keyLen);
  let prev = new Uint8Array(0);
  let written = 0;
  let counter = 1;
  while (written < config.keyLen) {
    const input = concatByteArrays(prev, SS_SUBKEY_INFO, new Uint8Array([counter]));
    prev = new Uint8Array(await crypto.subtle.sign("HMAC", prkKey, input));
    const copyLen = Math.min(prev.byteLength, config.keyLen - written);
    subKey.set(prev.subarray(0, copyLen), written);
    written += copyLen;
    counter += 1;
  }
  return crypto.subtle.importKey(
    "raw",
    subKey,
    { name: "AES-GCM", length: config.aesLength },
    false,
    usages
  );
}
async function ssAeadEncrypt(cryptoKey, nonceCounter, plaintext) {
  const iv = nonceCounter.slice();
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, tagLength: 128 },
    cryptoKey,
    plaintext
  );
  ssIncrementNonce(nonceCounter);
  return new Uint8Array(ct);
}
async function ssAeadDecrypt(cryptoKey, nonceCounter, ciphertext) {
  const iv = nonceCounter.slice();
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, tagLength: 128 },
    cryptoKey,
    ciphertext
  );
  ssIncrementNonce(nonceCounter);
  return new Uint8Array(pt);
}

// src/handlers/ss-inbound.ts
var ssTextDecoder = new TextDecoder();
function createSsInbound(serverSock, yourUUID, requestedEnc, log) {
  const preferredCipher = SS_CIPHERS[requestedEnc] || SS_CIPHERS["aes-128-gcm"];
  const candidateCiphers = [
    preferredCipher,
    ...Object.values(SS_CIPHERS).filter((c) => c.method !== preferredCipher.method)
  ];
  const masterKeyTaskCache = /* @__PURE__ */ new Map();
  const getMasterKeyTask = (config) => {
    if (!masterKeyTaskCache.has(config.method)) {
      masterKeyTaskCache.set(config.method, ssDeriveMasterKey(yourUUID, config.keyLen));
    }
    return masterKeyTaskCache.get(config.method);
  };
  const inboundState = {
    buffer: new Uint8Array(0),
    hasSalt: false,
    waitPayloadLength: null,
    decryptKey: null,
    nonceCounter: new Uint8Array(SS_NONCE_LENGTH),
    cipherConfig: null
  };
  const initInboundDecryption = async () => {
    const lengthCipherTotalLen = 2 + SS_AEAD_TAG_LENGTH;
    const maxSaltLen = Math.max(...candidateCiphers.map((c) => c.saltLen));
    const minSaltLen = Math.min(...candidateCiphers.map((c) => c.saltLen));
    const maxAlignmentScan = 16;
    const scanLimit = Math.min(
      maxAlignmentScan,
      Math.max(0, inboundState.buffer.byteLength - (lengthCipherTotalLen + minSaltLen))
    );
    for (let offset = 0; offset <= scanLimit; offset++) {
      for (const config of candidateCiphers) {
        const minBytes = offset + config.saltLen + lengthCipherTotalLen;
        if (inboundState.buffer.byteLength < minBytes) continue;
        const salt = inboundState.buffer.subarray(offset, offset + config.saltLen);
        const lengthCipher = inboundState.buffer.subarray(
          offset + config.saltLen,
          minBytes
        );
        const masterKey = await getMasterKeyTask(config);
        const decryptKey = await ssDeriveSessionKey(config, masterKey, salt, ["decrypt"]);
        const nonceCounter = new Uint8Array(SS_NONCE_LENGTH);
        try {
          const lengthPlain = await ssAeadDecrypt(decryptKey, nonceCounter, lengthCipher);
          if (lengthPlain.byteLength !== 2) continue;
          const payloadLength = lengthPlain[0] << 8 | lengthPlain[1];
          if (payloadLength < 0 || payloadLength > config.maxChunk) continue;
          if (offset > 0) log(`[SS-IN] leading noise ${offset}B aligned`);
          if (config.method !== preferredCipher.method) {
            log(`[SS-IN] requested enc=${requestedEnc || preferredCipher.method} but actual ${config.method}, switched`);
          }
          inboundState.buffer = inboundState.buffer.subarray(minBytes);
          inboundState.decryptKey = decryptKey;
          inboundState.nonceCounter = nonceCounter;
          inboundState.waitPayloadLength = payloadLength;
          inboundState.cipherConfig = config;
          inboundState.hasSalt = true;
          return true;
        } catch (_) {
        }
      }
    }
    const failureThreshold = maxSaltLen + lengthCipherTotalLen + maxAlignmentScan;
    if (inboundState.buffer.byteLength >= failureThreshold) {
      throw new Error(
        `SS handshake decrypt failed (enc=${requestedEnc || "auto"}, candidates=${candidateCiphers.map((c) => c.method).join("/")})`
      );
    }
    return false;
  };
  const decryptInput = async (chunkInput) => {
    const chunk = toUint8Array(chunkInput);
    if (chunk.byteLength > 0) {
      inboundState.buffer = concatByteArrays(inboundState.buffer, chunk);
    }
    if (!inboundState.hasSalt) {
      const ok = await initInboundDecryption();
      if (!ok) return [];
    }
    const plaintextChunks = [];
    while (true) {
      if (inboundState.waitPayloadLength === null) {
        const lenTotal = 2 + SS_AEAD_TAG_LENGTH;
        if (inboundState.buffer.byteLength < lenTotal) break;
        const lengthCipher = inboundState.buffer.subarray(0, lenTotal);
        inboundState.buffer = inboundState.buffer.subarray(lenTotal);
        const lengthPlain = await ssAeadDecrypt(
          inboundState.decryptKey,
          inboundState.nonceCounter,
          lengthCipher
        );
        if (lengthPlain.byteLength !== 2) throw new Error("SS length decrypt failed");
        const payloadLength = lengthPlain[0] << 8 | lengthPlain[1];
        if (payloadLength < 0 || payloadLength > inboundState.cipherConfig.maxChunk) {
          throw new Error(`SS payload length invalid: ${payloadLength}`);
        }
        inboundState.waitPayloadLength = payloadLength;
      }
      const payloadTotal = inboundState.waitPayloadLength + SS_AEAD_TAG_LENGTH;
      if (inboundState.buffer.byteLength < payloadTotal) break;
      const payloadCipher = inboundState.buffer.subarray(0, payloadTotal);
      inboundState.buffer = inboundState.buffer.subarray(payloadTotal);
      const payloadPlain = await ssAeadDecrypt(
        inboundState.decryptKey,
        inboundState.nonceCounter,
        payloadCipher
      );
      plaintextChunks.push(payloadPlain);
      inboundState.waitPayloadLength = null;
    }
    return plaintextChunks;
  };
  let outboundEncryptor = null;
  const SS_BATCH_LIMIT = 32 * 1024;
  const getOutboundEncryptor = async () => {
    if (outboundEncryptor) return outboundEncryptor;
    if (!inboundState.cipherConfig) throw new Error("SS cipher is not negotiated");
    const cfg = inboundState.cipherConfig;
    const masterKey = await ssDeriveMasterKey(yourUUID, cfg.keyLen);
    const salt = crypto.getRandomValues(new Uint8Array(cfg.saltLen));
    const encryptKey = await ssDeriveSessionKey(cfg, masterKey, salt, ["encrypt"]);
    const nonceCounter = new Uint8Array(SS_NONCE_LENGTH);
    let saltSent = false;
    outboundEncryptor = {
      async encryptAndSend(dataChunk, send) {
        const plaintext = toUint8Array(dataChunk);
        if (!saltSent) {
          await send(salt);
          saltSent = true;
        }
        if (plaintext.byteLength === 0) return;
        let offset = 0;
        while (offset < plaintext.byteLength) {
          const end = Math.min(offset + cfg.maxChunk, plaintext.byteLength);
          const payloadPlain = plaintext.subarray(offset, end);
          const lengthPlain = new Uint8Array(2);
          lengthPlain[0] = payloadPlain.byteLength >>> 8 & 255;
          lengthPlain[1] = payloadPlain.byteLength & 255;
          const lengthCipher = await ssAeadEncrypt(encryptKey, nonceCounter, lengthPlain);
          const payloadCipher = await ssAeadEncrypt(encryptKey, nonceCounter, payloadPlain);
          const frame = new Uint8Array(lengthCipher.byteLength + payloadCipher.byteLength);
          frame.set(lengthCipher, 0);
          frame.set(payloadCipher, lengthCipher.byteLength);
          await send(frame);
          offset = end;
        }
      }
    };
    return outboundEncryptor;
  };
  let sendQueue = Promise.resolve();
  const enqueueSend = (chunk) => {
    sendQueue = sendQueue.then(async () => {
      if (serverSock.readyState !== WebSocket.OPEN) return;
      const enc = await getOutboundEncryptor();
      await enc.encryptAndSend(chunk, async (encryptedChunk) => {
        if (encryptedChunk.byteLength > 0 && serverSock.readyState === WebSocket.OPEN) {
          await wsSendAndWait(serverSock, encryptedChunk.buffer);
        }
      });
    }).catch((error) => {
      log(`[SS-OUT] encryption failed: ${error?.message || error}`);
      closeSocketQuietly(serverSock);
    });
    return sendQueue;
  };
  const bridge = {
    get readyState() {
      return serverSock.readyState;
    },
    async send(data) {
      const chunk = toUint8Array(data);
      if (chunk.byteLength <= SS_BATCH_LIMIT) {
        await enqueueSend(chunk);
        return;
      }
      let lastPromise = Promise.resolve();
      for (let i = 0; i < chunk.byteLength; i += SS_BATCH_LIMIT) {
        lastPromise = enqueueSend(chunk.subarray(i, Math.min(i + SS_BATCH_LIMIT, chunk.byteLength)));
      }
      await lastPromise;
    },
    close() {
      closeSocketQuietly(serverSock);
    }
  };
  return {
    decryptInput,
    bridge,
    firstPacketEstablished: false,
    targetHost: "",
    targetPort: 0
  };
}
function parseSsTargetHeader(plaintext) {
  if (plaintext.byteLength < 3) throw new Error("invalid ss data");
  const addressType = plaintext[0];
  let cursor = 1;
  let hostname = "";
  if (addressType === 1) {
    if (plaintext.byteLength < cursor + 4 + 2) throw new Error("invalid ss ipv4 length");
    hostname = `${plaintext[cursor]}.${plaintext[cursor + 1]}.${plaintext[cursor + 2]}.${plaintext[cursor + 3]}`;
    cursor += 4;
  } else if (addressType === 3) {
    if (plaintext.byteLength < cursor + 1) throw new Error("invalid ss domain length");
    const domainLength = plaintext[cursor];
    cursor += 1;
    if (plaintext.byteLength < cursor + domainLength + 2) throw new Error("invalid ss domain data");
    hostname = ssTextDecoder.decode(plaintext.subarray(cursor, cursor + domainLength));
    cursor += domainLength;
  } else if (addressType === 4) {
    if (plaintext.byteLength < cursor + 16 + 2) throw new Error("invalid ss ipv6 length");
    const view = new DataView(plaintext.buffer, plaintext.byteOffset + cursor, 16);
    const groups = [];
    for (let i = 0; i < 8; i++) groups.push(view.getUint16(i * 2).toString(16));
    hostname = groups.join(":");
    cursor += 16;
  } else {
    throw new Error(`invalid ss addressType: ${addressType}`);
  }
  if (!hostname) throw new Error(`invalid ss address: ${addressType}`);
  if (isSpeedTestSite(hostname)) throw new Error("Speedtest site is blocked");
  const port = plaintext[cursor] << 8 | plaintext[cursor + 1];
  cursor += 2;
  const rawData = plaintext.subarray(cursor);
  return { hostname, port, rawData };
}

// src/handlers/websocket.ts
async function handleWebSocketRequest(deps, request, yourUUID, url) {
  const wsPair = new WebSocketPair();
  const [clientSock, serverSock] = Object.values(wsPair);
  serverSock.accept();
  serverSock.binaryType = "arraybuffer";
  const remoteConnWrapper = {
    socket: null,
    connectingPromise: null,
    retryConnect: null
  };
  let isDnsQuery = false;
  let isTrojan = null;
  const trojanUdpCtx = { buffer: new Uint8Array(0) };
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
  const ssMode = !!url.searchParams.get("enc");
  let cancelled = false;
  let streamFinished = false;
  const readable = new ReadableStream({
    start(controller) {
      const isClosedError = (err) => {
        const msg = err?.message || `${err || ""}`;
        return msg.includes("ReadableStream is closed") || msg.includes("The stream is closed") || msg.includes("already closed");
      };
      const safeEnqueue = (data) => {
        if (cancelled || streamFinished) return;
        try {
          controller.enqueue(data);
        } catch (err) {
          streamFinished = true;
          if (!isClosedError(err)) {
            try {
              controller.error(err);
            } catch (_) {
            }
          }
        }
      };
      const safeClose = () => {
        if (cancelled || streamFinished) return;
        streamFinished = true;
        try {
          controller.close();
        } catch (err) {
          if (!isClosedError(err)) {
            try {
              controller.error(err);
            } catch (_) {
            }
          }
        }
      };
      const safeError = (err) => {
        if (cancelled || streamFinished) return;
        streamFinished = true;
        try {
          controller.error(err);
        } catch (_) {
        }
      };
      serverSock.addEventListener("message", (event) => {
        safeEnqueue(event.data);
      });
      serverSock.addEventListener("close", () => {
        closeSocketQuietly(serverSock);
        safeClose();
      });
      serverSock.addEventListener("error", (err) => {
        safeError(err);
        closeSocketQuietly(serverSock);
      });
      if (ssMode || !earlyDataHeader) return;
      try {
        const binaryString = atob(
          earlyDataHeader.replace(/-/g, "+").replace(/_/g, "/")
        );
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
          bytes[i] = binaryString.charCodeAt(i);
        }
        safeEnqueue(bytes.buffer);
      } catch (error) {
        safeError(error);
      }
    },
    cancel() {
      cancelled = true;
      streamFinished = true;
      closeSocketQuietly(serverSock);
    }
  });
  let detectedProtocol = null;
  let currentWriteSocket = null;
  let remoteWriter = null;
  let ssContext = null;
  let ssInitTask = null;
  const releaseRemoteWriter = () => {
    if (remoteWriter) {
      try {
        remoteWriter.releaseLock();
      } catch (e) {
      }
      remoteWriter = null;
    }
    currentWriteSocket = null;
  };
  const writeRemote = async (chunk, allowRetry = true) => {
    const socket = remoteConnWrapper.socket;
    if (!socket) return false;
    if (socket !== currentWriteSocket) {
      releaseRemoteWriter();
      currentWriteSocket = socket;
      remoteWriter = socket.writable.getWriter();
    }
    try {
      await remoteWriter.write(chunk);
      return true;
    } catch (err) {
      releaseRemoteWriter();
      if (allowRetry && typeof remoteConnWrapper.retryConnect === "function") {
        await remoteConnWrapper.retryConnect();
        return await writeRemote(chunk, false);
      }
      throw err;
    }
  };
  const getSsContext = async () => {
    if (ssContext) return ssContext;
    if (!ssInitTask) {
      ssInitTask = (async () => {
        const requestedEnc = (url.searchParams.get("enc") || "").toLowerCase();
        ssContext = createSsInbound(serverSock, yourUUID, requestedEnc, deps.log);
        return ssContext;
      })().finally(() => {
        ssInitTask = null;
      });
    }
    return ssInitTask;
  };
  const handleSsData = async (chunk) => {
    const ctx = await getSsContext();
    let plaintextBlocks = [];
    try {
      plaintextBlocks = await ctx.decryptInput(chunk);
    } catch (err) {
      const msg = err?.message || `${err}`;
      if (msg.includes("Decryption failed") || msg.includes("SS handshake decrypt failed") || msg.includes("SS length decrypt failed")) {
        deps.log(`[SS-IN] decrypt failed, closing: ${msg}`);
        closeSocketQuietly(serverSock);
        return;
      }
      throw err;
    }
    for (const block of plaintextBlocks) {
      let written = false;
      try {
        written = await writeRemote(block, false);
      } catch (_) {
        written = false;
      }
      if (written) continue;
      if (ctx.firstPacketEstablished && ctx.targetHost && ctx.targetPort > 0) {
        await forwardTcp(
          deps,
          ctx.targetHost,
          ctx.targetPort,
          block,
          ctx.bridge,
          null,
          remoteConnWrapper,
          yourUUID
        );
        continue;
      }
      const { hostname, port, rawData } = parseSsTargetHeader(block);
      ctx.firstPacketEstablished = true;
      ctx.targetHost = hostname;
      ctx.targetPort = port;
      await forwardTcp(
        deps,
        hostname,
        port,
        rawData,
        ctx.bridge,
        null,
        remoteConnWrapper,
        yourUUID
      );
    }
  };
  readable.pipeTo(
    new WritableStream({
      async write(chunk) {
        if (isDnsQuery) {
          if (isTrojan) {
            return await forwardTrojanUdp(chunk, serverSock, trojanUdpCtx, deps.log);
          }
          return await forwardUdpToDns(chunk, serverSock, null, null, deps.log);
        }
        if (detectedProtocol === "ss") {
          await handleSsData(chunk);
          return;
        }
        if (await writeRemote(chunk)) return;
        if (detectedProtocol === null) {
          if (url.searchParams.get("enc")) {
            detectedProtocol = "ss";
          } else {
            const bytes = new Uint8Array(chunk);
            detectedProtocol = bytes.byteLength >= 58 && bytes[56] === 13 && bytes[57] === 10 ? "trojan" : "vless";
          }
          isTrojan = detectedProtocol === "trojan";
          deps.log(
            `[WS] protocol: ${detectedProtocol} | host: ${url.host} | UA: ${request.headers.get("user-agent") || "unknown"}`
          );
        }
        if (detectedProtocol === "ss") {
          await handleSsData(chunk);
          return;
        }
        if (await writeRemote(chunk)) return;
        if (detectedProtocol === "trojan") {
          const result = parseTrojanRequest(chunk, yourUUID);
          if (result.hasError) {
            throw new Error(result.message || "Invalid trojan request");
          }
          const { port, hostname, rawClientData, isUDP } = result;
          if (isSpeedTestSite(hostname)) throw new Error("Speedtest site is blocked");
          if (isUDP) {
            isDnsQuery = true;
            if (byteLength(rawClientData) > 0) {
              return forwardTrojanUdp(rawClientData, serverSock, trojanUdpCtx, deps.log);
            }
            return;
          }
          await forwardTcp(
            deps,
            hostname,
            port,
            new Uint8Array(rawClientData),
            serverSock,
            null,
            remoteConnWrapper,
            yourUUID
          );
        } else {
          isTrojan = false;
          const result = parseVlessRequest(chunk, yourUUID);
          if (result.hasError) {
            throw new Error(result.message || "Invalid VLESS request");
          }
          const { port, hostname, rawIndex, version, isUDP } = result;
          if (isSpeedTestSite(hostname)) throw new Error("Speedtest site is blocked");
          if (isUDP) {
            if (port === 53) isDnsQuery = true;
            else throw new Error("UDP is not supported");
          }
          const respHeader = new Uint8Array([version[0], 0]);
          const rawData = new Uint8Array(chunk.slice(rawIndex));
          if (isDnsQuery) {
            if (isTrojan) {
              return forwardTrojanUdp(rawData, serverSock, trojanUdpCtx, deps.log);
            }
            return forwardUdpToDns(rawData, serverSock, respHeader, null, deps.log);
          }
          await forwardTcp(
            deps,
            hostname,
            port,
            rawData,
            serverSock,
            respHeader,
            remoteConnWrapper,
            yourUUID
          );
        }
      },
      close() {
        releaseRemoteWriter();
      },
      abort() {
        releaseRemoteWriter();
      }
    })
  ).catch((err) => {
    const msg = err?.message || `${err}`;
    if (msg.includes("Network connection lost") || msg.includes("ReadableStream is closed")) {
      deps.log(`[WS] connection ended: ${msg}`);
    } else {
      deps.log(`[WS] handler failed: ${msg}`);
    }
    releaseRemoteWriter();
    closeSocketQuietly(serverSock);
  });
  return new Response(null, { status: 101, webSocket: clientSock });
}

// src/handlers/grpc.ts
var DOWNSTREAM_BUFFER_LIMIT = 64 * 1024;
var DOWNSTREAM_FLUSH_INTERVAL_MS = 20;
async function handleGrpcRequest(deps, request, yourUUID) {
  if (!request.body) return new Response("Bad Request", { status: 400 });
  const reader = request.body.getReader();
  const remoteConnWrapper = {
    socket: null,
    connectingPromise: null,
    retryConnect: null
  };
  let isDnsQuery = false;
  const trojanUdpCtx = { buffer: new Uint8Array(0) };
  let isTrojan = null;
  let currentWriteSocket = null;
  let remoteWriter = null;
  const grpcHeaders = new Headers({
    "Content-Type": "application/grpc",
    "grpc-status": "0",
    "X-Accel-Buffering": "no",
    "Cache-Control": "no-store"
  });
  return new Response(
    new ReadableStream({
      async start(controller) {
        let closed = false;
        let sendQueue = [];
        let queueBytes = 0;
        let flushTimer = null;
        const flushQueue = (force = false) => {
          if (flushTimer) {
            clearTimeout(flushTimer);
            flushTimer = null;
          }
          if (!force && closed || queueBytes === 0) return;
          const out = new Uint8Array(queueBytes);
          let offset = 0;
          for (const item of sendQueue) {
            out.set(item, offset);
            offset += item.byteLength;
          }
          sendQueue = [];
          queueBytes = 0;
          try {
            controller.enqueue(out);
          } catch (e) {
            closed = true;
            grpcBridge.readyState = WebSocket.CLOSED;
          }
        };
        const grpcBridge = {
          readyState: WebSocket.OPEN,
          send(data) {
            if (closed) return;
            const chunk = data instanceof Uint8Array ? data : new Uint8Array(data);
            const lenBytes = [];
            let remaining = chunk.byteLength >>> 0;
            while (remaining > 127) {
              lenBytes.push(remaining & 127 | 128);
              remaining >>>= 7;
            }
            lenBytes.push(remaining);
            const protobufLen = 1 + lenBytes.length + chunk.byteLength;
            const frame = new Uint8Array(5 + protobufLen);
            frame[0] = 0;
            frame[1] = protobufLen >>> 24 & 255;
            frame[2] = protobufLen >>> 16 & 255;
            frame[3] = protobufLen >>> 8 & 255;
            frame[4] = protobufLen & 255;
            frame[5] = 10;
            frame.set(new Uint8Array(lenBytes), 6);
            frame.set(chunk, 6 + lenBytes.length);
            sendQueue.push(frame);
            queueBytes += frame.byteLength;
            if (queueBytes >= DOWNSTREAM_BUFFER_LIMIT) flushQueue();
            else if (!flushTimer) flushTimer = setTimeout(flushQueue, DOWNSTREAM_FLUSH_INTERVAL_MS);
          },
          close() {
            if (this.readyState === WebSocket.CLOSED) return;
            flushQueue(true);
            closed = true;
            this.readyState = WebSocket.CLOSED;
            try {
              controller.close();
            } catch (e) {
            }
          }
        };
        const closeAll = () => {
          if (closed) return;
          flushQueue(true);
          closed = true;
          grpcBridge.readyState = WebSocket.CLOSED;
          if (flushTimer) clearTimeout(flushTimer);
          if (remoteWriter) {
            try {
              remoteWriter.releaseLock();
            } catch (e) {
            }
            remoteWriter = null;
          }
          currentWriteSocket = null;
          try {
            reader.releaseLock();
          } catch (e) {
          }
          try {
            remoteConnWrapper.socket?.close();
          } catch (e) {
          }
          try {
            controller.close();
          } catch (e) {
          }
        };
        const releaseRemoteWriter = () => {
          if (remoteWriter) {
            try {
              remoteWriter.releaseLock();
            } catch (e) {
            }
            remoteWriter = null;
          }
          currentWriteSocket = null;
        };
        const writeRemote = async (payload, allowRetry = true) => {
          const socket = remoteConnWrapper.socket;
          if (!socket) return false;
          if (socket !== currentWriteSocket) {
            releaseRemoteWriter();
            currentWriteSocket = socket;
            remoteWriter = socket.writable.getWriter();
          }
          try {
            await remoteWriter.write(payload);
            return true;
          } catch (err) {
            releaseRemoteWriter();
            if (allowRetry && typeof remoteConnWrapper.retryConnect === "function") {
              await remoteConnWrapper.retryConnect();
              return await writeRemote(payload, false);
            }
            throw err;
          }
        };
        try {
          let pending = new Uint8Array(0);
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            if (!value || value.byteLength === 0) continue;
            const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
            const merged = new Uint8Array(pending.length + chunk.length);
            merged.set(pending, 0);
            merged.set(chunk, pending.length);
            pending = merged;
            while (pending.byteLength >= 5) {
              const grpcLen = pending[1] << 24 >>> 0 | pending[2] << 16 | pending[3] << 8 | pending[4];
              const frameSize = 5 + grpcLen;
              if (pending.byteLength < frameSize) break;
              const grpcPayload = pending.slice(5, frameSize);
              pending = pending.slice(frameSize);
              if (!grpcPayload.byteLength) continue;
              let payload = grpcPayload;
              if (payload.byteLength >= 2 && payload[0] === 10) {
                let shift = 0;
                let offset = 1;
                let varintValid = false;
                while (offset < payload.length) {
                  const cur = payload[offset++];
                  if ((cur & 128) === 0) {
                    varintValid = true;
                    break;
                  }
                  shift += 7;
                  if (shift > 35) break;
                }
                if (varintValid) payload = payload.slice(offset);
              }
              if (!payload.byteLength) continue;
              if (isDnsQuery) {
                if (isTrojan) {
                  await forwardTrojanUdp(payload, grpcBridge, trojanUdpCtx, deps.log);
                } else {
                  await forwardUdpToDns(payload, grpcBridge, null, null, deps.log);
                }
                continue;
              }
              if (remoteConnWrapper.socket) {
                if (!await writeRemote(payload)) {
                  throw new Error("Remote socket is not ready");
                }
              } else {
                const firstBuf = payload.buffer.slice(
                  payload.byteOffset,
                  payload.byteOffset + payload.byteLength
                );
                const firstBytes = new Uint8Array(firstBuf);
                if (isTrojan === null) {
                  isTrojan = firstBytes.byteLength >= 58 && firstBytes[56] === 13 && firstBytes[57] === 10;
                }
                if (isTrojan) {
                  const result = parseTrojanRequest(firstBuf, yourUUID);
                  if (result.hasError) {
                    throw new Error(result.message || "Invalid trojan request");
                  }
                  const { port, hostname, rawClientData, isUDP } = result;
                  deps.log(`[gRPC] trojan first: ${hostname}:${port} | UDP: ${isUDP}`);
                  if (isSpeedTestSite(hostname)) throw new Error("Speedtest site is blocked");
                  if (isUDP) {
                    isDnsQuery = true;
                    if (byteLength(rawClientData) > 0) {
                      await forwardTrojanUdp(rawClientData, grpcBridge, trojanUdpCtx, deps.log);
                    }
                  } else {
                    await forwardTcp(
                      deps,
                      hostname,
                      port,
                      new Uint8Array(rawClientData),
                      grpcBridge,
                      null,
                      remoteConnWrapper,
                      yourUUID
                    );
                  }
                } else {
                  isTrojan = false;
                  const result = parseVlessRequest(firstBuf, yourUUID);
                  if (result.hasError) {
                    throw new Error(result.message || "Invalid VLESS request");
                  }
                  const { port, hostname, rawIndex, version, isUDP } = result;
                  deps.log(`[gRPC] vless first: ${hostname}:${port} | UDP: ${isUDP}`);
                  if (isSpeedTestSite(hostname)) throw new Error("Speedtest site is blocked");
                  if (isUDP) {
                    if (port !== 53) throw new Error("UDP is not supported");
                    isDnsQuery = true;
                  }
                  const respHeader = new Uint8Array([version[0], 0]);
                  grpcBridge.send(respHeader);
                  const rawData = new Uint8Array(firstBuf.slice(rawIndex));
                  if (isDnsQuery) {
                    if (isTrojan) {
                      await forwardTrojanUdp(rawData, grpcBridge, trojanUdpCtx, deps.log);
                    } else {
                      await forwardUdpToDns(rawData, grpcBridge, null, null, deps.log);
                    }
                  } else {
                    await forwardTcp(
                      deps,
                      hostname,
                      port,
                      rawData,
                      grpcBridge,
                      null,
                      remoteConnWrapper,
                      yourUUID
                    );
                  }
                }
              }
            }
            flushQueue();
          }
        } catch (err) {
          deps.log(`[gRPC] error: ${err?.message || err}`);
        } finally {
          releaseRemoteWriter();
          closeAll();
        }
      },
      cancel() {
        try {
          remoteConnWrapper.socket?.close();
        } catch (e) {
        }
        try {
          reader.releaseLock();
        } catch (e) {
        }
      }
    }),
    { status: 200, headers: grpcHeaders }
  );
}

// src/protocols/dispatch.ts
async function readFirstPacket(reader, token) {
  let buffer = new Uint8Array(1024);
  let offset = 0;
  while (true) {
    const { value, done } = await reader.read();
    if (done) {
      if (offset === 0) return null;
      break;
    }
    const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
    if (offset + chunk.byteLength > buffer.byteLength) {
      const newBuffer = new Uint8Array(
        Math.max(buffer.byteLength * 2, offset + chunk.byteLength)
      );
      newBuffer.set(buffer.subarray(0, offset));
      buffer = newBuffer;
    }
    buffer.set(chunk, offset);
    offset += chunk.byteLength;
    const current = buffer.subarray(0, offset);
    const trojan2 = tryParseTrojanFirstPacket(current, token);
    if (trojan2.status === "ok") return { ...trojan2.result, reader };
    const vless2 = tryParseVlessFirstPacket(current, token);
    if (vless2.status === "ok") return { ...vless2.result, reader };
    if (trojan2.status === "invalid" && vless2.status === "invalid") return null;
  }
  const finalBuffer = buffer.subarray(0, offset);
  const trojan = tryParseTrojanFirstPacket(finalBuffer, token);
  if (trojan.status === "ok") return { ...trojan.result, reader };
  const vless = tryParseVlessFirstPacket(finalBuffer, token);
  if (vless.status === "ok") return { ...vless.result, reader };
  return null;
}

// src/handlers/xhttp.ts
async function handleXhttpRequest(deps, request, yourUUID) {
  if (!request.body) return new Response("Bad Request", { status: 400 });
  const reader = request.body.getReader();
  const firstPacket = await readFirstPacket(reader, yourUUID);
  if (!firstPacket) {
    try {
      reader.releaseLock();
    } catch (e) {
    }
    return new Response("Invalid request", { status: 400 });
  }
  if (isSpeedTestSite(firstPacket.hostname)) {
    try {
      reader.releaseLock();
    } catch (e) {
    }
    return new Response("Forbidden", { status: 403 });
  }
  if (firstPacket.isUDP && firstPacket.protocol !== "trojan" && firstPacket.port !== 53) {
    try {
      reader.releaseLock();
    } catch (e) {
    }
    return new Response("UDP is not supported", { status: 400 });
  }
  const remoteConnWrapper = {
    socket: null,
    connectingPromise: null,
    retryConnect: null
  };
  let currentWriteSocket = null;
  let remoteWriter = null;
  const responseHeaders = new Headers({
    "Content-Type": "application/octet-stream",
    "X-Accel-Buffering": "no",
    "Cache-Control": "no-store"
  });
  const releaseRemoteWriter = () => {
    if (remoteWriter) {
      try {
        remoteWriter.releaseLock();
      } catch (e) {
      }
      remoteWriter = null;
    }
    currentWriteSocket = null;
  };
  const getRemoteWriter = () => {
    const socket = remoteConnWrapper.socket;
    if (!socket) return null;
    if (socket !== currentWriteSocket) {
      releaseRemoteWriter();
      currentWriteSocket = socket;
      remoteWriter = socket.writable.getWriter();
    }
    return remoteWriter;
  };
  return new Response(
    new ReadableStream({
      async start(controller) {
        let closed = false;
        let udpRespHeader = firstPacket.respHeader;
        const trojanUdpCtx = { buffer: new Uint8Array(0) };
        const xhttpBridge = {
          readyState: WebSocket.OPEN,
          send(data) {
            if (closed) return;
            try {
              const chunk = data instanceof Uint8Array ? data : data instanceof ArrayBuffer ? new Uint8Array(data) : ArrayBuffer.isView(data) ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength) : new Uint8Array(data);
              controller.enqueue(chunk);
            } catch (e) {
              closed = true;
              this.readyState = WebSocket.CLOSED;
            }
          },
          close() {
            if (closed) return;
            closed = true;
            this.readyState = WebSocket.CLOSED;
            try {
              controller.close();
            } catch (e) {
            }
          }
        };
        const writeRemote = async (payload, allowRetry = true) => {
          const writer = getRemoteWriter();
          if (!writer) return false;
          try {
            await writer.write(payload);
            return true;
          } catch (err) {
            releaseRemoteWriter();
            if (allowRetry && typeof remoteConnWrapper.retryConnect === "function") {
              await remoteConnWrapper.retryConnect();
              return await writeRemote(payload, false);
            }
            throw err;
          }
        };
        try {
          if (firstPacket.isUDP) {
            if (firstPacket.rawData?.byteLength) {
              if (firstPacket.protocol === "trojan") {
                await forwardTrojanUdp(firstPacket.rawData, xhttpBridge, trojanUdpCtx, deps.log);
              } else {
                await forwardUdpToDns(firstPacket.rawData, xhttpBridge, udpRespHeader, null, deps.log);
              }
              udpRespHeader = null;
            }
          } else {
            await forwardTcp(
              deps,
              firstPacket.hostname,
              firstPacket.port,
              firstPacket.rawData,
              xhttpBridge,
              firstPacket.respHeader,
              remoteConnWrapper,
              yourUUID
            );
          }
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            if (!value || value.byteLength === 0) continue;
            if (firstPacket.isUDP) {
              if (firstPacket.protocol === "trojan") {
                await forwardTrojanUdp(value, xhttpBridge, trojanUdpCtx, deps.log);
              } else {
                await forwardUdpToDns(value, xhttpBridge, udpRespHeader, null, deps.log);
              }
              udpRespHeader = null;
            } else {
              if (!await writeRemote(value)) {
                throw new Error("Remote socket is not ready");
              }
            }
          }
          if (!firstPacket.isUDP) {
            const writer = getRemoteWriter();
            if (writer) {
              try {
                await writer.close();
              } catch (e) {
              }
            }
          }
        } catch (err) {
          deps.log(`[XHTTP] error: ${err?.message || err}`);
          closeSocketQuietly(xhttpBridge);
        } finally {
          releaseRemoteWriter();
          try {
            reader.releaseLock();
          } catch (e) {
          }
        }
      },
      cancel() {
        releaseRemoteWriter();
        try {
          remoteConnWrapper.socket?.close();
        } catch (e) {
        }
        try {
          reader.releaseLock();
        } catch (e) {
        }
      }
    }),
    { status: 200, headers: responseHeaders }
  );
}

// src/admin/proxy-resolver.ts
var SOCKS5_AUTH_BASE64_PATTERN = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
var IPV6_BRACKETS_PATTERN = /^\[.*\]$/;
function parseSocks5Auth(address, defaultPort = 80) {
  const firstAt = address.lastIndexOf("@");
  if (firstAt !== -1) {
    let auth = address.slice(0, firstAt).replaceAll("%3D", "=");
    if (!auth.includes(":") && SOCKS5_AUTH_BASE64_PATTERN.test(auth)) {
      auth = atob(auth);
    }
    address = `${auth}@${address.slice(firstAt + 1)}`;
  }
  const atIndex = address.lastIndexOf("@");
  const hostPart = atIndex === -1 ? address : address.slice(atIndex + 1);
  const authPart = atIndex === -1 ? "" : address.slice(0, atIndex);
  const [username, password] = authPart ? authPart.split(":") : [];
  if (authPart && !password) {
    throw new Error('Invalid SOCKS auth format: must be "user:password"');
  }
  let hostname = hostPart;
  let port = defaultPort;
  if (hostPart.includes("]:")) {
    const [ipv6Host, ipv6Port = ""] = hostPart.split("]:");
    hostname = ipv6Host + "]";
    port = Number(ipv6Port.replace(/[^\d]/g, ""));
  } else if (!hostPart.startsWith("[")) {
    const parts = hostPart.split(":");
    if (parts.length === 2) {
      hostname = parts[0];
      port = Number(parts[1].replace(/[^\d]/g, ""));
    }
  }
  if (isNaN(port)) {
    throw new Error("Invalid SOCKS address: port must be numeric");
  }
  if (hostname.includes(":") && !IPV6_BRACKETS_PATTERN.test(hostname)) {
    throw new Error("Invalid SOCKS address: IPv6 must be wrapped in brackets like [2001:db8::1]");
  }
  return { username, password, hostname, port };
}
async function parseProxyParams(ctx, url) {
  const { searchParams } = url;
  const pathname = decodeURIComponent(url.pathname);
  const pathLower = pathname.toLowerCase();
  ctx.socks5Auth = searchParams.get("socks5") || searchParams.get("http") || searchParams.get("https") || "";
  ctx.socks5GlobalEnabled = searchParams.has("globalproxy");
  if (searchParams.get("socks5")) ctx.socks5Mode = "socks5";
  else if (searchParams.get("http")) ctx.socks5Mode = "http";
  else if (searchParams.get("https")) ctx.socks5Mode = "https";
  const parseProxyURL = (value, forceGlobal = true) => {
    const match = /^(socks5|http|https):\/\/(.+)$/i.exec(value || "");
    if (!match) return false;
    ctx.socks5Mode = match[1].toLowerCase();
    ctx.socks5Auth = match[2].split("/")[0];
    if (forceGlobal) ctx.socks5GlobalEnabled = true;
    return true;
  };
  const setProxyIP = (value) => {
    ctx.proxyIP = value;
    ctx.socks5Mode = null;
    ctx.proxyFallbackEnabled = false;
  };
  const extractPathValue = (value) => {
    if (!value.includes("://")) {
      const slashIdx2 = value.indexOf("/");
      return slashIdx2 > 0 ? value.slice(0, slashIdx2) : value;
    }
    const split = value.split("://");
    if (split.length !== 2) return value;
    const slashIdx = split[1].indexOf("/");
    return slashIdx > 0 ? `${split[0]}://${split[1].slice(0, slashIdx)}` : value;
  };
  const queryProxyIP = searchParams.get("proxyip");
  if (queryProxyIP !== null) {
    if (!parseProxyURL(queryProxyIP)) {
      setProxyIP(queryProxyIP);
      return;
    }
  } else {
    let match;
    if (match = /\/(socks5?|http|https):\/?\/?([^/?#\s]+)/i.exec(pathname)) {
      const type = match[1].toLowerCase();
      ctx.socks5Mode = type === "http" ? "http" : type === "https" ? "https" : "socks5";
      ctx.socks5Auth = match[2].split("/")[0];
      ctx.socks5GlobalEnabled = true;
    } else if (match = /\/(g?s5|socks5|g?http|g?https)=([^/?#\s]+)/i.exec(pathname)) {
      const type = match[1].toLowerCase();
      ctx.socks5Auth = match[2].split("/")[0];
      ctx.socks5Mode = type.includes("https") ? "https" : type.includes("http") ? "http" : "socks5";
      if (type.startsWith("g")) ctx.socks5GlobalEnabled = true;
    } else if (match = /\/(proxyip[.=]|pyip=|ip=)([^?#\s]+)/.exec(pathLower)) {
      const pathProxyValue = extractPathValue(match[2]);
      if (!parseProxyURL(pathProxyValue)) {
        setProxyIP(pathProxyValue);
        return;
      }
    }
  }
  if (!ctx.socks5Auth) {
    ctx.socks5Mode = null;
    return;
  }
  try {
    ctx.parsedSocks5 = parseSocks5Auth(
      ctx.socks5Auth,
      ctx.socks5Mode === "https" ? 443 : 80
    );
    if (searchParams.get("socks5")) ctx.socks5Mode = "socks5";
    else if (searchParams.get("http")) ctx.socks5Mode = "http";
    else if (searchParams.get("https")) ctx.socks5Mode = "https";
    else ctx.socks5Mode = ctx.socks5Mode || "socks5";
  } catch (err) {
    console.error("parseProxyParams: socks5 auth parse failed:", err.message);
    ctx.socks5Mode = null;
  }
}

// src/utils/dns.ts
var DEFAULT_DOH_SERVICE = "https://cloudflare-dns.com/dns-query";
var RECORD_TYPE_MAP = {
  A: 1,
  NS: 2,
  CNAME: 5,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  HTTPS: 65
};
function encodeDnsName(name) {
  const parts = name.endsWith(".") ? name.slice(0, -1).split(".") : name.split(".");
  const bufs = [];
  for (const label of parts) {
    const enc = new TextEncoder().encode(label);
    bufs.push(new Uint8Array([enc.length]), enc);
  }
  bufs.push(new Uint8Array([0]));
  const total = bufs.reduce((s, b) => s + b.length, 0);
  const result = new Uint8Array(total);
  let off = 0;
  for (const b of bufs) {
    result.set(b, off);
    off += b.length;
  }
  return result;
}
function parseDnsName(buf, pos) {
  const labels = [];
  let p = pos;
  let jumped = false;
  let endPos = -1;
  let safe = 128;
  while (p < buf.length && safe-- > 0) {
    const len = buf[p];
    if (len === 0) {
      if (!jumped) endPos = p + 1;
      break;
    }
    if ((len & 192) === 192) {
      if (!jumped) endPos = p + 2;
      p = (len & 63) << 8 | buf[p + 1];
      jumped = true;
      continue;
    }
    labels.push(new TextDecoder().decode(buf.slice(p + 1, p + 1 + len)));
    p += len + 1;
  }
  if (endPos === -1) endPos = p + 1;
  return [labels.join("."), endPos];
}
async function dohQuery(domain, recordType, dohService = DEFAULT_DOH_SERVICE, log = () => {
}) {
  const startTime = performance.now();
  log(`[DoH] querying ${domain} ${recordType} via ${dohService}`);
  try {
    const qtype = RECORD_TYPE_MAP[recordType.toUpperCase()] || 1;
    const qname = encodeDnsName(domain);
    const query = new Uint8Array(12 + qname.length + 4);
    const qview = new DataView(query.buffer);
    qview.setUint16(0, crypto.getRandomValues(new Uint16Array(1))[0]);
    qview.setUint16(2, 256);
    qview.setUint16(4, 1);
    query.set(qname, 12);
    qview.setUint16(12 + qname.length, qtype);
    qview.setUint16(12 + qname.length + 2, 1);
    const response = await fetch(dohService, {
      method: "POST",
      headers: {
        "Content-Type": "application/dns-message",
        Accept: "application/dns-message"
      },
      body: query
    });
    if (!response.ok) {
      console.warn(`[DoH] request failed ${domain} ${recordType}: ${response.status}`);
      return [];
    }
    const buf = new Uint8Array(await response.arrayBuffer());
    const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    const qdcount = dv.getUint16(4);
    const ancount = dv.getUint16(6);
    log(`[DoH] response ${domain} ${recordType}: ${buf.length}B, ${ancount} answers`);
    let offset = 12;
    for (let i = 0; i < qdcount; i++) {
      const [, end] = parseDnsName(buf, offset);
      offset = end + 4;
    }
    const answers = [];
    for (let i = 0; i < ancount && offset < buf.length; i++) {
      const [name, nameEnd] = parseDnsName(buf, offset);
      offset = nameEnd;
      const type = dv.getUint16(offset);
      offset += 2;
      offset += 2;
      const ttl = dv.getUint32(offset);
      offset += 4;
      const rdlen = dv.getUint16(offset);
      offset += 2;
      const rdata = buf.slice(offset, offset + rdlen);
      offset += rdlen;
      let data;
      if (type === 1 && rdlen === 4) {
        data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
      } else if (type === 28 && rdlen === 16) {
        const segs = [];
        for (let j = 0; j < 16; j += 2) {
          segs.push((rdata[j] << 8 | rdata[j + 1]).toString(16));
        }
        data = segs.join(":");
      } else if (type === 16) {
        let tOff = 0;
        const parts = [];
        while (tOff < rdlen) {
          const tLen = rdata[tOff++];
          parts.push(new TextDecoder().decode(rdata.slice(tOff, tOff + tLen)));
          tOff += tLen;
        }
        data = parts.join("");
      } else if (type === 5) {
        const [cname] = parseDnsName(buf, offset - rdlen);
        data = cname;
      } else {
        data = Array.from(rdata).map((b) => b.toString(16).padStart(2, "0")).join("");
      }
      answers.push({ name, type, TTL: ttl, data, rdata });
    }
    const elapsed = (performance.now() - startTime).toFixed(2);
    log(`[DoH] complete ${domain} ${recordType}: ${elapsed}ms, ${answers.length} results`);
    return answers;
  } catch (error) {
    const elapsed = (performance.now() - startTime).toFixed(2);
    console.error(`[DoH] error ${domain} ${recordType} ${elapsed}ms:`, error);
    return [];
  }
}

// src/admin/parse-address.ts
function splitAddressPort(str, defaultPort = 443) {
  let address = str;
  let port = defaultPort;
  if (str.includes("]:")) {
    const parts = str.split("]:");
    address = parts[0] + "]";
    port = parseInt(parts[1], 10) || defaultPort;
  } else if (str.includes(":") && !str.startsWith("[")) {
    const colonIndex = str.lastIndexOf(":");
    address = str.slice(0, colonIndex);
    port = parseInt(str.slice(colonIndex + 1), 10) || defaultPort;
  }
  return [address, port];
}
var IPV4_REGEX = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
var IPV6_REGEX = /^\[?([a-fA-F0-9:]+)\]?$/;
async function parseAddressPort(ctx, proxyIP, targetDomain = "dash.cloudflare.com", uuid = "00000000-0000-4000-8000-000000000000", log = () => {
}) {
  if (ctx.cachedProxyIP && ctx.cachedProxyArray && ctx.cachedProxyIP === proxyIP) {
    log(`[proxy-resolve] cache hit, ${ctx.cachedProxyArray.length} candidates`);
    return ctx.cachedProxyArray;
  }
  proxyIP = proxyIP.toLowerCase();
  const proxyIPArray = toArray(proxyIP);
  let allCandidates = [];
  for (const single of proxyIPArray) {
    if (single.includes(".william")) {
      try {
        let txtRecords = await dohQuery(single, "TXT", void 0, log);
        let txtData = txtRecords.filter((r) => r.type === 16).map((r) => r.data);
        if (txtData.length === 0) {
          log(`[proxy-resolve] default DoH found no TXT, retry via Google DoH for ${single}`);
          txtRecords = await dohQuery(single, "TXT", "https://dns.google/dns-query", log);
          txtData = txtRecords.filter((r) => r.type === 16).map((r) => r.data);
        }
        if (txtData.length > 0) {
          let data = txtData[0];
          if (data.startsWith('"') && data.endsWith('"')) data = data.slice(1, -1);
          const prefixes = data.replace(/\\010/g, ",").replace(/\n/g, ",").split(",").map((s) => s.trim()).filter(Boolean);
          allCandidates.push(...prefixes.map((prefix) => splitAddressPort(prefix)));
        }
      } catch (error) {
        console.error("[proxy-resolve] william domain failed:", error);
      }
    } else {
      let [address, port] = splitAddressPort(single);
      if (single.includes(".tp")) {
        const tpMatch = single.match(/\.tp(\d+)/);
        if (tpMatch) port = parseInt(tpMatch[1], 10);
      }
      const isIp = IPV4_REGEX.test(address) || IPV6_REGEX.test(address);
      if (!isIp) {
        let [aRecords, aaaaRecords] = await Promise.all([
          dohQuery(address, "A", void 0, log),
          dohQuery(address, "AAAA", void 0, log)
        ]);
        let ipv4List = aRecords.filter((r) => r.type === 1).map((r) => r.data);
        let ipv6List = aaaaRecords.filter((r) => r.type === 28).map((r) => `[${r.data}]`);
        let ipAddresses = [...ipv4List, ...ipv6List];
        if (ipAddresses.length === 0) {
          log(`[proxy-resolve] default DoH found no records, retry via Google DoH for ${address}`);
          [aRecords, aaaaRecords] = await Promise.all([
            dohQuery(address, "A", "https://dns.google/dns-query", log),
            dohQuery(address, "AAAA", "https://dns.google/dns-query", log)
          ]);
          ipv4List = aRecords.filter((r) => r.type === 1).map((r) => r.data);
          ipv6List = aaaaRecords.filter((r) => r.type === 28).map((r) => `[${r.data}]`);
          ipAddresses = [...ipv4List, ...ipv6List];
        }
        if (ipAddresses.length > 0) {
          allCandidates.push(...ipAddresses.map((ip) => [ip, port]));
        } else {
          allCandidates.push([address, port]);
        }
      } else {
        allCandidates.push([address, port]);
      }
    }
  }
  const sorted = [...allCandidates].sort((a, b) => a[0].localeCompare(b[0]));
  const targetRootDomain = targetDomain.includes(".") ? targetDomain.split(".").slice(-2).join(".") : targetDomain;
  let seed = [...targetRootDomain + uuid].reduce((a, c) => a + c.charCodeAt(0), 0);
  log(`[proxy-resolve] seed=${seed}, target root=${targetRootDomain}`);
  const shuffled = [...sorted].sort(() => {
    seed = seed * 1103515245 + 12345 & 2147483647;
    return seed / 2147483647 - 0.5;
  });
  const top8 = shuffled.slice(0, 8);
  log(
    `[proxy-resolve] resolved ${top8.length} candidates:
` + top8.map(([ip, p], i) => `${i + 1}. ${ip}:${p}`).join("\n")
  );
  ctx.cachedProxyArray = top8;
  ctx.cachedProxyIP = proxyIP;
  return top8;
}

// src/transports/https-proxy.ts
import { connect as connect5 } from "cloudflare:sockets";

// src/crypto/ecdh.ts
async function generateKeyShare(group = "P-256") {
  const algorithm = group === "X25519" ? { name: "X25519" } : { name: "ECDH", namedCurve: group };
  const keyPair = await crypto.subtle.generateKey(algorithm, true, [
    "deriveBits"
  ]);
  const publicKeyRaw = await crypto.subtle.exportKey(
    "raw",
    keyPair.publicKey
  );
  return { keyPair, publicKeyRaw: new Uint8Array(publicKeyRaw) };
}
async function deriveSharedSecret(privateKey, peerPublicKey, group = "P-256") {
  const algorithm = group === "X25519" ? { name: "X25519" } : { name: "ECDH", namedCurve: group };
  const peerKey = await crypto.subtle.importKey("raw", peerPublicKey, algorithm, false, []);
  const bits = group === "P-384" ? 384 : group === "P-521" ? 528 : 256;
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: algorithm.name, public: peerKey },
      privateKey,
      bits
    )
  );
}

// src/crypto/hmac-hkdf.ts
var hashByteLength = (hash) => hash === "SHA-512" ? 64 : hash === "SHA-384" ? 48 : 32;
async function hmac(hash, key, data) {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash },
    false,
    ["sign"]
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, data));
}
async function digestBytes(hash, data) {
  return new Uint8Array(await crypto.subtle.digest(hash, data));
}
async function tls12Prf(secret, label, seed, length, hash = "SHA-256") {
  const labelSeed = concatBytes(textEncoder.encode(label), seed);
  let output = new Uint8Array(0);
  let currentA = labelSeed;
  while (output.length < length) {
    currentA = await hmac(hash, secret, currentA);
    const block = await hmac(hash, secret, concatBytes(currentA, labelSeed));
    output = concatBytes(output, block);
  }
  return output.slice(0, length);
}
async function hkdfExtract(hash, salt, inputKeyMaterial) {
  if (!salt || !salt.length) {
    salt = new Uint8Array(hashByteLength(hash));
  }
  return hmac(hash, salt, inputKeyMaterial);
}
async function hkdfExpand(hash, secret, info, length) {
  const hashLen = hashByteLength(hash);
  const roundCount = Math.ceil(length / hashLen);
  let output = new Uint8Array(0);
  let previousBlock = new Uint8Array(0);
  for (let round = 1; round <= roundCount; round++) {
    previousBlock = await hmac(
      hash,
      secret,
      concatBytes(previousBlock, info, new Uint8Array([round]))
    );
    output = concatBytes(output, previousBlock);
  }
  return output.slice(0, length);
}
async function hkdfExpandLabel(hash, secret, label, context, length) {
  const fullLabel = textEncoder.encode("tls13 " + label);
  const info = tlsBytes(
    uint16be(length),
    fullLabel.length,
    fullLabel,
    context.length,
    context
  );
  return hkdfExpand(hash, secret, info, length);
}

// src/crypto/aes-gcm.ts
async function importAesGcmKey(key, usages) {
  return crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, false, usages);
}
async function aesGcmEncrypt(cryptoKey, iv, plaintext, additionalData) {
  return new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData, tagLength: 128 },
      cryptoKey,
      plaintext
    )
  );
}
async function aesGcmDecrypt(cryptoKey, iv, ciphertext, additionalData) {
  return new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData, tagLength: 128 },
      cryptoKey,
      ciphertext
    )
  );
}

// src/crypto/chacha20.ts
var rotateLeft32 = (value, bits) => (value << bits | value >>> 32 - bits) >>> 0;
function quarterRound(state, a, b, c, d) {
  state[a] = state[a] + state[b] >>> 0;
  state[d] = rotateLeft32(state[d] ^ state[a], 16);
  state[c] = state[c] + state[d] >>> 0;
  state[b] = rotateLeft32(state[b] ^ state[c], 12);
  state[a] = state[a] + state[b] >>> 0;
  state[d] = rotateLeft32(state[d] ^ state[a], 8);
  state[c] = state[c] + state[d] >>> 0;
  state[b] = rotateLeft32(state[b] ^ state[c], 7);
}
function chacha20Block(key, counter, nonce) {
  const state = new Uint32Array(16);
  state[0] = 1634760805;
  state[1] = 857760878;
  state[2] = 2036477234;
  state[3] = 1797285236;
  const keyView = new DataView(key.buffer, key.byteOffset, key.byteLength);
  for (let i = 0; i < 8; i++) state[4 + i] = keyView.getUint32(4 * i, true);
  state[12] = counter;
  const nonceView = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
  state[13] = nonceView.getUint32(0, true);
  state[14] = nonceView.getUint32(4, true);
  state[15] = nonceView.getUint32(8, true);
  const working = new Uint32Array(state);
  for (let round = 0; round < 10; round++) {
    quarterRound(working, 0, 4, 8, 12);
    quarterRound(working, 1, 5, 9, 13);
    quarterRound(working, 2, 6, 10, 14);
    quarterRound(working, 3, 7, 11, 15);
    quarterRound(working, 0, 5, 10, 15);
    quarterRound(working, 1, 6, 11, 12);
    quarterRound(working, 2, 7, 8, 13);
    quarterRound(working, 3, 4, 9, 14);
  }
  for (let i = 0; i < 16; i++) working[i] = working[i] + state[i] >>> 0;
  return new Uint8Array(working.buffer.slice(0));
}
function chacha20Xor(key, nonce, data) {
  const output = new Uint8Array(data.length);
  let counter = 1;
  for (let offset = 0; offset < data.length; offset += 64) {
    const block = chacha20Block(key, counter++, nonce);
    const blockLength = Math.min(64, data.length - offset);
    for (let i = 0; i < blockLength; i++) {
      output[offset + i] = data[offset + i] ^ block[i];
    }
  }
  return output;
}

// src/crypto/poly1305.ts
function poly1305Mac(key, message) {
  const rBytes = key.slice(0, 16);
  const r = new Uint8Array(rBytes);
  r[3] &= 15;
  r[7] &= 15;
  r[11] &= 15;
  r[15] &= 15;
  r[4] &= 252;
  r[8] &= 252;
  r[12] &= 252;
  const s = key.slice(16, 32);
  const accumulator = [0n, 0n, 0n, 0n, 0n];
  const rLimbs = [
    0x3ffffffn & BigInt(r[0] | r[1] << 8 | r[2] << 16 | r[3] << 24),
    0x3ffffffn & BigInt(r[3] >> 2 | r[4] << 6 | r[5] << 14 | r[6] << 22),
    0x3ffffffn & BigInt(r[6] >> 4 | r[7] << 4 | r[8] << 12 | r[9] << 20),
    0x3ffffffn & BigInt(r[9] >> 6 | r[10] << 2 | r[11] << 10 | r[12] << 18),
    0x3ffffffn & BigInt(r[13] | r[14] << 8 | r[15] << 16)
  ];
  for (let offset = 0; offset < message.length; offset += 16) {
    const chunk = message.slice(offset, offset + 16);
    const padded = new Uint8Array(17);
    padded.set(chunk);
    padded[chunk.length] = 1;
    accumulator[0] += BigInt(
      padded[0] | padded[1] << 8 | padded[2] << 16 | (3 & padded[3]) << 24
    );
    accumulator[1] += BigInt(
      padded[3] >> 2 | padded[4] << 6 | padded[5] << 14 | (15 & padded[6]) << 22
    );
    accumulator[2] += BigInt(
      padded[6] >> 4 | padded[7] << 4 | padded[8] << 12 | (63 & padded[9]) << 20
    );
    accumulator[3] += BigInt(
      padded[9] >> 6 | padded[10] << 2 | padded[11] << 10 | padded[12] << 18
    );
    accumulator[4] += BigInt(
      padded[13] | padded[14] << 8 | padded[15] << 16 | padded[16] << 24
    );
    const product = [0n, 0n, 0n, 0n, 0n];
    for (let i = 0; i < 5; i++) {
      for (let j = 0; j < 5; j++) {
        const idx = i + j;
        if (idx < 5) {
          product[idx] += accumulator[i] * rLimbs[j];
        } else {
          product[idx - 5] += accumulator[i] * rLimbs[j] * 5n;
        }
      }
    }
    let carry = 0n;
    for (let i = 0; i < 5; i++) {
      product[i] += carry;
      accumulator[i] = 0x3ffffffn & product[i];
      carry = product[i] >> 26n;
    }
    accumulator[0] += 5n * carry;
    carry = accumulator[0] >> 26n;
    accumulator[0] &= 0x3ffffffn;
    accumulator[1] += carry;
  }
  let tagValue = accumulator[0] | accumulator[1] << 26n | accumulator[2] << 52n | accumulator[3] << 78n | accumulator[4] << 104n;
  tagValue = tagValue + s.reduce((total, byte, idx) => total + (BigInt(byte) << BigInt(8 * idx)), 0n) & (1n << 128n) - 1n;
  const tag = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    tag[i] = Number(tagValue >> BigInt(8 * i) & 0xffn);
  }
  return tag;
}

// src/crypto/chacha20-poly1305.ts
function chacha20Poly1305Encrypt(key, nonce, plaintext, additionalData) {
  const polyKey = chacha20Block(key, 0, nonce).slice(0, 32);
  const ciphertext = chacha20Xor(key, nonce, plaintext);
  const aadPad = (16 - additionalData.length % 16) % 16;
  const ctPad = (16 - ciphertext.length % 16) % 16;
  const macData = new Uint8Array(
    additionalData.length + aadPad + ciphertext.length + ctPad + 16
  );
  macData.set(additionalData, 0);
  macData.set(ciphertext, additionalData.length + aadPad);
  const lenView = new DataView(
    macData.buffer,
    additionalData.length + aadPad + ciphertext.length + ctPad
  );
  lenView.setBigUint64(0, BigInt(additionalData.length), true);
  lenView.setBigUint64(8, BigInt(ciphertext.length), true);
  const tag = poly1305Mac(polyKey, macData);
  return concatBytes(ciphertext, tag);
}
function chacha20Poly1305Decrypt(key, nonce, ciphertextWithTag, additionalData) {
  if (ciphertextWithTag.length < 16) throw new Error("Ciphertext too short");
  const tag = ciphertextWithTag.slice(-16);
  const ciphertext = ciphertextWithTag.slice(0, -16);
  const polyKey = chacha20Block(key, 0, nonce).slice(0, 32);
  const aadPad = (16 - additionalData.length % 16) % 16;
  const ctPad = (16 - ciphertext.length % 16) % 16;
  const macData = new Uint8Array(
    additionalData.length + aadPad + ciphertext.length + ctPad + 16
  );
  macData.set(additionalData, 0);
  macData.set(ciphertext, additionalData.length + aadPad);
  const lenView = new DataView(
    macData.buffer,
    additionalData.length + aadPad + ciphertext.length + ctPad
  );
  lenView.setBigUint64(0, BigInt(additionalData.length), true);
  lenView.setBigUint64(8, BigInt(ciphertext.length), true);
  const expectedTag = poly1305Mac(polyKey, macData);
  let diff = 0;
  for (let i = 0; i < 16; i++) diff |= tag[i] ^ expectedTag[i];
  if (diff !== 0) throw new Error("ChaCha20-Poly1305 authentication failed");
  return chacha20Xor(key, nonce, ciphertext);
}

// src/crypto/tls-record.ts
function buildTlsRecord(contentType, fragment, version = TLS_VERSION_12) {
  const data = toUint8Array(fragment);
  const record = new Uint8Array(5 + data.byteLength);
  record[0] = contentType;
  record[1] = version >> 8 & 255;
  record[2] = version & 255;
  record[3] = data.byteLength >> 8 & 255;
  record[4] = data.byteLength & 255;
  record.set(data, 5);
  return record;
}
function buildHandshakeMessage(handshakeType, body) {
  const lengthBytes = [
    body.length >> 16 & 255,
    body.length >> 8 & 255,
    body.length & 255
  ];
  return tlsBytes(handshakeType, lengthBytes, body);
}
var TlsRecordParser = class {
  buffer = new Uint8Array(0);
  feed(chunk) {
    const bytes = toUint8Array(chunk);
    this.buffer = this.buffer.length ? concatBytes(this.buffer, bytes) : bytes;
  }
  next() {
    if (this.buffer.length < 5) return null;
    const type = this.buffer[0];
    const version = readUint16(this.buffer, 1);
    const length = readUint16(this.buffer, 3);
    if (this.buffer.length < 5 + length) return null;
    const fragment = this.buffer.subarray(5, 5 + length);
    this.buffer = this.buffer.subarray(5 + length);
    return { type, version, length, fragment };
  }
};
var TlsHandshakeParser = class {
  buffer = new Uint8Array(0);
  feed(chunk) {
    const bytes = toUint8Array(chunk);
    this.buffer = this.buffer.length ? concatBytes(this.buffer, bytes) : bytes;
  }
  next() {
    if (this.buffer.length < 4) return null;
    const type = this.buffer[0];
    const length = readUint24(this.buffer, 1);
    if (this.buffer.length < 4 + length) return null;
    const body = this.buffer.subarray(4, 4 + length);
    const raw = this.buffer.subarray(0, 4 + length);
    this.buffer = this.buffer.subarray(4 + length);
    return { type, length, body, raw };
  }
};
var shouldIgnoreTlsAlert = (fragment) => fragment?.[0] === ALERT_LEVEL_WARNING && fragment?.[1] === ALERT_UNRECOGNIZED_NAME;
function xorSequenceIntoIv(iv, sequenceNumber) {
  const nonce = iv.slice();
  const seqBytes = uint64be(sequenceNumber);
  for (let i = 0; i < 8; i++) {
    nonce[nonce.length - 8 + i] ^= seqBytes[i];
  }
  return nonce;
}
async function deriveTrafficKeys(hash, secret, keyLen, ivLen) {
  return Promise.all([
    hkdfExpandLabel(hash, secret, "key", EMPTY_BYTES, keyLen),
    hkdfExpandLabel(hash, secret, "iv", EMPTY_BYTES, ivLen)
  ]);
}

// src/crypto/tls-messages.ts
var HELLO_RETRY_REQUEST_RANDOM = new Uint8Array([
  207,
  33,
  173,
  116,
  229,
  154,
  97,
  17,
  190,
  29,
  140,
  2,
  30,
  101,
  184,
  145,
  194,
  162,
  17,
  22,
  122,
  187,
  140,
  94,
  7,
  158,
  9,
  226,
  200,
  168,
  51,
  156
]);
function parseServerHello(body) {
  let offset = 0;
  const legacyVersion = readUint16(body, offset);
  offset += 2;
  const serverRandom = body.slice(offset, offset + 32);
  offset += 32;
  const sessionIdLength = body[offset++];
  const sessionId = body.slice(offset, offset + sessionIdLength);
  offset += sessionIdLength;
  const cipherSuite = readUint16(body, offset);
  offset += 2;
  const compression = body[offset++];
  let selectedVersion = legacyVersion;
  let keyShare = null;
  let alpn = null;
  if (offset < body.length) {
    const extensionsLength = readUint16(body, offset);
    offset += 2;
    const extensionsEnd = offset + extensionsLength;
    while (offset + 4 <= extensionsEnd) {
      const extType = readUint16(body, offset);
      offset += 2;
      const extLen = readUint16(body, offset);
      offset += 2;
      const extData = body.slice(offset, offset + extLen);
      offset += extLen;
      if (extType === EXT_SUPPORTED_VERSIONS && extLen >= 2) {
        selectedVersion = readUint16(extData, 0);
      } else if (extType === EXT_KEY_SHARE && extLen >= 4) {
        const group = readUint16(extData, 0);
        const keyLength = readUint16(extData, 2);
        keyShare = { group, key: extData.slice(4, 4 + keyLength) };
      } else if (extType === EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION && extLen >= 3) {
        alpn = textDecoder.decode(extData.slice(3, 3 + extData[2]));
      }
    }
  }
  return {
    version: legacyVersion,
    serverRandom,
    sessionId,
    cipherSuite,
    compression,
    selectedVersion,
    keyShare,
    alpn,
    isHRR: constantTimeEqual(serverRandom, HELLO_RETRY_REQUEST_RANDOM),
    isTls13: selectedVersion === TLS_VERSION_13
  };
}
function parseServerKeyExchange(body) {
  let offset = 1;
  const namedCurve = readUint16(body, offset);
  offset += 2;
  const keyLength = body[offset++];
  return {
    namedCurve,
    serverPublicKey: body.slice(offset, offset + keyLength)
  };
}
function extractLeafCertificate(body, hasContext = 0) {
  let offset = 0;
  if (hasContext) {
    const contextLength = body[offset++];
    offset += contextLength;
  }
  if (offset + 3 > body.length) return null;
  const certListLength = readUint24(body, offset);
  offset += 3;
  if (!certListLength || offset + 3 > body.length) return null;
  const certLength = readUint24(body, offset);
  offset += 3;
  return certLength ? body.slice(offset, offset + certLength) : null;
}
function parseEncryptedExtensions(body) {
  const parsed = { alpn: null };
  let offset = 2;
  const extensionsEnd = 2 + readUint16(body, 0);
  while (offset + 4 <= extensionsEnd) {
    const extType = readUint16(body, offset);
    offset += 2;
    const extLen = readUint16(body, offset);
    offset += 2;
    if (extType === EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION && extLen >= 3) {
      const protocolLength = body[offset + 2];
      if (protocolLength > 0 && 3 + protocolLength <= extLen) {
        parsed.alpn = textDecoder.decode(
          body.slice(offset + 3, offset + 3 + protocolLength)
        );
      }
    }
    offset += extLen;
  }
  return parsed;
}
function buildClientHello(clientRandom, serverName, keyShares, {
  tls13: enableTls13 = true,
  tls12: enableTls12 = true,
  alpn = null,
  chacha = true
} = {}) {
  const cipherIds = [];
  if (enableTls13) {
    cipherIds.push(4865, 4866);
    if (chacha) cipherIds.push(4867);
  }
  if (enableTls12) {
    cipherIds.push(49199, 49200, 49195, 49196);
    if (chacha) cipherIds.push(52392, 52393);
  }
  const cipherBytes = tlsBytes(...cipherIds.flatMap(uint16be));
  const extensions = [tlsBytes(255, 1, 0, 1, 0)];
  if (serverName) {
    const snBytes = textEncoder.encode(serverName);
    const snList = tlsBytes(0, uint16be(snBytes.length), snBytes);
    extensions.push(
      tlsBytes(
        uint16be(EXT_SERVER_NAME),
        uint16be(snList.length + 2),
        uint16be(snList.length),
        snList
      )
    );
  }
  extensions.push(tlsBytes(uint16be(EXT_EC_POINT_FORMATS), 0, 2, 1, 0));
  extensions.push(tlsBytes(uint16be(EXT_SUPPORTED_GROUPS), 0, 6, 0, 4, 0, 29, 0, 23));
  const sigBytes = tlsBytes(...SUPPORTED_SIGNATURE_ALGORITHMS.flatMap(uint16be));
  extensions.push(
    tlsBytes(
      uint16be(EXT_SIGNATURE_ALGORITHMS),
      uint16be(sigBytes.length + 2),
      uint16be(sigBytes.length),
      sigBytes
    )
  );
  const protocols = Array.isArray(alpn) ? alpn.filter(Boolean) : alpn ? [alpn] : [];
  if (protocols.length) {
    const alpnBytes = concatBytes(
      ...protocols.map((p) => {
        const pBytes = textEncoder.encode(p);
        return tlsBytes(pBytes.length, pBytes);
      })
    );
    extensions.push(
      tlsBytes(
        uint16be(EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION),
        uint16be(alpnBytes.length + 2),
        uint16be(alpnBytes.length),
        alpnBytes
      )
    );
  }
  if (enableTls13 && keyShares) {
    extensions.push(
      enableTls12 ? tlsBytes(uint16be(EXT_SUPPORTED_VERSIONS), 0, 5, 4, 3, 4, 3, 3) : tlsBytes(uint16be(EXT_SUPPORTED_VERSIONS), 0, 3, 2, 3, 4)
    );
    extensions.push(tlsBytes(uint16be(EXT_PSK_KEY_EXCHANGE_MODES), 0, 2, 1, 1));
    let keyShareBytes;
    if (typeof keyShares === "object" && !(keyShares instanceof Uint8Array) && keyShares.x25519 && keyShares.p256) {
      keyShareBytes = concatBytes(
        tlsBytes(0, 29, uint16be(keyShares.x25519.length), keyShares.x25519),
        tlsBytes(0, 23, uint16be(keyShares.p256.length), keyShares.p256)
      );
    } else if (typeof keyShares === "object" && !(keyShares instanceof Uint8Array) && keyShares.x25519) {
      keyShareBytes = tlsBytes(0, 29, uint16be(keyShares.x25519.length), keyShares.x25519);
    } else if (typeof keyShares === "object" && !(keyShares instanceof Uint8Array) && keyShares.p256) {
      keyShareBytes = tlsBytes(0, 23, uint16be(keyShares.p256.length), keyShares.p256);
    } else if (keyShares instanceof Uint8Array) {
      keyShareBytes = tlsBytes(0, 23, uint16be(keyShares.length), keyShares);
    } else {
      throw new Error("Invalid keyShares");
    }
    extensions.push(
      tlsBytes(
        uint16be(EXT_KEY_SHARE),
        uint16be(keyShareBytes.length + 2),
        uint16be(keyShareBytes.length),
        keyShareBytes
      )
    );
  }
  const extensionsBytes = concatBytes(...extensions);
  return buildHandshakeMessage(
    HANDSHAKE_TYPE_CLIENT_HELLO,
    tlsBytes(
      uint16be(TLS_VERSION_12),
      clientRandom,
      0,
      // legacy session ID length
      uint16be(cipherBytes.length),
      cipherBytes,
      1,
      0,
      // legacy compression methods: [null]
      uint16be(extensionsBytes.length),
      extensionsBytes
    )
  );
}

// src/crypto/tls-client.ts
var TlsClient = class {
  socket;
  serverName;
  supportTls13;
  supportTls12;
  alpnProtocols;
  allowChacha;
  timeout;
  clientRandom;
  serverRandom = null;
  handshakeChunks = [];
  handshakeComplete = false;
  negotiatedAlpn = null;
  cipherSuite = null;
  cipherConfig = null;
  isTls13 = false;
  // Secrets / keys
  masterSecret = null;
  handshakeSecret = null;
  clientWriteKey = null;
  serverWriteKey = null;
  clientWriteIv = null;
  serverWriteIv = null;
  clientHandshakeKey = null;
  serverHandshakeKey = null;
  clientHandshakeIv = null;
  serverHandshakeIv = null;
  clientAppKey = null;
  serverAppKey = null;
  clientAppIv = null;
  serverAppIv = null;
  // Cached CryptoKey objects (lazily imported) for AES-GCM paths
  clientWriteCryptoKey = null;
  serverWriteCryptoKey = null;
  clientHandshakeCryptoKey = null;
  serverHandshakeCryptoKey = null;
  clientAppCryptoKey = null;
  serverAppCryptoKey = null;
  clientSeqNum = 0n;
  serverSeqNum = 0n;
  recordParser = new TlsRecordParser();
  handshakeParser = new TlsHandshakeParser();
  keyPairs = /* @__PURE__ */ new Map();
  ecdhKeyPair = null;
  sawCert = false;
  constructor(socket, options = {}) {
    this.socket = socket;
    this.serverName = options.serverName || "";
    this.supportTls13 = options.tls13 !== false;
    this.supportTls12 = options.tls12 !== false;
    if (!this.supportTls13 && !this.supportTls12) {
      throw new Error("At least one TLS version must be enabled");
    }
    this.alpnProtocols = Array.isArray(options.alpn) ? options.alpn : options.alpn ? [options.alpn] : null;
    this.allowChacha = options.allowChacha !== false;
    this.timeout = options.timeout ?? 3e4;
    this.clientRandom = randomBytes(32);
  }
  // ─── Internal helpers ─────────────────────────────────────────────
  recordHandshake(chunk) {
    this.handshakeChunks.push(chunk);
  }
  transcript() {
    return this.handshakeChunks.length === 1 ? this.handshakeChunks[0] : concatBytes(...this.handshakeChunks);
  }
  getCipherConfig(cipherSuite) {
    return CIPHER_SUITES_BY_ID.get(cipherSuite) || null;
  }
  async readChunk(reader) {
    if (this.timeout) {
      return Promise.race([
        reader.read(),
        new Promise(
          (_, reject) => setTimeout(() => reject(new Error("TLS read timeout")), this.timeout)
        )
      ]);
    }
    return reader.read();
  }
  async readRecordsUntil(reader, predicate, closedError) {
    while (true) {
      let record;
      while (record = this.recordParser.next()) {
        if (await predicate(record)) return;
      }
      const { value, done } = await this.readChunk(reader);
      if (done) throw new Error(closedError);
      if (value) this.recordParser.feed(value);
    }
  }
  async readHandshakeUntil(reader, predicate, closedError) {
    let message;
    while (message = this.handshakeParser.next()) {
      if (await predicate(message)) return;
    }
    return this.readRecordsUntil(
      reader,
      async (record) => {
        if (record.type === CONTENT_TYPE_ALERT) {
          if (shouldIgnoreTlsAlert(record.fragment)) return;
          throw new Error(`TLS Alert: ${record.fragment[1]}`);
        }
        if (record.type === CONTENT_TYPE_HANDSHAKE) {
          this.handshakeParser.feed(record.fragment);
          let m;
          while (m = this.handshakeParser.next()) {
            if (await predicate(m)) return 1;
          }
        }
      },
      closedError
    );
  }
  async acceptCertificate(certificate) {
    if (!certificate?.length) throw new Error("Empty certificate");
    this.sawCert = true;
  }
  // ─── Public handshake driver ──────────────────────────────────────
  async handshake() {
    const [p256Share, x25519Share] = await Promise.all([
      generateKeyShare("P-256"),
      generateKeyShare("X25519")
    ]);
    this.keyPairs = /* @__PURE__ */ new Map([
      [23, p256Share],
      [29, x25519Share]
    ]);
    this.ecdhKeyPair = p256Share.keyPair;
    const reader = this.socket.readable.getReader();
    const writer = this.socket.writable.getWriter();
    try {
      const clientHello = buildClientHello(
        this.clientRandom,
        this.serverName,
        { x25519: x25519Share.publicKeyRaw, p256: p256Share.publicKeyRaw },
        {
          tls13: this.supportTls13,
          tls12: this.supportTls12,
          alpn: this.alpnProtocols,
          chacha: this.allowChacha
        }
      );
      this.recordHandshake(clientHello);
      await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, clientHello, TLS_VERSION_10));
      const serverHello = await this.receiveServerHello(reader);
      if (serverHello.isHRR) {
        throw new Error("HelloRetryRequest is not supported by TlsClient");
      }
      if (serverHello.keyShare?.group != null && this.keyPairs.has(serverHello.keyShare.group)) {
        const selected = this.keyPairs.get(serverHello.keyShare.group);
        this.ecdhKeyPair = selected.keyPair;
      }
      if (serverHello.isTls13) {
        await this.handshakeTls13(reader, writer, serverHello);
      } else {
        await this.handshakeTls12(reader, writer);
      }
      this.handshakeComplete = true;
    } finally {
      reader.releaseLock();
      writer.releaseLock();
    }
  }
  async receiveServerHello(reader) {
    while (true) {
      const { value, done } = await this.readChunk(reader);
      if (done) throw new Error("Connection closed waiting for ServerHello");
      if (value) this.recordParser.feed(value);
      let record;
      while (record = this.recordParser.next()) {
        if (record.type === CONTENT_TYPE_ALERT) {
          if (shouldIgnoreTlsAlert(record.fragment)) continue;
          throw new Error(`TLS Alert: level=${record.fragment[0]}, desc=${record.fragment[1]}`);
        }
        if (record.type !== CONTENT_TYPE_HANDSHAKE) continue;
        this.handshakeParser.feed(record.fragment);
        let message;
        while (message = this.handshakeParser.next()) {
          if (message.type !== HANDSHAKE_TYPE_SERVER_HELLO) continue;
          this.recordHandshake(message.raw);
          const sh = parseServerHello(message.body);
          this.serverRandom = sh.serverRandom;
          this.cipherSuite = sh.cipherSuite;
          this.cipherConfig = this.getCipherConfig(sh.cipherSuite);
          this.isTls13 = sh.isTls13;
          this.negotiatedAlpn = sh.alpn || null;
          if (!this.cipherConfig) {
            throw new Error(`Unsupported cipher suite: 0x${sh.cipherSuite.toString(16)}`);
          }
          return sh;
        }
      }
    }
  }
  // ─── TLS 1.2 handshake ────────────────────────────────────────────
  async handshakeTls12(reader, writer) {
    let serverKeyExchange = null;
    let sawServerHelloDone = false;
    await this.readHandshakeUntil(
      reader,
      async (message) => {
        switch (message.type) {
          case HANDSHAKE_TYPE_CERTIFICATE: {
            this.recordHandshake(message.raw);
            const cert = extractLeafCertificate(message.body, 1);
            if (!cert) throw new Error("Missing TLS 1.2 certificate");
            await this.acceptCertificate(cert);
            break;
          }
          case HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE:
            this.recordHandshake(message.raw);
            serverKeyExchange = parseServerKeyExchange(message.body);
            break;
          case HANDSHAKE_TYPE_SERVER_HELLO_DONE:
            this.recordHandshake(message.raw);
            sawServerHelloDone = true;
            return 1;
          case HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
            throw new Error("Client certificate is not supported");
          default:
            this.recordHandshake(message.raw);
        }
      },
      "Connection closed during TLS 1.2 handshake"
    );
    if (!this.sawCert) throw new Error("Missing TLS 1.2 leaf certificate");
    if (!serverKeyExchange) throw new Error("Missing TLS 1.2 ServerKeyExchange");
    const ske = serverKeyExchange;
    const curveName = GROUPS_BY_ID.get(ske.namedCurve);
    if (!curveName) {
      throw new Error(`Unsupported named curve: 0x${ske.namedCurve.toString(16)}`);
    }
    const keyShare = this.keyPairs.get(ske.namedCurve);
    if (!keyShare) {
      throw new Error(`Missing key pair for curve: 0x${ske.namedCurve.toString(16)}`);
    }
    const preMasterSecret = await deriveSharedSecret(
      keyShare.keyPair.privateKey,
      ske.serverPublicKey,
      curveName
    );
    const clientKeyExchange = buildHandshakeMessage(
      HANDSHAKE_TYPE_CERTIFICATE_REQUEST + 3,
      // CLIENT_KEY_EXCHANGE = 16
      tlsBytes(keyShare.publicKeyRaw.length, keyShare.publicKeyRaw)
    );
    this.recordHandshake(clientKeyExchange);
    const config = this.cipherConfig;
    const hashName = config.hash;
    this.masterSecret = await tls12Prf(
      preMasterSecret,
      "master secret",
      concatBytes(this.clientRandom, this.serverRandom),
      48,
      hashName
    );
    const keyLen = config.keyLen;
    const ivLen = config.ivLen;
    const keyBlock = await tls12Prf(
      this.masterSecret,
      "key expansion",
      concatBytes(this.serverRandom, this.clientRandom),
      2 * keyLen + 2 * ivLen,
      hashName
    );
    this.clientWriteKey = keyBlock.slice(0, keyLen);
    this.serverWriteKey = keyBlock.slice(keyLen, 2 * keyLen);
    this.clientWriteIv = keyBlock.slice(2 * keyLen, 2 * keyLen + ivLen);
    this.serverWriteIv = keyBlock.slice(2 * keyLen + ivLen, 2 * keyLen + 2 * ivLen);
    if (!config.chacha) {
      [this.clientWriteCryptoKey, this.serverWriteCryptoKey] = await Promise.all([
        importAesGcmKey(this.clientWriteKey, ["encrypt"]),
        importAesGcmKey(this.serverWriteKey, ["decrypt"])
      ]);
    }
    await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, clientKeyExchange));
    await writer.write(buildTlsRecord(CONTENT_TYPE_CHANGE_CIPHER_SPEC, tlsBytes(1)));
    const clientVerifyData = await tls12Prf(
      this.masterSecret,
      "client finished",
      await digestBytes(hashName, this.transcript()),
      12,
      hashName
    );
    const finishedMessage = buildHandshakeMessage(HANDSHAKE_TYPE_FINISHED, clientVerifyData);
    this.recordHandshake(finishedMessage);
    await writer.write(
      buildTlsRecord(
        CONTENT_TYPE_HANDSHAKE,
        await this.encryptTls12(finishedMessage, CONTENT_TYPE_HANDSHAKE)
      )
    );
    let sawChangeCipherSpec = false;
    await this.readRecordsUntil(
      reader,
      async (record) => {
        if (record.type === CONTENT_TYPE_ALERT) {
          if (shouldIgnoreTlsAlert(record.fragment)) return;
          throw new Error(`TLS Alert: ${record.fragment[1]}`);
        }
        if (record.type === CONTENT_TYPE_CHANGE_CIPHER_SPEC) {
          sawChangeCipherSpec = true;
          return;
        }
        if (record.type !== CONTENT_TYPE_HANDSHAKE || !sawChangeCipherSpec) return;
        const decrypted = await this.decryptTls12(record.fragment, CONTENT_TYPE_HANDSHAKE);
        if (decrypted[0] !== HANDSHAKE_TYPE_FINISHED) return;
        const verifyLen = readUint24(decrypted, 1);
        const verifyData = decrypted.slice(4, 4 + verifyLen);
        const expected = await tls12Prf(
          this.masterSecret,
          "server finished",
          await digestBytes(hashName, this.transcript()),
          12,
          hashName
        );
        if (!constantTimeEqual(verifyData, expected)) {
          throw new Error("TLS 1.2 server Finished verify failed");
        }
        return 1;
      },
      "Connection closed waiting for TLS 1.2 Finished"
    );
  }
  // ─── TLS 1.3 handshake ────────────────────────────────────────────
  async handshakeTls13(reader, writer, serverHello) {
    const groupId = serverHello.keyShare?.group;
    const groupName = groupId != null ? GROUPS_BY_ID.get(groupId) : void 0;
    if (!groupName || !serverHello.keyShare?.key?.length) {
      throw new Error("Missing TLS 1.3 key_share");
    }
    const config = this.cipherConfig;
    const hashName = config.hash;
    const hashLen = hashByteLength(hashName);
    const keyLen = config.keyLen;
    const ivLen = config.ivLen;
    const sharedSecret = await deriveSharedSecret(
      this.ecdhKeyPair.privateKey,
      serverHello.keyShare.key,
      groupName
    );
    const earlySecret = await hkdfExtract(hashName, null, new Uint8Array(hashLen));
    const derivedSecret = await hkdfExpandLabel(
      hashName,
      earlySecret,
      "derived",
      await digestBytes(hashName, EMPTY_BYTES),
      hashLen
    );
    this.handshakeSecret = await hkdfExtract(hashName, derivedSecret, sharedSecret);
    const transcriptHash = await digestBytes(hashName, this.transcript());
    const clientHsTrafficSecret = await hkdfExpandLabel(
      hashName,
      this.handshakeSecret,
      "c hs traffic",
      transcriptHash,
      hashLen
    );
    const serverHsTrafficSecret = await hkdfExpandLabel(
      hashName,
      this.handshakeSecret,
      "s hs traffic",
      transcriptHash,
      hashLen
    );
    [this.clientHandshakeKey, this.clientHandshakeIv] = await deriveTrafficKeys(
      hashName,
      clientHsTrafficSecret,
      keyLen,
      ivLen
    );
    [this.serverHandshakeKey, this.serverHandshakeIv] = await deriveTrafficKeys(
      hashName,
      serverHsTrafficSecret,
      keyLen,
      ivLen
    );
    if (!config.chacha) {
      [this.clientHandshakeCryptoKey, this.serverHandshakeCryptoKey] = await Promise.all([
        importAesGcmKey(this.clientHandshakeKey, ["encrypt"]),
        importAesGcmKey(this.serverHandshakeKey, ["decrypt"])
      ]);
    }
    const serverFinishedKey = await hkdfExpandLabel(
      hashName,
      serverHsTrafficSecret,
      "finished",
      EMPTY_BYTES,
      hashLen
    );
    let serverFinishedReceived = false;
    const handleHandshakeMessage = async (message) => {
      switch (message.type) {
        case HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: {
          const ee = parseEncryptedExtensions(message.body);
          if (ee.alpn) this.negotiatedAlpn = ee.alpn;
          this.recordHandshake(message.raw);
          break;
        }
        case HANDSHAKE_TYPE_CERTIFICATE: {
          const cert = extractLeafCertificate(message.body);
          if (!cert) throw new Error("Missing TLS 1.3 certificate");
          await this.acceptCertificate(cert);
          this.recordHandshake(message.raw);
          break;
        }
        case HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
          throw new Error("Client certificate is not supported");
        case HANDSHAKE_TYPE_CERTIFICATE_VERIFY:
          this.recordHandshake(message.raw);
          break;
        case HANDSHAKE_TYPE_FINISHED: {
          const expected = await hmac(
            hashName,
            serverFinishedKey,
            await digestBytes(hashName, this.transcript())
          );
          if (!constantTimeEqual(expected, message.body)) {
            throw new Error("TLS 1.3 server Finished verify failed");
          }
          this.recordHandshake(message.raw);
          serverFinishedReceived = true;
          break;
        }
        default:
          this.recordHandshake(message.raw);
      }
    };
    await this.readRecordsUntil(
      reader,
      async (record) => {
        if (record.type === CONTENT_TYPE_CHANGE_CIPHER_SPEC || record.type === CONTENT_TYPE_HANDSHAKE) {
          return;
        }
        if (record.type === CONTENT_TYPE_ALERT) {
          if (shouldIgnoreTlsAlert(record.fragment)) return;
          throw new Error(`TLS Alert: ${record.fragment[1]}`);
        }
        if (record.type !== CONTENT_TYPE_APPLICATION_DATA) return;
        const decrypted = await this.decryptTls13Handshake(record.fragment);
        const innerType = decrypted[decrypted.length - 1];
        const plaintext = decrypted.slice(0, -1);
        if (innerType === CONTENT_TYPE_HANDSHAKE) {
          this.handshakeParser.feed(plaintext);
          let message;
          while (message = this.handshakeParser.next()) {
            await handleHandshakeMessage(message);
            if (serverFinishedReceived) return 1;
          }
        }
      },
      "Connection closed during TLS 1.3 handshake"
    );
    const appTranscriptHash = await digestBytes(hashName, this.transcript());
    const masterDerivedSecret = await hkdfExpandLabel(
      hashName,
      this.handshakeSecret,
      "derived",
      await digestBytes(hashName, EMPTY_BYTES),
      hashLen
    );
    const masterSecret = await hkdfExtract(
      hashName,
      masterDerivedSecret,
      new Uint8Array(hashLen)
    );
    const clientAppTrafficSecret = await hkdfExpandLabel(
      hashName,
      masterSecret,
      "c ap traffic",
      appTranscriptHash,
      hashLen
    );
    const serverAppTrafficSecret = await hkdfExpandLabel(
      hashName,
      masterSecret,
      "s ap traffic",
      appTranscriptHash,
      hashLen
    );
    [this.clientAppKey, this.clientAppIv] = await deriveTrafficKeys(
      hashName,
      clientAppTrafficSecret,
      keyLen,
      ivLen
    );
    [this.serverAppKey, this.serverAppIv] = await deriveTrafficKeys(
      hashName,
      serverAppTrafficSecret,
      keyLen,
      ivLen
    );
    if (!config.chacha) {
      [this.clientAppCryptoKey, this.serverAppCryptoKey] = await Promise.all([
        importAesGcmKey(this.clientAppKey, ["encrypt"]),
        importAesGcmKey(this.serverAppKey, ["decrypt"])
      ]);
    }
    const clientFinishedKey = await hkdfExpandLabel(
      hashName,
      clientHsTrafficSecret,
      "finished",
      EMPTY_BYTES,
      hashLen
    );
    const clientFinishedVerifyData = await hmac(
      hashName,
      clientFinishedKey,
      await digestBytes(hashName, this.transcript())
    );
    const clientFinishedMessage = buildHandshakeMessage(
      HANDSHAKE_TYPE_FINISHED,
      clientFinishedVerifyData
    );
    this.recordHandshake(clientFinishedMessage);
    await writer.write(
      buildTlsRecord(
        CONTENT_TYPE_APPLICATION_DATA,
        await this.encryptTls13Handshake(
          concatBytes(clientFinishedMessage, new Uint8Array([CONTENT_TYPE_HANDSHAKE]))
        )
      )
    );
    this.clientSeqNum = 0n;
    this.serverSeqNum = 0n;
  }
  // ─── Record-layer encrypt/decrypt ─────────────────────────────────
  async encryptTls12(plaintext, contentType) {
    const seqNum = this.clientSeqNum++;
    const aad = concatBytes(
      // sequence number bytes
      new Uint8Array(new Uint8Array(new BigInt64Array([seqNum]).buffer).reverse()),
      new Uint8Array([contentType]),
      new Uint8Array(uint16be(TLS_VERSION_12)),
      new Uint8Array(uint16be(plaintext.length))
    );
    if (this.cipherConfig.chacha) {
      const nonce = xorSequenceIntoIv(this.clientWriteIv, seqNum);
      return chacha20Poly1305Encrypt(this.clientWriteKey, nonce, plaintext, aad);
    }
    const explicitNonce = randomBytes(8);
    if (!this.clientWriteCryptoKey) {
      this.clientWriteCryptoKey = await importAesGcmKey(this.clientWriteKey, ["encrypt"]);
    }
    return concatBytes(
      explicitNonce,
      await aesGcmEncrypt(
        this.clientWriteCryptoKey,
        concatBytes(this.clientWriteIv, explicitNonce),
        plaintext,
        aad
      )
    );
  }
  async decryptTls12(ciphertext, contentType) {
    const seqNum = this.serverSeqNum++;
    const seqBytes = new Uint8Array(new Uint8Array(new BigInt64Array([seqNum]).buffer).reverse());
    if (this.cipherConfig.chacha) {
      const nonce = xorSequenceIntoIv(this.serverWriteIv, seqNum);
      const aad = concatBytes(
        seqBytes,
        new Uint8Array([contentType]),
        new Uint8Array(uint16be(TLS_VERSION_12)),
        new Uint8Array(uint16be(ciphertext.length - 16))
      );
      return chacha20Poly1305Decrypt(this.serverWriteKey, nonce, ciphertext, aad);
    }
    const explicitNonce = ciphertext.subarray(0, 8);
    const encryptedData = ciphertext.subarray(8);
    if (!this.serverWriteCryptoKey) {
      this.serverWriteCryptoKey = await importAesGcmKey(this.serverWriteKey, ["decrypt"]);
    }
    return aesGcmDecrypt(
      this.serverWriteCryptoKey,
      concatBytes(this.serverWriteIv, explicitNonce),
      encryptedData,
      concatBytes(
        seqBytes,
        new Uint8Array([contentType]),
        new Uint8Array(uint16be(TLS_VERSION_12)),
        new Uint8Array(uint16be(encryptedData.length - 16))
      )
    );
  }
  async encryptTls13Handshake(plaintext) {
    const nonce = xorSequenceIntoIv(this.clientHandshakeIv, this.clientSeqNum++);
    const aad = tlsBytes(
      CONTENT_TYPE_APPLICATION_DATA,
      3,
      3,
      uint16be(plaintext.length + 16)
    );
    if (this.cipherConfig.chacha) {
      return chacha20Poly1305Encrypt(this.clientHandshakeKey, nonce, plaintext, aad);
    }
    if (!this.clientHandshakeCryptoKey) {
      this.clientHandshakeCryptoKey = await importAesGcmKey(this.clientHandshakeKey, ["encrypt"]);
    }
    return aesGcmEncrypt(this.clientHandshakeCryptoKey, nonce, plaintext, aad);
  }
  async decryptTls13Handshake(ciphertext) {
    const nonce = xorSequenceIntoIv(this.serverHandshakeIv, this.serverSeqNum++);
    const aad = tlsBytes(
      CONTENT_TYPE_APPLICATION_DATA,
      3,
      3,
      uint16be(ciphertext.length)
    );
    const decrypted = this.cipherConfig.chacha ? await chacha20Poly1305Decrypt(this.serverHandshakeKey, nonce, ciphertext, aad) : await aesGcmDecrypt(
      this.serverHandshakeCryptoKey || (this.serverHandshakeCryptoKey = await importAesGcmKey(
        this.serverHandshakeKey,
        ["decrypt"]
      )),
      nonce,
      ciphertext,
      aad
    );
    let innerTypeIndex = decrypted.length - 1;
    while (innerTypeIndex >= 0 && !decrypted[innerTypeIndex]) innerTypeIndex--;
    return innerTypeIndex < 0 ? EMPTY_BYTES : decrypted.slice(0, innerTypeIndex + 1);
  }
  async encryptTls13(data) {
    const plaintext = concatBytes(data, new Uint8Array([CONTENT_TYPE_APPLICATION_DATA]));
    const nonce = xorSequenceIntoIv(this.clientAppIv, this.clientSeqNum++);
    const aad = tlsBytes(
      CONTENT_TYPE_APPLICATION_DATA,
      3,
      3,
      uint16be(plaintext.length + 16)
    );
    if (this.cipherConfig.chacha) {
      return chacha20Poly1305Encrypt(this.clientAppKey, nonce, plaintext, aad);
    }
    if (!this.clientAppCryptoKey) {
      this.clientAppCryptoKey = await importAesGcmKey(this.clientAppKey, ["encrypt"]);
    }
    return aesGcmEncrypt(this.clientAppCryptoKey, nonce, plaintext, aad);
  }
  async decryptTls13(ciphertext) {
    const nonce = xorSequenceIntoIv(this.serverAppIv, this.serverSeqNum++);
    const aad = tlsBytes(
      CONTENT_TYPE_APPLICATION_DATA,
      3,
      3,
      uint16be(ciphertext.length)
    );
    const plaintext = this.cipherConfig.chacha ? await chacha20Poly1305Decrypt(this.serverAppKey, nonce, ciphertext, aad) : await aesGcmDecrypt(
      this.serverAppCryptoKey || (this.serverAppCryptoKey = await importAesGcmKey(this.serverAppKey, ["decrypt"])),
      nonce,
      ciphertext,
      aad
    );
    let innerTypeIndex = plaintext.length - 1;
    while (innerTypeIndex >= 0 && !plaintext[innerTypeIndex]) innerTypeIndex--;
    if (innerTypeIndex < 0) return { data: EMPTY_BYTES, type: 0 };
    return { data: plaintext.slice(0, innerTypeIndex), type: plaintext[innerTypeIndex] };
  }
  // ─── Public application-data API ──────────────────────────────────
  async write(data) {
    if (!this.handshakeComplete) throw new Error("Handshake not complete");
    const plaintext = toUint8Array(data);
    if (!plaintext.byteLength) return;
    const writer = this.socket.writable.getWriter();
    try {
      const records = [];
      for (let offset = 0; offset < plaintext.byteLength; offset += TLS_MAX_PLAINTEXT_FRAGMENT) {
        const chunk = plaintext.subarray(
          offset,
          Math.min(offset + TLS_MAX_PLAINTEXT_FRAGMENT, plaintext.byteLength)
        );
        const encrypted = this.isTls13 ? await this.encryptTls13(chunk) : await this.encryptTls12(chunk, CONTENT_TYPE_APPLICATION_DATA);
        records.push(buildTlsRecord(CONTENT_TYPE_APPLICATION_DATA, encrypted));
      }
      await writer.write(records.length === 1 ? records[0] : concatBytes(...records));
    } finally {
      writer.releaseLock();
    }
  }
  async read() {
    while (true) {
      let record;
      while (record = this.recordParser.next()) {
        if (record.type === CONTENT_TYPE_ALERT) {
          if (record.fragment[1] === ALERT_CLOSE_NOTIFY) return null;
          throw new Error(`TLS Alert: ${record.fragment[1]}`);
        }
        if (record.type !== CONTENT_TYPE_APPLICATION_DATA) continue;
        if (!this.isTls13) {
          return this.decryptTls12(record.fragment, CONTENT_TYPE_APPLICATION_DATA);
        }
        const { data, type } = await this.decryptTls13(record.fragment);
        if (type === CONTENT_TYPE_APPLICATION_DATA) return data;
        if (type === CONTENT_TYPE_ALERT) {
          if (data[1] === ALERT_CLOSE_NOTIFY) return null;
          throw new Error(`TLS Alert: ${data[1]}`);
        }
        if (type !== CONTENT_TYPE_HANDSHAKE) continue;
        this.handshakeParser.feed(data);
        let message;
        while (message = this.handshakeParser.next()) {
          if (message.type !== HANDSHAKE_TYPE_NEW_SESSION_TICKET && message.type === HANDSHAKE_TYPE_KEY_UPDATE) {
            throw new Error("TLS 1.3 KeyUpdate is not supported by TlsClient");
          }
        }
      }
      const reader = this.socket.readable.getReader();
      try {
        const { value, done } = await this.readChunk(reader);
        if (done) return null;
        if (value) this.recordParser.feed(value);
      } finally {
        reader.releaseLock();
      }
    }
  }
  close() {
    this.socket.close();
  }
};

// src/transports/tls-wrap.ts
function wrapTlsSocket(tlsSocket, bufferedData = null) {
  let closedSettled = false;
  let resolveClosed;
  let rejectClosed;
  const settleClosed = (settle, value) => {
    if (!closedSettled) {
      closedSettled = true;
      settle(value);
    }
  };
  const closed = new Promise((resolve, reject) => {
    resolveClosed = resolve;
    rejectClosed = reject;
  });
  const close = () => {
    try {
      tlsSocket.close();
    } catch (e) {
    }
    settleClosed(resolveClosed);
  };
  const readable = new ReadableStream({
    async start(controller) {
      try {
        if (byteLength(bufferedData) > 0 && bufferedData) {
          controller.enqueue(bufferedData);
        }
        while (true) {
          const data = await tlsSocket.read();
          if (!data) break;
          if (data.byteLength > 0) controller.enqueue(data);
        }
        try {
          controller.close();
        } catch (e) {
        }
        settleClosed(resolveClosed);
      } catch (error) {
        try {
          controller.error(error);
        } catch (e) {
        }
        settleClosed(rejectClosed, error);
      }
    },
    cancel() {
      close();
    }
  });
  const writable = new WritableStream({
    async write(chunk) {
      await tlsSocket.write(toUint8Array(chunk));
    },
    close,
    abort(error) {
      close();
      if (error) settleClosed(rejectClosed, error);
    }
  });
  return { readable, writable, closed, close };
}

// src/transports/https-proxy.ts
async function httpsConnect(ctx, targetHost, targetPort, initialData, log = () => {
}) {
  const { username, password, hostname, port } = ctx.parsedSocks5;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  let tlsSocket = null;
  const tlsServerName = isIPHostname(hostname) ? "" : stripIPv6Brackets(hostname);
  const needsChachaFallback = (error) => /cipher|handshake|TLS Alert|ServerHello|Finished|Unsupported|Missing TLS/i.test(
    error?.message || `${error || ""}`
  );
  const openProxyTls = async (allowChacha = false) => {
    const proxySocket = connect5({ hostname, port });
    try {
      await proxySocket.opened;
      const socket = new TlsClient(proxySocket, {
        serverName: tlsServerName,
        insecure: true,
        allowChacha
      });
      await socket.handshake();
      log(
        `[HTTPS-PROXY] TLS ${socket.isTls13 ? "1.3" : "1.2"} | cipher: 0x${socket.cipherSuite?.toString(16)}${socket.cipherConfig?.chacha ? " (ChaCha20)" : " (AES-GCM)"}`
      );
      return socket;
    } catch (error) {
      try {
        proxySocket.close();
      } catch (e) {
      }
      throw error;
    }
  };
  try {
    try {
      tlsSocket = await openProxyTls(false);
    } catch (error) {
      if (!needsChachaFallback(error)) throw error;
      log(
        `[HTTPS-PROXY] AES-GCM TLS handshake failed, falling back to ChaCha20: ${error?.message || error}`
      );
      tlsSocket = await openProxyTls(true);
    }
    const auth = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r
` : "";
    const request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r
Host: ${targetHost}:${targetPort}\r
` + auth + `User-Agent: Mozilla/5.0\r
Connection: keep-alive\r
\r
`;
    await tlsSocket.write(encoder.encode(request));
    let responseBuffer = new Uint8Array(0);
    let headerEndIndex = -1;
    let bytesRead = 0;
    while (headerEndIndex === -1 && bytesRead < 8192) {
      const value = await tlsSocket.read();
      if (!value) throw new Error("HTTPS proxy closed connection before CONNECT response");
      responseBuffer = concatByteArrays(responseBuffer, value);
      bytesRead = responseBuffer.length;
      const idx = responseBuffer.findIndex(
        (_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 13 && responseBuffer[i + 1] === 10 && responseBuffer[i + 2] === 13 && responseBuffer[i + 3] === 10
      );
      if (idx !== -1) headerEndIndex = idx + 4;
    }
    if (headerEndIndex === -1) {
      throw new Error("HTTPS proxy CONNECT response too long or invalid");
    }
    const statusLine = decoder.decode(responseBuffer.slice(0, headerEndIndex)).split("\r\n")[0];
    const statusMatch = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
    const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
    if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) {
      throw new Error(`Connection failed: HTTP ${statusCode}`);
    }
    if (byteLength(initialData) > 0 && initialData) {
      await tlsSocket.write(toUint8Array(initialData));
    }
    const bufferedData = bytesRead > headerEndIndex ? responseBuffer.subarray(headerEndIndex, bytesRead) : null;
    return wrapTlsSocket(tlsSocket, bufferedData);
  } catch (error) {
    try {
      tlsSocket?.close();
    } catch (e) {
    }
    throw error;
  }
}

// src/admin/pages.ts
function nginx() {
  return `
	<!DOCTYPE html>
	<html>
	<head>
	<title>Welcome to nginx!</title>
	<style>
		body {
			width: 35em;
			margin: 0 auto;
			font-family: Tahoma, Verdana, Arial, sans-serif;
		}
	</style>
	</head>
	<body>
	<h1>Welcome to nginx!</h1>
	<p>If you see this page, the nginx web server is successfully installed and
	working. Further configuration is required.</p>

	<p>For online documentation and support please refer to
	<a href="http://nginx.org/">nginx.org</a>.<br/>
	Commercial support is available at
	<a href="http://nginx.com/">nginx.com</a>.</p>

	<p><em>Thank you for using nginx.</em></p>
	</body>
	</html>
	`;
}
function html1101(host, accessIP) {
  const now = /* @__PURE__ */ new Date();
  const formattedTimestamp = now.getFullYear() + "-" + String(now.getMonth() + 1).padStart(2, "0") + "-" + String(now.getDate()).padStart(2, "0") + " " + String(now.getHours()).padStart(2, "0") + ":" + String(now.getMinutes()).padStart(2, "0") + ":" + String(now.getSeconds()).padStart(2, "0");
  const randomRayId = Array.from(crypto.getRandomValues(new Uint8Array(8))).map((b) => b.toString(16).padStart(2, "0")).join("");
  return `<!DOCTYPE html>
<!--[if lt IE 7]> <html class="no-js ie6 oldie" lang="en-US"> <![endif]-->
<!--[if IE 7]>    <html class="no-js ie7 oldie" lang="en-US"> <![endif]-->
<!--[if IE 8]>    <html class="no-js ie8 oldie" lang="en-US"> <![endif]-->
<!--[if gt IE 8]><!--> <html class="no-js" lang="en-US"> <!--<![endif]-->
<head>
<title>Worker threw exception | ${host} | Cloudflare</title>
<meta charset="UTF-8" />
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<meta http-equiv="X-UA-Compatible" content="IE=Edge" />
<meta name="robots" content="noindex, nofollow" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<link rel="stylesheet" id="cf_styles-css" href="/cdn-cgi/styles/cf.errors.css" />
<!--[if lt IE 9]><link rel="stylesheet" id='cf_styles-ie-css' href="/cdn-cgi/styles/cf.errors.ie.css" /><![endif]-->
<style>body{margin:0;padding:0}</style>


<!--[if gte IE 10]><!-->
<script>
  if (!navigator.cookieEnabled) {
    window.addEventListener('DOMContentLoaded', function () {
      var cookieEl = document.getElementById('cookie-alert');
      cookieEl.style.display = 'block';
    })
  }
</script>
<!--<![endif]-->

</head>
<body>
    <div id="cf-wrapper">
        <div class="cf-alert cf-alert-error cf-cookie-error" id="cookie-alert" data-translate="enable_cookies">Please enable cookies.</div>
        <div id="cf-error-details" class="cf-error-details-wrapper">
            <div class="cf-wrapper cf-header cf-error-overview">
                <h1>
                    <span class="cf-error-type" data-translate="error">Error</span>
                    <span class="cf-error-code">1101</span>
                    <small class="heading-ray-id">Ray ID: ${randomRayId} &bull; ${formattedTimestamp} UTC</small>
                </h1>
                <h2 class="cf-subheadline" data-translate="error_desc">Worker threw exception</h2>
            </div><!-- /.header -->

            <section></section><!-- spacer -->

            <div class="cf-section cf-wrapper">
                <div class="cf-columns two">
                    <div class="cf-column">
                        <h2 data-translate="what_happened">What happened?</h2>
                            <p>You've requested a page on a website (${host}) that is on the <a href="https://www.cloudflare.com/5xx-error-landing?utm_source=error_100x" target="_blank">Cloudflare</a> network. An unknown error occurred while rendering the page.</p>
                    </div>

                    <div class="cf-column">
                        <h2 data-translate="what_can_i_do">What can I do?</h2>
                            <p><strong>If you are the owner of this website:</strong><br />refer to <a href="https://developers.cloudflare.com/workers/observability/errors/" target="_blank">Workers - Errors and Exceptions</a> and check Workers Logs for ${host}.</p>
                    </div>

                </div>
            </div><!-- /.section -->

            <div class="cf-error-footer cf-wrapper w-240 lg:w-full py-10 sm:py-4 sm:px-8 mx-auto text-center sm:text-left border-solid border-0 border-t border-gray-300">
    <p class="text-13">
      <span class="cf-footer-item sm:block sm:mb-1">Cloudflare Ray ID: <strong class="font-semibold"> ${randomRayId}</strong></span>
      <span class="cf-footer-separator sm:hidden">&bull;</span>
      <span id="cf-footer-item-ip" class="cf-footer-item hidden sm:block sm:mb-1">
        Your IP:
        <button type="button" id="cf-footer-ip-reveal" class="cf-footer-ip-reveal-btn">Click to reveal</button>
        <span class="hidden" id="cf-footer-ip">${accessIP}</span>
        <span class="cf-footer-separator sm:hidden">&bull;</span>
      </span>
      <span class="cf-footer-item sm:block sm:mb-1"><span>Performance &amp; security by</span> <a rel="noopener noreferrer" href="https://www.cloudflare.com/5xx-error-landing" id="brand_link" target="_blank">Cloudflare</a></span>

    </p>
    <script>(function(){function d(){var b=a.getElementById("cf-footer-item-ip"),c=a.getElementById("cf-footer-ip-reveal");b&&"classList"in b&&(b.classList.remove("hidden"),c.addEventListener("click",function(){c.classList.add("hidden");a.getElementById("cf-footer-ip").classList.remove("hidden")}))}var a=document;document.addEventListener&&a.addEventListener("DOMContentLoaded",d)})();</script>
  </div><!-- /.error-footer -->

        </div><!-- /#cf-error-details -->
    </div><!-- /#cf-wrapper -->

     <script>
    window._cf_translation = {};


  </script>
</body>
</html>`;
}

// src/index.ts
var VERSION = "2026-05-03 01:19:25";
var UUID_REGEX = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
var src_default = {
  async fetch(request, env, workerCtx) {
    const url = new URL(normalizeRequestUrl(request.url));
    const ua = request.headers.get("User-Agent") || "null";
    const upgradeHeader = (request.headers.get("Upgrade") || "").toLowerCase();
    const contentType = (request.headers.get("content-type") || "").toLowerCase();
    const adminPassword = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY || env.UUID || env.uuid || "";
    const encryptKey = env.KEY || "\u52FF\u52A8\u6B64\u9ED8\u8BA4\u5BC6\u94A5\uFF0C\u6709\u9700\u6C42\u8BF7\u81EA\u884C\u901A\u8FC7\u6DFB\u52A0\u53D8\u91CFKEY\u8FDB\u884C\u4FEE\u6539";
    const userIDMD5 = await md5x2(adminPassword + encryptKey);
    const envUUID = env.UUID || env.uuid;
    const userID = envUUID && UUID_REGEX.test(envUUID) ? envUUID.toLowerCase() : [
      userIDMD5.slice(0, 8),
      userIDMD5.slice(8, 12),
      "4" + userIDMD5.slice(13, 16),
      "8" + userIDMD5.slice(17, 20),
      userIDMD5.slice(20)
    ].join("-");
    const hosts = env.HOST ? toArray(env.HOST).map(
      (h) => h.toLowerCase().replace(/^https?:\/\//, "").split("/")[0].split(":")[0]
    ) : [url.hostname];
    const host = hosts[0];
    const accessPath = url.pathname.slice(1).toLowerCase();
    const casePreservingPath = url.pathname.slice(1);
    const ctx = createDefaultContext();
    ctx.debugLogEnabled = ["1", "true"].includes(env.DEBUG || "");
    if (env.PROXYIP) {
      const proxyIPs = toArray(env.PROXYIP);
      ctx.proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
      ctx.proxyFallbackEnabled = false;
    } else {
      ctx.proxyIP = (request.cf?.colo + ".PrOxYIp.CmLiUsSsS.nEt").toLowerCase();
    }
    if (env.GO2SOCKS5) ctx.socks5Whitelist = toArray(env.GO2SOCKS5);
    const accessIP = request.headers.get("CF-Connecting-IP") || request.headers.get("True-Client-IP") || request.headers.get("X-Real-IP") || request.headers.get("X-Forwarded-For") || request.headers.get("Fly-Client-IP") || request.headers.get("X-Appengine-Remote-Addr") || request.headers.get("X-Cluster-Client-IP") || "unknown-IP";
    const log = makeLogger(ctx);
    const tcpDeps = {
      ctx,
      log,
      resolveProxyIPs: (proxyIP, target, uuid) => parseAddressPort(ctx, proxyIP, target, uuid, log),
      httpsConnect: (c, h, p, d) => httpsConnect(c, h, p, d, log)
    };
    if (accessPath === "version" && url.searchParams.get("uuid") === userID) {
      return new Response(
        JSON.stringify({ Version: Number(String(VERSION).replace(/\D+/g, "")) }),
        {
          status: 200,
          headers: { "Content-Type": "application/json;charset=utf-8" }
        }
      );
    }
    if (adminPassword && upgradeHeader === "websocket") {
      await parseProxyParams(ctx, url);
      log(`[WS] hit: ${url.pathname}${url.search}`);
      return await handleWebSocketRequest(tcpDeps, request, userID, url);
    }
    if (adminPassword && !accessPath.startsWith("admin/") && accessPath !== "login" && request.method === "POST") {
      await parseProxyParams(ctx, url);
      const referer = request.headers.get("Referer") || "";
      const isXhttpHint = referer.includes("x_padding", 14) || referer.includes("x_padding=");
      if (!isXhttpHint && contentType.startsWith("application/grpc")) {
        log(`[gRPC] hit: ${url.pathname}${url.search}`);
        return await handleGrpcRequest(tcpDeps, request, userID);
      }
      log(`[XHTTP] hit: ${url.pathname}${url.search}`);
      return await handleXhttpRequest(tcpDeps, request, userID);
    }
    if (url.protocol === "http:") {
      return Response.redirect(
        url.href.replace(`http://${url.hostname}`, `https://${url.hostname}`),
        301
      );
    }
    if (!adminPassword) {
      const r = await fetch(PAGES_STATIC_URL + "/noADMIN");
      const headers = new Headers(r.headers);
      headers.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
      headers.set("Pragma", "no-cache");
      headers.set("Expires", "0");
      return new Response(r.body, {
        status: 404,
        statusText: r.statusText,
        headers
      });
    }
    if (env.KV && typeof env.KV.get === "function") {
      if (casePreservingPath === encryptKey && encryptKey !== "\u52FF\u52A8\u6B64\u9ED8\u8BA4\u5BC6\u94A5\uFF0C\u6709\u9700\u6C42\u8BF7\u81EA\u884C\u901A\u8FC7\u6DFB\u52A0\u53D8\u91CFKEY\u8FDB\u884C\u4FEE\u6539") {
        const params = new URLSearchParams(url.search);
        params.set("token", await md5x2(host + userID));
        return new Response("Redirecting...", {
          status: 302,
          headers: { Location: `/sub?${params.toString()}` }
        });
      }
      if (accessPath === "login") {
        return handleLogin(request, ua, adminPassword, encryptKey);
      }
      if (accessPath === "admin" || accessPath.startsWith("admin/")) {
        const ok = await verifyAuthCookie(request, ua, adminPassword, encryptKey);
        if (!ok) {
          return new Response("Redirecting...", {
            status: 302,
            headers: { Location: "/login" }
          });
        }
        return handleAdmin(
          ctx,
          env,
          request,
          url,
          accessPath,
          casePreservingPath,
          host,
          userID,
          ua,
          accessIP,
          workerCtx
        );
      }
      if (accessPath === "logout" || UUID_REGEX.test(accessPath)) {
        const response = new Response("Redirecting...", {
          status: 302,
          headers: { Location: "/login" }
        });
        response.headers.set("Set-Cookie", "auth=; Path=/; Max-Age=0; HttpOnly");
        return response;
      }
      if (accessPath === "sub") {
        const subResponse = await handleSubscription(
          ctx,
          env,
          request,
          url,
          host,
          userID,
          ua,
          accessIP,
          workerCtx
        );
        if (subResponse) return subResponse;
      }
      if (accessPath === "locations") {
        const ok = await verifyAuthCookie(request, ua, adminPassword, encryptKey);
        if (ok) {
          return fetch(
            new Request("https://speed.cloudflare.com/locations", {
              headers: { Referer: "https://speed.cloudflare.com/" }
            })
          );
        }
      }
      if (accessPath === "robots.txt") {
        return new Response("User-agent: *\nDisallow: /", {
          status: 200,
          headers: { "Content-Type": "text/plain; charset=UTF-8" }
        });
      }
    } else if (!envUUID) {
      const r = await fetch(PAGES_STATIC_URL + "/noKV");
      const headers = new Headers(r.headers);
      headers.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
      headers.set("Pragma", "no-cache");
      headers.set("Expires", "0");
      return new Response(r.body, {
        status: 404,
        statusText: r.statusText,
        headers
      });
    }
    let disguiseUrl = env.URL || "nginx";
    if (disguiseUrl && disguiseUrl !== "nginx" && disguiseUrl !== "1101") {
      disguiseUrl = disguiseUrl.trim().replace(/\/$/, "");
      if (!disguiseUrl.match(/^https?:\/\//i)) disguiseUrl = "https://" + disguiseUrl;
      if (disguiseUrl.toLowerCase().startsWith("http://")) {
        disguiseUrl = "https://" + disguiseUrl.substring(7);
      }
      try {
        const u = new URL(disguiseUrl);
        disguiseUrl = u.protocol + "//" + u.host;
      } catch (e) {
        disguiseUrl = "nginx";
      }
    }
    if (disguiseUrl === "1101") {
      return new Response(html1101(url.host, accessIP), {
        status: 200,
        headers: { "Content-Type": "text/html; charset=UTF-8" }
      });
    }
    if (disguiseUrl !== "nginx") {
      try {
        const targetURL = new URL(disguiseUrl);
        const newHeaders = new Headers(request.headers);
        newHeaders.set("Host", targetURL.host);
        newHeaders.set("Referer", targetURL.origin);
        newHeaders.set("Origin", targetURL.origin);
        if (!newHeaders.has("User-Agent") && ua && ua !== "null") {
          newHeaders.set("User-Agent", ua);
        }
        const proxyResponse = await fetch(
          targetURL.origin + url.pathname + url.search,
          {
            method: request.method,
            headers: newHeaders,
            body: request.body,
            cf: request.cf
          }
        );
        const respContentType = proxyResponse.headers.get("content-type") || "";
        if (/text|javascript|json|xml/.test(respContentType)) {
          const body = (await proxyResponse.text()).replaceAll(targetURL.host, url.host);
          return new Response(body, {
            status: proxyResponse.status,
            headers: {
              ...Object.fromEntries(proxyResponse.headers),
              "Cache-Control": "no-store"
            }
          });
        }
        return proxyResponse;
      } catch (error) {
      }
    }
    return new Response(nginx(), {
      status: 200,
      headers: { "Content-Type": "text/html; charset=UTF-8" }
    });
  }
};
export {
  src_default as default
};
