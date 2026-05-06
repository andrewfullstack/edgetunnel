// Request logging — persists structured access records to KV and
// optionally relays to Telegram via bot API.
//
// This is the audit log that the admin panel reads back via /admin/log.json.

/**
 * Mask sensitive fields by replacing the middle with asterisks.
 * Returns the original if it's too short to mask meaningfully.
 */
export function maskSensitive(text: string, prefixLen = 3, suffixLen = 2): string {
  if (!text || typeof text !== 'string') return text;
  if (text.length <= prefixLen + suffixLen) return text;
  const prefix = text.slice(0, prefixLen);
  const suffix = text.slice(-suffixLen);
  const stars = text.length - prefixLen - suffixLen;
  return `${prefix}${'*'.repeat(stars)}${suffix}`;
}

interface LogEnv {
  KV: KVNamespace;
  OFF_LOG?: string;
}

interface LogConfig {
  TG?: { enabled?: boolean };
  'preferredSub'?: { SUBNAME?: string };
  CF?: { Usage?: { success?: boolean; total?: number; max?: number } };
}

interface CfRequestProps {
  cf?: {
    asn?: number;
    asOrganization?: string;
    country?: string;
    city?: string;
  };
  url: string;
  headers: Headers;
}

interface LogEntry {
  TYPE: string;
  IP: string;
  ASN: string;
  CC: string;
  URL: string;
  UA: string;
  TIME: number;
}

const KV_SIZE_LIMIT_MB = 4;

/**
 * Append a structured log entry to the KV-backed access log.
 * Optionally relays the entry to Telegram if configJson.TG.enabled is set.
 *
 * Behaviour:
 *   - For non-Get_SUB types: dedupes against entries from the last 30 min
 *   - Trims log array to fit within KV_SIZE_LIMIT_MB
 *   - Honours OFF_LOG env var
 */
export async function logRequest(
  env: LogEnv,
  request: CfRequestProps,
  accessIP: string,
  requestType: string = 'Get_SUB',
  configJson: LogConfig,
  writeToKV: boolean = true
): Promise<void> {
  try {
    const now = new Date();
    const entry: LogEntry = {
      TYPE: requestType,
      IP: accessIP,
      ASN: `AS${request.cf?.asn || '0'} ${request.cf?.asOrganization || 'Unknown'}`,
      CC: `${request.cf?.country || 'N/A'} ${request.cf?.city || 'N/A'}`,
      URL: request.url,
      UA: request.headers.get('User-Agent') || 'Unknown',
      TIME: now.getTime(),
    };

    // Telegram relay
    if (configJson.TG?.enabled) {
      try {
        const tgText = await env.KV.get('tg.json');
        const tgJson = tgText ? JSON.parse(tgText) : null;
        if (tgJson?.BotToken && tgJson?.ChatID) {
          const requestTime = new Date(entry.TIME).toLocaleString('zh-CN', {
            timeZone: 'Asia/Shanghai',
          });
          const requestUrl = new URL(entry.URL);
          const subname = configJson['preferredSub']?.SUBNAME || '';
          const usage = configJson.CF?.Usage;
          const usageLine = usage?.success
            ? `📊 <b>请求用量：</b>${usage.total}/${usage.max} <b>${(((usage.total || 0) / (usage.max || 1)) * 100).toFixed(2)}%</b>\n`
            : '';
          const msg =
            `<b>#${subname} 日志通知</b>\n\n` +
            `📌 <b>类型：</b>#${entry.TYPE}\n` +
            `🌐 <b>IP：</b><code>${entry.IP}</code>\n` +
            `📍 <b>位置：</b>${entry.CC}\n` +
            `🏢 <b>ASN：</b>${entry.ASN}\n` +
            `🔗 <b>域名：</b><code>${requestUrl.host}</code>\n` +
            `🔍 <b>路径：</b><code>${requestUrl.pathname + requestUrl.search}</code>\n` +
            `🤖 <b>UA：</b><code>${entry.UA}</code>\n` +
            `📅 <b>时间：</b>${requestTime}\n` +
            usageLine;

          await fetch(
            `https://api.telegram.org/bot${tgJson.BotToken}/sendMessage?chat_id=${tgJson.ChatID}&parse_mode=HTML&text=${encodeURIComponent(msg)}`,
            {
              method: 'GET',
              headers: {
                Accept: 'text/html,application/xhtml+xml,application/xml;',
                'Accept-Encoding': 'gzip, deflate, br',
                'User-Agent': entry.UA || 'Unknown',
              },
            }
          );
        }
      } catch (error: any) {
        console.error(`tg.json error: ${error.message}`);
      }
    }

    const finalWriteToKV = ['1', 'true'].includes(env.OFF_LOG || '') ? false : writeToKV;
    if (!finalWriteToKV) return;

    let logArray: LogEntry[] = [];
    const existing = await env.KV.get('log.json');
    if (existing) {
      try {
        logArray = JSON.parse(existing);
        if (!Array.isArray(logArray)) {
          logArray = [entry];
        } else if (requestType !== 'Get_SUB') {
          // Dedupe non-subscription requests within last 30 minutes
          const thirtyMinAgo = now.getTime() - 30 * 60 * 1000;
          const dup = logArray.some(
            (l) =>
              l.TYPE !== 'Get_SUB' &&
              l.IP === accessIP &&
              l.URL === request.url &&
              l.UA === entry.UA &&
              l.TIME >= thirtyMinAgo
          );
          if (dup) return;
          logArray.push(entry);
          while (
            JSON.stringify(logArray, null, 2).length > KV_SIZE_LIMIT_MB * 1024 * 1024 &&
            logArray.length > 0
          ) {
            logArray.shift();
          }
        } else {
          logArray.push(entry);
          while (
            JSON.stringify(logArray, null, 2).length > KV_SIZE_LIMIT_MB * 1024 * 1024 &&
            logArray.length > 0
          ) {
            logArray.shift();
          }
        }
      } catch (e) {
        logArray = [entry];
      }
    } else {
      logArray = [entry];
    }
    await env.KV.put('log.json', JSON.stringify(logArray, null, 2));
  } catch (error: any) {
    console.error(`logRequest failed: ${error.message}`);
  }
}
