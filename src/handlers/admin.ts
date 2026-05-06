// /admin/* routes — KV CRUD + status endpoints.
//
// All endpoints require a valid auth cookie (verified by caller).
// Each maps to a single KV key (config.json, cf.json, tg.json, ADD.txt)
// or a metadata endpoint (log.json, getCloudflareUsage, etc.).

import { logRequest } from '../utils/log.js';
import { readConfigJson } from '../admin/config.js';
import { getCloudflareUsage } from '../admin/cloudflare-api.js';
import { generateRandomIPs } from '../admin/random-ip.js';
import { requestPreferredApi } from '../admin/preferred-sub.js';
import { PAGES_STATIC_URL } from '../constants.js';
import type { ProxyContext } from '../state.js';

interface AdminEnv {
  KV: KVNamespace;
  HOST?: string;
  PATH?: string;
  OFF_LOG?: string;
}

const json = (obj: any, status = 200) =>
  new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: { 'Content-Type': 'application/json;charset=utf-8' },
  });

/**
 * Handle a request matching /admin or /admin/*. Caller must have already
 * verified the auth cookie. Returns null if the path didn't match (caller
 * should fall through to default).
 */
export async function handleAdmin(
  ctx: ProxyContext,
  env: AdminEnv,
  request: Request,
  url: URL,
  caseInsensitivePath: string,
  casePreservingPath: string,
  host: string,
  userID: string,
  ua: string,
  accessIP: string,
  workerCtx: { waitUntil: (p: Promise<any>) => void }
): Promise<Response> {
  // Read access log
  if (caseInsensitivePath === 'admin/log.json') {
    const logContent = (await env.KV.get('log.json')) || '[]';
    return new Response(logContent, {
      status: 200,
      headers: { 'Content-Type': 'application/json;charset=utf-8' },
    });
  }

  // Cloudflare usage (case-sensitive path)
  if (casePreservingPath === 'admin/getCloudflareUsage') {
    try {
      const usage = await getCloudflareUsage(
        url.searchParams.get('Email'),
        url.searchParams.get('GlobalAPIKey'),
        url.searchParams.get('AccountID'),
        url.searchParams.get('APIToken')
      );
      return json(usage);
    } catch (err: any) {
      return json({ msg: 'getCloudflareUsage failed: ' + err.message, error: err.message }, 500);
    }
  }

  // Validate preferred-IP API endpoint
  if (casePreservingPath === 'admin/getADDAPI') {
    if (url.searchParams.get('url')) {
      const testUrl = url.searchParams.get('url')!;
      try {
        new URL(testUrl);
        const result = await requestPreferredApi(
          [testUrl],
          url.searchParams.get('port') || '443'
        );
        let apiIPs = result[0].length > 0 ? result[0] : result[1];
        apiIPs = apiIPs.map((item) =>
          item.replace(/#(.+)$/, (_, remark) => '#' + decodeURIComponent(remark))
        );
        return json({ success: true, data: apiIPs });
      } catch (err: any) {
        return json({ msg: 'getADDAPI failed: ' + err.message, error: err.message }, 500);
      }
    }
    return json({ success: false, data: [] }, 403);
  }

  // /admin/check requires direct socket access for proxy testing.
  // Skipped here — UI will display "diagnostic disabled" if missing.
  if (caseInsensitivePath === 'admin/check') {
    return json({ error: 'proxy check not implemented in modular build' }, 501);
  }

  // Load config (most subsequent endpoints need it)
  let config = await readConfigJson(ctx, env, host, userID, ua);

  // Reset config to defaults
  if (caseInsensitivePath === 'admin/init') {
    try {
      config = await readConfigJson(ctx, env, host, userID, ua, true);
      workerCtx.waitUntil(
        logRequest(env, request as any, accessIP, 'Init_Config', config)
      );
      config.init = 'configuration reset to defaults';
      return json(config);
    } catch (err: any) {
      return json({ msg: 'config reset failed: ' + err.message, error: err.message }, 500);
    }
  }

  // POST: KV writes
  if (request.method === 'POST') {
    if (caseInsensitivePath === 'admin/config.json') {
      try {
        const newConfig: any = await request.json();
        if (!newConfig.UUID || !newConfig.HOST) {
          return json({ error: 'incomplete configuration' }, 400);
        }
        await env.KV.put('config.json', JSON.stringify(newConfig, null, 2));
        workerCtx.waitUntil(
          logRequest(env, request as any, accessIP, 'Save_Config', config)
        );
        return json({ success: true, message: 'configuration saved' });
      } catch (error: any) {
        console.error('save config failed:', error);
        return json({ error: 'save config failed: ' + error.message }, 500);
      }
    }

    if (caseInsensitivePath === 'admin/cf.json') {
      try {
        const newConfig: any = await request.json();
        const cfJson: any = {
          Email: null,
          GlobalAPIKey: null,
          AccountID: null,
          APIToken: null,
          UsageAPI: null,
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
            return json({ error: 'incomplete configuration' }, 400);
          }
        }
        await env.KV.put('cf.json', JSON.stringify(cfJson, null, 2));
        workerCtx.waitUntil(
          logRequest(env, request as any, accessIP, 'Save_Config', config)
        );
        return json({ success: true, message: 'configuration saved' });
      } catch (error: any) {
        return json({ error: 'save config failed: ' + error.message }, 500);
      }
    }

    if (caseInsensitivePath === 'admin/tg.json') {
      try {
        const newConfig: any = await request.json();
        if (newConfig.init && newConfig.init === true) {
          const tgJson = { BotToken: null, ChatID: null };
          await env.KV.put('tg.json', JSON.stringify(tgJson, null, 2));
        } else {
          if (!newConfig.BotToken || !newConfig.ChatID) {
            return json({ error: 'incomplete configuration' }, 400);
          }
          await env.KV.put('tg.json', JSON.stringify(newConfig, null, 2));
        }
        workerCtx.waitUntil(
          logRequest(env, request as any, accessIP, 'Save_Config', config)
        );
        return json({ success: true, message: 'configuration saved' });
      } catch (error: any) {
        return json({ error: 'save config failed: ' + error.message }, 500);
      }
    }

    if (casePreservingPath === 'admin/ADD.txt') {
      try {
        const customIPs = await request.text();
        await env.KV.put('ADD.txt', customIPs);
        workerCtx.waitUntil(
          logRequest(env, request as any, accessIP, 'Save_Custom_IPs', config)
        );
        return json({ success: true, message: 'custom IPs saved' });
      } catch (error: any) {
        return json({ error: 'save custom IPs failed: ' + error.message }, 500);
      }
    }

    return json({ error: 'unsupported POST path' }, 404);
  }

  // GET endpoints
  if (caseInsensitivePath === 'admin/config.json') {
    return json(config);
  }
  if (casePreservingPath === 'admin/ADD.txt') {
    let customIPs = (await env.KV.get('ADD.txt')) || 'null';
    if (customIPs == 'null') {
      customIPs = (
        await generateRandomIPs(
          request as any,
          config.preferredSub.localIP.count,
          config.preferredSub.localIP.port,
          config.protocol === 'ss' ? config.SS.TLS : true
        )
      )[1];
    }
    return new Response(customIPs, {
      status: 200,
      headers: {
        'Content-Type': 'text/plain;charset=utf-8',
        asn: String((request as any).cf?.asn || ''),
      },
    });
  }
  if (caseInsensitivePath === 'admin/cf.json') {
    return json((request as any).cf || {});
  }

  // Default: serve admin UI from external CDN
  workerCtx.waitUntil(
    logRequest(env, request as any, accessIP, 'Admin_Login', config)
  );
  return fetch(PAGES_STATIC_URL + '/admin' + url.search) as any;
}
