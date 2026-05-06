// /sub subscription generator.
//
// Auto-detects the client format (Clash, Sing-box, Surge, Loon, QuantumultX,
// or raw mixed) and returns the corresponding subscription. Validates the
// `?token=` parameter against MD5MD5(host + userID).

import { md5x2 } from '../crypto/md5.js';
import { toArray } from '../utils/url.js';
import { randomPath, replaceAsterisks, bulkReplaceDomains } from '../utils/path.js';
import { logRequest } from '../utils/log.js';
import { readConfigJson } from '../admin/config.js';
import { getTransportConfig, getTransportPath } from '../admin/transport.js';
import { generateRandomIPs } from '../admin/random-ip.js';
import {
  fetchPreferredSubData,
  requestPreferredApi,
} from '../admin/preferred-sub.js';
import { patchClashSubscription } from '../subscription/clash.js';
import { patchSingboxSubscription } from '../subscription/singbox.js';
import { patchSurgeSubscription } from '../subscription/surge.js';
import type { ProxyContext } from '../state.js';

interface SubEnv {
  KV: KVNamespace;
  HOST?: string;
  PATH?: string;
  BEST_SUB?: string;
  OFF_LOG?: string;
}

const PLACEHOLDER_UUID = '00000000-0000-4000-8000-000000000000';
const EXPIRE = 4102329600; // 2099-12-31

/**
 * Handle a `/sub?token=…` subscription request.
 * Returns 404 (caller should fall through) if the token is invalid.
 */
export async function handleSubscription(
  ctx: ProxyContext,
  env: SubEnv,
  request: Request,
  url: URL,
  host: string,
  userID: string,
  ua: string,
  accessIP: string,
  workerCtx: { waitUntil: (p: Promise<any>) => void }
): Promise<Response | null> {
  const subToken = await md5x2(host + userID);
  const asPreferredSubGenerator =
    ['1', 'true'].includes(env.BEST_SUB || '') &&
    url.searchParams.get('host') === 'example.com' &&
    url.searchParams.get('uuid') === PLACEHOLDER_UUID &&
    ua.toLowerCase().includes('tunnel (https://github.com/cmliu/edge');

  if (url.searchParams.get('token') !== subToken && !asPreferredSubGenerator) {
    return null;
  }

  const config = await readConfigJson(ctx, env, host, userID, ua);
  if (asPreferredSubGenerator) {
    workerCtx.waitUntil(
      logRequest(env, request as any, accessIP, 'Get_Best_SUB', config, false)
    );
  } else {
    workerCtx.waitUntil(logRequest(env, request as any, accessIP, 'Get_SUB', config));
  }

  const uaLower = ua.toLowerCase();
  const now = Date.now();
  const today = new Date(now);
  today.setHours(0, 0, 0, 0);
  const UD = Math.floor(((now - today.getTime()) / 86400000) * 24 * 1099511627776 / 2);
  let pagesSum = UD;
  let workersSum = UD;
  let total = 24 * 1099511627776;
  if (config.CF.Usage.success) {
    pagesSum = config.CF.Usage.pages;
    workersSum = config.CF.Usage.workers;
    total = Number.isFinite(config.CF.Usage.max)
      ? (config.CF.Usage.max / 1000) * 1024
      : 1024 * 100;
  }

  const responseHeaders: Record<string, string> = {
    'content-type': 'text/plain; charset=utf-8',
    'Profile-Update-Interval': String(config.preferredSub.SUBUpdateTime),
    'Profile-web-page-url': url.protocol + '//' + url.host + '/admin',
    'Subscription-Userinfo': `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${EXPIRE}`,
    'Cache-Control': 'no-store',
  };

  const isSubConverterRequest =
    url.searchParams.has('b64') ||
    url.searchParams.has('base64') ||
    !!request.headers.get('subconverter-request') ||
    !!request.headers.get('subconverter-version') ||
    uaLower.includes('subconverter') ||
    uaLower.includes(('CF-Workers-SUB').toLowerCase()) ||
    asPreferredSubGenerator;

  const subType = isSubConverterRequest
    ? 'mixed'
    : url.searchParams.has('target')
      ? url.searchParams.get('target')!
      : url.searchParams.has('clash') || uaLower.includes('clash') || uaLower.includes('meta') || uaLower.includes('mihomo')
        ? 'clash'
        : url.searchParams.has('sb') || url.searchParams.has('singbox') || uaLower.includes('singbox') || uaLower.includes('sing-box')
          ? 'singbox'
          : url.searchParams.has('surge') || uaLower.includes('surge')
            ? 'surge&ver=4'
            : url.searchParams.has('quanx') || uaLower.includes('quantumult')
              ? 'quanx'
              : url.searchParams.has('loon') || uaLower.includes('loon')
                ? 'loon'
                : 'mixed';

  if (!uaLower.includes('mozilla')) {
    responseHeaders['Content-Disposition'] = `attachment; filename*=utf-8''${encodeURIComponent(
      config.preferredSub.SUBNAME
    )}`;
  }

  const protoType = config.protocol;

  let subContent = '';

  if (subType === 'mixed') {
    const tlsFragmentParam =
      config.tlsFragment == 'Shadowrocket'
        ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}`
        : config.tlsFragment == 'Happ'
          ? `&fragment=${encodeURIComponent('3,1,tlshello')}`
          : '';
    let fullPreferredIPs: string[] = [];
    let otherNodeLinks = '';
    let proxyIPPool: string[] = [];

    if (!url.searchParams.has('sub') && config.preferredSub.local) {
      // Local subscription generation
      const fullList: string[] = config.preferredSub.localIP.randomIP
        ? (
            await generateRandomIPs(
              request as any,
              config.preferredSub.localIP.count,
              config.preferredSub.localIP.port,
              true
            )
          )[0]
        : (await env.KV.get('ADD.txt'))
          ? toArray(await env.KV.get('ADD.txt') || '')
          : (
              await generateRandomIPs(
                request as any,
                config.preferredSub.localIP.count,
                config.preferredSub.localIP.port,
                true
              )
            )[0];

      const apiList: string[] = [];
      const ipList: string[] = [];
      const otherNodes: string[] = [];

      for (const item of fullList) {
        if (item.toLowerCase().startsWith('sub://')) {
          apiList.push(item);
        } else {
          const subMatch = item.match(/sub\s*=\s*([^\s&#]+)/i);
          if (subMatch && subMatch[1].trim().includes('.')) {
            const asProxyIP = item.toLowerCase().includes('proxyip=true');
            if (asProxyIP) {
              apiList.push(
                'sub://' +
                  subMatch[1].trim() +
                  '?proxyip=true' +
                  (item.includes('#') ? '#' + item.split('#')[1] : '')
              );
            } else {
              apiList.push(
                'sub://' +
                  subMatch[1].trim() +
                  (item.includes('#') ? '#' + item.split('#')[1] : '')
              );
            }
          } else if (item.toLowerCase().startsWith('https://')) {
            apiList.push(item);
          } else if (item.toLowerCase().includes('://')) {
            if (item.includes('#')) {
              const [addr, remark] = item.split('#');
              otherNodes.push(addr + '#' + encodeURIComponent(decodeURIComponent(remark)));
            } else {
              otherNodes.push(item);
            }
          } else {
            const hashIdx = item.indexOf('#');
            const addrPart = hashIdx > -1 ? item.slice(0, hashIdx) : item;
            if (addrPart.includes('*')) {
              const remarkPart = hashIdx > -1 ? item.slice(hashIdx) : '';
              ipList.push(replaceAsterisks(addrPart) + remarkPart);
            } else {
              ipList.push(item);
            }
          }
        }
      }

      const apiResult = await requestPreferredApi(apiList, '443');
      const mergedOtherNodes = [...new Set(otherNodes.concat(apiResult[1]))];
      otherNodeLinks =
        mergedOtherNodes.length > 0 ? mergedOtherNodes.join('\n') + '\n' : '';
      const apiIPs = apiResult[0];
      proxyIPPool = apiResult[3] || [];
      fullPreferredIPs = [...new Set(ipList.concat(apiIPs))];
    } else {
      // Use external subscription generator
      const generatorHost = url.searchParams.get('sub') || config.preferredSub.SUB;
      const [genIPs, genOtherNodes] = await fetchPreferredSubData(generatorHost);
      fullPreferredIPs = fullPreferredIPs.concat(genIPs);
      otherNodeLinks += genOtherNodes;
    }

    const echLinkParam = config.ECH
      ? `&ech=${encodeURIComponent(
          (config.ECHConfig.SNI ? config.ECHConfig.SNI + '+' : '') + config.ECHConfig.DNS
        )}`
      : '';
    const isLoonOrSurge = uaLower.includes('loon') || uaLower.includes('surge');
    const { type: transportProto, pathField: pathField, hostField: hostField } =
      getTransportConfig(config);

    subContent =
      otherNodeLinks +
      fullPreferredIPs
        .map((rawAddr) => {
          const regex =
            /^(\[[\da-fA-F:]+\]|[\d.]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(?::(\d+))?(?:#(.+))?$/;
          const match = rawAddr.match(regex);
          let nodeAddr: string;
          let nodePort = '443';
          let nodeRemark: string;

          if (match) {
            nodeAddr = match[1];
            nodePort = match[2] || '443';
            nodeRemark = match[3] || nodeAddr;
          } else {
            console.warn(`[sub] invalid format ignored: ${rawAddr}`);
            return null;
          }

          let fullPath: string = config.fullNodePath;
          if (proxyIPPool.length > 0) {
            const matchedProxy = proxyIPPool.find((p) => p.includes(nodeAddr));
            if (matchedProxy) {
              fullPath =
                `${config.PATH}/proxyip=${matchedProxy}`.replace(/\/\//g, '/') +
                (config.enable0RTT ? '?ed=2560' : '');
            }
          }
          if (isLoonOrSurge) fullPath = fullPath.replace(/,/g, '%2C');

          const transportPathValue = getTransportPath(
            config,
            fullPath,
            asPreferredSubGenerator
          );
          return `${protoType}://${PLACEHOLDER_UUID}@${nodeAddr}:${nodePort}?security=tls&type=${transportProto + echLinkParam}&${hostField}=example.com&fp=${config.Fingerprint}&sni=example.com&${pathField}=${
            encodeURIComponent(transportPathValue) + tlsFragmentParam
          }&encryption=none${
            config.skipCertVerify ? '&insecure=1&allowInsecure=1' : ''
          }#${encodeURIComponent(nodeRemark)}`;
        })
        .filter((item) => item !== null)
        .join('\n');
  } else {
    // External subconverter
    const subConvertURL = `${config.subConverter.SUBAPI}/sub?target=${subType}&url=${encodeURIComponent(
      url.protocol +
        '//' +
        url.host +
        '/sub?target=mixed&token=' +
        subToken +
        (url.searchParams.has('sub') && url.searchParams.get('sub') != ''
          ? `&sub=${url.searchParams.get('sub')}`
          : '')
    )}&config=${encodeURIComponent(config.subConverter.SUBCONFIG)}&emoji=${config.subConverter.SUBEMOJI}&scv=${config.skipCertVerify}`;
    try {
      const response = await fetch(subConvertURL, {
        headers: {
          'User-Agent':
            'Subconverter for ' + subType + ' edge' + 'tunnel (https://github.com/cmliu/edge' + 'tunnel)',
        },
      });
      if (response.ok) {
        subContent = await response.text();
        if (url.searchParams.has('surge') || uaLower.includes('surge')) {
          subContent = patchSurgeSubscription(
            subContent,
            url.protocol + '//' + url.host + '/sub?token=' + subToken + '&surge',
            config
          );
        }
      } else {
        return new Response('Subconverter backend error: ' + response.statusText, {
          status: response.status,
        });
      }
    } catch (error: any) {
      return new Response('Subconverter backend error: ' + error.message, {
        status: 403,
      });
    }
  }

  if (!uaLower.includes('subconverter') && !asPreferredSubGenerator) {
    subContent = bulkReplaceDomains(
      subContent
        .replace(/00000000-0000-4000-8000-000000000000/g, config.UUID)
        .replace(/MDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDAw/g, btoa(config.UUID)),
      config.HOSTS
    );
  }

  if (
    subType === 'mixed' &&
    (!uaLower.includes('mozilla') ||
      url.searchParams.has('b64') ||
      url.searchParams.has('base64'))
  ) {
    subContent = btoa(subContent);
  }

  if (subType === 'singbox') {
    subContent = await patchSingboxSubscription(subContent, config);
    responseHeaders['content-type'] = 'application/json; charset=utf-8';
  } else if (subType === 'clash') {
    subContent = patchClashSubscription(subContent, config);
    responseHeaders['content-type'] = 'application/x-yaml; charset=utf-8';
  }

  return new Response(subContent, { status: 200, headers: responseHeaders });
}
