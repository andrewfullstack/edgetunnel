// Surge subscription post-processor.
//
// Surge has a quirk where Trojan with WebSocket transport requires
// explicit `ws=true, ws-path=..., ws-headers=Host:"..."` parameters
// that the upstream subconverter doesn't add. This patch injects them.

import { randomPath } from '../utils/path.js';

interface SurgeConfig {
  randomPath?: boolean;
  fullNodePath?: string;
  skipCertVerify?: boolean;
  'preferredSub'?: { SUBUpdateTime?: number };
}

/**
 * Patch a Surge subscription file:
 *   - Inject `ws=true, ws-path=..., ws-headers=Host:"..."` for Trojan lines
 *   - Prepend the #!MANAGED-CONFIG header with subscription URL + update interval
 */
export function patchSurgeSubscription(
  content: string,
  url: string,
  config: SurgeConfig
): string {
  const lines = content.includes('\r\n') ? content.split('\r\n') : content.split('\n');
  const fullPath = config.randomPath
    ? randomPath(config.fullNodePath || '/')
    : config.fullNodePath || '/';

  let output = '';
  for (const x of lines) {
    if (x.includes('= tro' + 'jan,') && !x.includes('ws=true') && !x.includes('ws-path=')) {
      const host = x.split('sni=')[1].split(',')[0];
      const orig = `sni=${host}, skip-cert-verify=${config.skipCertVerify}`;
      const fixed =
        `sni=${host}, skip-cert-verify=${config.skipCertVerify}, ` +
        `ws=true, ws-path=${fullPath.replace(/,/g, '%2C')}, ws-headers=Host:"${host}"`;
      output += x.replace(new RegExp(orig, 'g'), fixed).replace('[', '').replace(']', '') + '\n';
    } else {
      output += x + '\n';
    }
  }

  const updateHours = config['preferredSub']?.SUBUpdateTime ?? 6;
  output =
    `#!MANAGED-CONFIG ${url} interval=${updateHours * 60 * 60} strict=false` +
    output.substring(output.indexOf('\n'));
  return output;
}
