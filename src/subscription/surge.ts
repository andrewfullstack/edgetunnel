// Surge subscription post-processor.
//
// Prepends the #!MANAGED-CONFIG header so Surge clients know the
// subscription URL + auto-update interval.
//
// (A previous version also injected ws=true / ws-path for Trojan lines
// — that branch was removed when we dropped Trojan support, since the
// upstream subconverter is now only fed VLESS input.)

interface SurgeConfig {
  'preferredSub'?: { SUBUpdateTime?: number };
}

/**
 * Patch a Surge subscription file by prepending the
 * `#!MANAGED-CONFIG ... interval=N strict=false` header.
 */
export function patchSurgeSubscription(
  content: string,
  url: string,
  config: SurgeConfig
): string {
  const updateHours = config['preferredSub']?.SUBUpdateTime ?? 6;
  const firstNewline = content.indexOf('\n');
  const tail = firstNewline >= 0 ? content.substring(firstNewline) : '\n' + content;
  return `#!MANAGED-CONFIG ${url} interval=${updateHours * 60 * 60} strict=false${tail}`;
}
