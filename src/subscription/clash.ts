// Clash subscription post-processor.
//
// Patches a Clash YAML subscription file:
//   - Normalises mode (Rule → rule)
//   - Adds standard DNS block if absent
//   - Configures ECH (Encrypted Client Hello) options on matching nodes
//   - Sets gRPC User-Agent on gRPC nodes
//
// The Clash YAML can use either flow style (`- {type: vless, ...}`) or
// block style (`- name: ...\n  type: vless\n  ...`); both are handled.
//
// Note: this preserves the original config_JSON schema field names
// (which are Chinese strings like "transport") since they're part of the
// on-disk config format.

interface ClashConfig {
  UUID?: string;
  ECH?: boolean;
  HOSTS?: string[];
  ECHConfig?: { SNI?: string; DNS?: string };
  transport?: string;
  gRPCUserAgent?: string;
}

const BASE_DNS_BLOCK = `dns:
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

/**
 * Patch a Clash YAML subscription. Returns the modified YAML.
 */
export function patchClashSubscription(originalYaml: string, config: ClashConfig = {}): string {
  const uuid = config?.UUID || null;
  const echEnabled = Boolean(config?.ECH);
  const hosts = Array.isArray(config?.HOSTS) ? [...(config.HOSTS as string[])] : [];
  const echSni = config?.ECHConfig?.SNI || null;
  const echDns = config?.ECHConfig?.DNS;
  const needEch = Boolean(uuid && echEnabled);
  const grpcUserAgent =
    typeof config?.gRPCUserAgent === 'string' && config.gRPCUserAgent.trim()
      ? config.gRPCUserAgent.trim()
      : null;
  const needGrpc = config?.transport === 'grpc' && Boolean(grpcUserAgent);
  const grpcUserAgentYaml = grpcUserAgent ? JSON.stringify(grpcUserAgent) : null;

  let yaml = originalYaml.replace(/mode:\s*Rule\b/g, 'mode: rule');

  // Helper: add grpc-user-agent to inline-style grpc-opts: {…}
  const addInlineGrpcUserAgent = (text: string): string =>
    text.replace(/grpc-opts:\s*\{([\s\S]*?)\}/i, (all, inner) => {
      if (/grpc-user-agent\s*:/i.test(inner)) return all;
      let content = inner.trim();
      if (content.endsWith(',')) content = content.slice(0, -1).trim();
      const patched = content
        ? `${content}, grpc-user-agent: ${grpcUserAgentYaml}`
        : `grpc-user-agent: ${grpcUserAgentYaml}`;
      return `grpc-opts: {${patched}}`;
    });

  const matchesGrpcNetwork = (text: string): boolean =>
    /(?:^|[,{])\s*network:\s*(?:"grpc"|'grpc'|grpc)(?=\s*(?:[,}\n#]|$))/im.test(text);

  const getNodeType = (nodeText: string): string =>
    nodeText.match(/type:\s*(\w+)/)?.[1] || 'vl' + 'ess';

  const getCredentialValue = (nodeText: string, isFlowStyle: boolean): string | null => {
    const credentialField = getNodeType(nodeText) === 'trojan' ? 'password' : 'uuid';
    const pattern = new RegExp(
      `${credentialField}:\\s*${isFlowStyle ? '([^,}\\n]+)' : '([^\\n]+)'}`
    );
    return nodeText.match(pattern)?.[1]?.trim() || null;
  };

  const insertNameserverPolicy = (yamlIn: string, hostsEntries: string): string => {
    if (/^\s{2}nameserver-policy:\s*(?:\n|$)/m.test(yamlIn)) {
      return yamlIn.replace(
        /^(\s{2}nameserver-policy:\s*\n)/m,
        `$1${hostsEntries}\n`
      );
    }
    const lines = yamlIn.split('\n');
    let dnsBlockEndIndex = -1;
    let inDnsBlock = false;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (/^dns:\s*$/.test(line)) {
        inDnsBlock = true;
        continue;
      }
      if (inDnsBlock && /^[a-zA-Z]/.test(line)) {
        dnsBlockEndIndex = i;
        break;
      }
    }
    const block = `  nameserver-policy:\n${hostsEntries}`;
    if (dnsBlockEndIndex !== -1) lines.splice(dnsBlockEndIndex, 0, block);
    else lines.push(block);
    return lines.join('\n');
  };

  const addFlowGrpcUserAgent = (nodeText: string): string => {
    if (!matchesGrpcNetwork(nodeText) || /grpc-user-agent\s*:/i.test(nodeText)) return nodeText;
    if (/grpc-opts:\s*\{/i.test(nodeText)) return addInlineGrpcUserAgent(nodeText);
    return nodeText.replace(
      /\}(\s*)$/,
      `, grpc-opts: {grpc-user-agent: ${grpcUserAgentYaml}}}$1`
    );
  };

  const addBlockGrpcUserAgent = (nodeLines: string[], topLevelIndent: number): string[] => {
    const topIndent = ' '.repeat(topLevelIndent);
    let grpcOptsIndex = -1;
    for (let idx = 0; idx < nodeLines.length; idx++) {
      const line = nodeLines[idx];
      if (!line.trim()) continue;
      const indent = line.search(/\S/);
      if (indent !== topLevelIndent) continue;
      if (
        /^\s*grpc-opts:\s*(?:#.*)?$/.test(line) ||
        /^\s*grpc-opts:\s*\{.*\}\s*(?:#.*)?$/.test(line)
      ) {
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
        `${' '.repeat(childIndent)}grpc-user-agent: ${grpcUserAgentYaml}`
      );
    }
    return nodeLines;
  };

  const addBlockEchOpts = (nodeLines: string[], topLevelIndent: number): string[] => {
    let insertIndex = -1;
    for (let j = nodeLines.length - 1; j >= 0; j--) {
      if (nodeLines[j].trim()) {
        insertIndex = j;
        break;
      }
    }
    if (insertIndex < 0) return nodeLines;
    const indent = ' '.repeat(topLevelIndent);
    const echLines = [`${indent}ech-opts:`, `${indent}  enable: true`];
    if (echSni) echLines.push(`${indent}  query-server-name: ${echSni}`);
    nodeLines.splice(insertIndex + 1, 0, ...echLines);
    return nodeLines;
  };

  // Inject DNS block if absent
  if (!/^dns:\s*(?:\n|$)/m.test(yaml)) yaml = BASE_DNS_BLOCK + yaml;
  if (echSni && !hosts.includes(echSni)) hosts.push(echSni);

  if (echEnabled && hosts.length > 0) {
    const hostsEntries = hosts.map((h) => `    "${h}": ${echDns ? echDns : ''}`).join('\n');
    yaml = insertNameserverPolicy(yaml, hostsEntries);
  }

  if (!needEch && !needGrpc) return yaml;

  const lines = yaml.split('\n');
  const processed: string[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.trim();

    if (trimmed.startsWith('- {')) {
      // Flow-style node: collect until braces balance
      let fullNode = line;
      let braceCount = (line.match(/\{/g) || []).length - (line.match(/\}/g) || []).length;
      while (braceCount > 0 && i + 1 < lines.length) {
        i++;
        fullNode += '\n' + lines[i];
        braceCount +=
          (lines[i].match(/\{/g) || []).length - (lines[i].match(/\}/g) || []).length;
      }
      if (needGrpc) fullNode = addFlowGrpcUserAgent(fullNode);
      if (needEch && getCredentialValue(fullNode, true) === uuid!.trim()) {
        fullNode = fullNode.replace(
          /\}(\s*)$/,
          `, ech-opts: {enable: true${echSni ? `, query-server-name: ${echSni}` : ''}}}$1`
        );
      }
      processed.push(fullNode);
      i++;
    } else if (trimmed.startsWith('- name:')) {
      // Block-style node: collect lines until the next sibling
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
        if (nextIndent <= baseIndent && nextTrimmed.startsWith('- ')) break;
        if (nextIndent < baseIndent && nextTrimmed) break;
        nodeLines.push(nextLine);
        i++;
      }
      let nodeText = nodeLines.join('\n');
      if (needGrpc && matchesGrpcNetwork(nodeText)) {
        nodeLines = addBlockGrpcUserAgent(nodeLines, topLevelIndent);
        nodeText = nodeLines.join('\n');
      }
      if (needEch && getCredentialValue(nodeText, false) === uuid!.trim()) {
        nodeLines = addBlockEchOpts(nodeLines, topLevelIndent);
      }
      processed.push(...nodeLines);
    } else {
      processed.push(line);
      i++;
    }
  }

  return processed.join('\n');
}
