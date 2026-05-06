// Helpers for converting subscription-config "transport" choices into
// the field names / values that go into VLESS / Trojan URIs.

import { randomPath } from '../utils/path.js';

export interface TransportConfig {
  transport?: 'ws' | 'grpc' | 'xhttp';
  grpcMode?: 'multi' | 'gun';
  randomPath?: boolean;
}

export interface ResolvedTransportConfig {
  /** Transport string suitable for inclusion in proxy URI ?type=... */
  type: string;
  /** Field name for the path/serviceName: 'path' for WS, 'serviceName' for gRPC */
  pathField: string;
  /** Field name for the host header: 'host' for WS, 'authority' for gRPC */
  hostField: string;
}

/**
 * Translate transport-config keys into the URI field names used by
 * the subscription generator.
 */
export function getTransportConfig(config: TransportConfig = {}): ResolvedTransportConfig {
  const isGrpc = config.transport === 'grpc';
  return {
    type: isGrpc
      ? config.grpcMode === 'multi'
        ? 'grpc&mode=multi'
        : 'grpc&mode=gun'
      : config.transport === 'xhttp'
        ? 'xhttp&mode=stream-one'
        : 'ws',
    pathField: isGrpc ? 'serviceName' : 'path',
    hostField: isGrpc ? 'authority' : 'host',
  };
}

/**
 * Apply random path-prefix randomisation to a node path if configured.
 * For gRPC, strips any query string from the path (gRPC service names
 * don't take ?query parameters).
 */
export function getTransportPath(
  config: TransportConfig = {},
  nodePath: string = '/',
  asPreferredSubGenerator: boolean = false
): string {
  const pathValue = asPreferredSubGenerator
    ? '/'
    : config.randomPath
      ? randomPath(nodePath)
      : nodePath;
  if (config.transport !== 'grpc') return pathValue;
  return pathValue.split('?')[0] || '/';
}
