import { describe, it, expect } from 'vitest';
import { getTransportConfig, getTransportPath } from '../../src/admin/transport.js';

describe('getTransportConfig', () => {
  it('defaults to WebSocket when no transport specified', () => {
    const result = getTransportConfig({});
    expect(result.type).toBe('ws');
    expect(result.pathField).toBe('path');
    expect(result.hostField).toBe('host');
  });

  it('handles gRPC with multi mode', () => {
    const result = getTransportConfig({ transport: 'grpc', grpcMode: 'multi' });
    expect(result.type).toBe('grpc&mode=multi');
    expect(result.pathField).toBe('serviceName');
    expect(result.hostField).toBe('authority');
  });

  it('handles gRPC with gun mode (default)', () => {
    const result = getTransportConfig({ transport: 'grpc' });
    expect(result.type).toBe('grpc&mode=gun');
    expect(result.pathField).toBe('serviceName');
  });

  it('handles XHTTP', () => {
    const result = getTransportConfig({ transport: 'xhttp' });
    expect(result.type).toBe('xhttp&mode=stream-one');
    expect(result.pathField).toBe('path');
  });
});

describe('getTransportPath', () => {
  it('returns "/" for preferred sub generator mode', () => {
    expect(getTransportPath({ randomPath: true }, '/path', true)).toBe('/');
  });

  it('returns nodePath as-is when randomPath is disabled', () => {
    expect(getTransportPath({ randomPath: false }, '/proxy?abc')).toBe('/proxy?abc');
  });

  it('strips query string for gRPC', () => {
    expect(getTransportPath({ transport: 'grpc' }, '/svc?ignored')).toBe('/svc');
  });

  it('returns "/" for gRPC if path is empty', () => {
    expect(getTransportPath({ transport: 'grpc' }, '')).toBe('/');
  });

  it('keeps query string for non-gRPC', () => {
    expect(getTransportPath({}, '/proxy?token=abc')).toBe('/proxy?token=abc');
  });
});
