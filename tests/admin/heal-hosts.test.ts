import { describe, it, expect } from 'vitest';
import { healHostsForRedeploy } from '../../src/admin/config.js';

describe('healHostsForRedeploy', () => {
  it('drops stale Pages preview hash and keeps current hostname', () => {
    // The bug: redeploying under a new Pages hash leaves the OLD hash in KV.
    // Sub generation then bakes a dead SNI into every VLESS node.
    const hosts = ['5fba32b2.mykv2-3yj.pages.dev'];
    expect(healHostsForRedeploy(hosts, '52e0ea14.mykv2-3yj.pages.dev'))
      .toEqual(['52e0ea14.mykv2-3yj.pages.dev']);
  });

  it('passes through when current host already matches', () => {
    expect(healHostsForRedeploy(
      ['52e0ea14.mykv2-3yj.pages.dev'],
      '52e0ea14.mykv2-3yj.pages.dev',
    )).toEqual(['52e0ea14.mykv2-3yj.pages.dev']);
  });

  it('preserves user-configured custom domains and prepends current hostname', () => {
    expect(healHostsForRedeploy(
      ['mycustom.com', 'edge.mycustom.com'],
      '52e0ea14.mykv2-3yj.pages.dev',
    )).toEqual(['52e0ea14.mykv2-3yj.pages.dev', 'mycustom.com', 'edge.mycustom.com']);
  });

  it('drops a stale Pages hash but keeps a custom domain', () => {
    expect(healHostsForRedeploy(
      ['old-hash.example.pages.dev', 'mycustom.com'],
      'new-hash.example.pages.dev',
    )).toEqual(['new-hash.example.pages.dev', 'mycustom.com']);
  });

  it('keeps the current pages.dev when it matches one of multiple pages.dev entries', () => {
    expect(healHostsForRedeploy(
      ['stale.foo.pages.dev', 'live.foo.pages.dev'],
      'live.foo.pages.dev',
    )).toEqual(['live.foo.pages.dev']);
  });

  it('handles non-array input', () => {
    expect(healHostsForRedeploy(null, 'a.pages.dev')).toEqual(['a.pages.dev']);
    expect(healHostsForRedeploy(undefined, 'a.pages.dev')).toEqual(['a.pages.dev']);
    expect(healHostsForRedeploy('not-an-array', 'a.pages.dev')).toEqual(['a.pages.dev']);
  });

  it('skips non-string entries', () => {
    expect(healHostsForRedeploy(
      [null, 42, 'mycustom.com', { junk: true }],
      'a.pages.dev',
    )).toEqual(['a.pages.dev', 'mycustom.com']);
  });

  it('preserves order of non-stale entries', () => {
    expect(healHostsForRedeploy(
      ['b.com', 'a.com', 'c.com'],
      'live.pages.dev',
    )).toEqual(['live.pages.dev', 'b.com', 'a.com', 'c.com']);
  });

  it('case-insensitive on the .pages.dev suffix', () => {
    expect(healHostsForRedeploy(
      ['STALE.PAGES.DEV', 'mycustom.com'],
      'new.pages.dev',
    )).toEqual(['new.pages.dev', 'mycustom.com']);
  });
});
