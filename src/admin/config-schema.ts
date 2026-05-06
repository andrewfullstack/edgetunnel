// KV config validator.
//
// Runs after the Chinese→English migration in `readConfigJson` and before
// the defaulting pass. Coerces wrong-type fields to known-good defaults and
// reports each issue. Never throws — bad config produces warnings, not 500s.
//
// Why hand-rolled instead of zod: the schema is small (a dozen field types),
// zod adds ~10KB to the bundle, and we want soft-coercion semantics (replace
// the bad value, keep going) which is awkward with zod's parse-or-throw model.

const PROTOCOLS = ['vless', 'trojan', 'ss'] as const;
const TRANSPORTS = ['ws', 'xhttp', 'grpc'] as const;
const GRPC_MODES = ['gun', 'multi'] as const;
const TLS_FRAGMENTS = ['Shadowrocket', 'Happ'] as const;

export interface ValidationIssue {
  /** Dot-path of the offending field, '' for the root. */
  path: string;
  /** Human-readable explanation including the rejected value and replacement. */
  message: string;
}

export interface ValidationResult {
  /** The (possibly mutated) config. May be the same object as the input. */
  config: any;
  /** All issues encountered. Empty when the input was clean. */
  issues: ValidationIssue[];
}

/** Friendly stringification for an unknown value, used in error messages. */
function describe(value: any): string {
  if (value === null) return 'null';
  if (value === undefined) return 'undefined';
  if (Array.isArray(value)) return `array(length=${value.length})`;
  if (typeof value === 'object') return 'object';
  if (typeof value === 'string') return `string ${JSON.stringify(value)}`;
  return `${typeof value} ${String(value)}`;
}

/**
 * Validate a parsed/migrated config object. Mutates the input — bad fields
 * are replaced with the documented defaults, and an issue is recorded for
 * each replacement. Returns the same reference plus the issues list.
 *
 * Only validates fields whose wrong type would crash a downstream handler.
 * Cosmetic fields (timestamps, user-agent strings, sub-converter URLs) are
 * left alone — admin UI handles their own input validation.
 */
export function validateConfig(input: any): ValidationResult {
  const issues: ValidationIssue[] = [];

  // Root must be a plain object, otherwise we can't repair anything.
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    issues.push({
      path: '',
      message: `expected object at root, got ${describe(input)} — replaced with empty config`,
    });
    return { config: {}, issues };
  }

  const c = input;

  const enumField = <T extends string>(
    parent: any,
    key: string,
    allowed: readonly T[],
    deflt: T,
    path: string
  ) => {
    if (parent[key] === undefined || parent[key] === null) return;
    if (typeof parent[key] !== 'string' || !(allowed as readonly string[]).includes(parent[key])) {
      issues.push({
        path,
        message: `expected one of [${allowed.join(', ')}], got ${describe(parent[key])} — replaced with '${deflt}'`,
      });
      parent[key] = deflt;
    }
  };

  const boolField = (parent: any, key: string, deflt: boolean, path: string) => {
    if (parent[key] === undefined || parent[key] === null) return;
    if (typeof parent[key] !== 'boolean') {
      issues.push({
        path,
        message: `expected boolean, got ${describe(parent[key])} — replaced with ${deflt}`,
      });
      parent[key] = deflt;
    }
  };

  const intField = (
    parent: any,
    key: string,
    min: number,
    max: number,
    deflt: number,
    path: string
  ) => {
    if (parent[key] === undefined || parent[key] === null) return;
    const v = parent[key];
    if (typeof v !== 'number' || !Number.isInteger(v) || v < min || v > max) {
      issues.push({
        path,
        message: `expected integer in [${min}, ${max}], got ${describe(v)} — replaced with ${deflt}`,
      });
      parent[key] = deflt;
    }
  };

  const stringField = (parent: any, key: string, deflt: string, path: string) => {
    if (parent[key] === undefined || parent[key] === null) return;
    if (typeof parent[key] !== 'string') {
      issues.push({
        path,
        message: `expected string, got ${describe(parent[key])} — replaced with '${deflt}'`,
      });
      parent[key] = deflt;
    }
  };

  const stringArrayField = (parent: any, key: string, deflt: string[], path: string) => {
    if (parent[key] === undefined || parent[key] === null) return;
    if (!Array.isArray(parent[key]) || !parent[key].every((x: any) => typeof x === 'string')) {
      issues.push({
        path,
        message: `expected string[], got ${describe(parent[key])} — replaced with [${deflt.join(', ')}]`,
      });
      parent[key] = deflt.slice();
    }
  };

  // ─── Top-level fields ────────────────────────────────────────────
  enumField(c, 'protocol', PROTOCOLS, 'vless', 'protocol');
  enumField(c, 'transport', TRANSPORTS, 'ws', 'transport');
  enumField(c, 'grpcMode', GRPC_MODES, 'gun', 'grpcMode');
  boolField(c, 'enable0RTT', false, 'enable0RTT');
  boolField(c, 'randomPath', false, 'randomPath');
  boolField(c, 'skipCertVerify', false, 'skipCertVerify');
  boolField(c, 'ECH', false, 'ECH');
  stringField(c, 'PATH', '/', 'PATH');
  stringField(c, 'Fingerprint', 'chrome', 'Fingerprint');
  stringArrayField(c, 'HOSTS', [], 'HOSTS');

  // tlsFragment: enum or null (null is the "off" state)
  if (c.tlsFragment !== undefined && c.tlsFragment !== null) {
    if (
      typeof c.tlsFragment !== 'string' ||
      !(TLS_FRAGMENTS as readonly string[]).includes(c.tlsFragment)
    ) {
      issues.push({
        path: 'tlsFragment',
        message: `expected one of [${TLS_FRAGMENTS.join(', ')}] or null, got ${describe(c.tlsFragment)} — replaced with null`,
      });
      c.tlsFragment = null;
    }
  }

  // ─── SS sub-object ───────────────────────────────────────────────
  if (c.SS !== undefined && c.SS !== null) {
    if (typeof c.SS !== 'object' || Array.isArray(c.SS)) {
      issues.push({
        path: 'SS',
        message: `expected object, got ${describe(c.SS)} — replaced with default`,
      });
      c.SS = { cipher: 'aes-128-gcm', TLS: true };
    } else {
      boolField(c.SS, 'TLS', true, 'SS.TLS');
      stringField(c.SS, 'cipher', 'aes-128-gcm', 'SS.cipher');
    }
  }

  // ─── preferredSub sub-object ─────────────────────────────────────
  if (c.preferredSub !== undefined && c.preferredSub !== null) {
    if (typeof c.preferredSub !== 'object' || Array.isArray(c.preferredSub)) {
      issues.push({
        path: 'preferredSub',
        message: `expected object, got ${describe(c.preferredSub)} — sub-object not validated`,
      });
    } else {
      const ps = c.preferredSub;
      boolField(ps, 'local', true, 'preferredSub.local');
      intField(ps, 'SUBUpdateTime', 1, 24 * 30, 3, 'preferredSub.SUBUpdateTime');
      stringField(ps, 'SUBNAME', 'edgetunnel', 'preferredSub.SUBNAME');

      if (ps.localIP !== undefined && ps.localIP !== null) {
        if (typeof ps.localIP !== 'object' || Array.isArray(ps.localIP)) {
          issues.push({
            path: 'preferredSub.localIP',
            message: `expected object, got ${describe(ps.localIP)} — sub-object not validated`,
          });
        } else {
          boolField(ps.localIP, 'randomIP', true, 'preferredSub.localIP.randomIP');
          intField(ps.localIP, 'count', 1, 1024, 16, 'preferredSub.localIP.count');
          // port: -1 means "auto", otherwise must be a TCP port
          intField(ps.localIP, 'port', -1, 65535, -1, 'preferredSub.localIP.port');
        }
      }
    }
  }

  return { config: c, issues };
}

/** Format a list of issues as a single multi-line string for logging. */
export function formatIssues(issues: ValidationIssue[]): string {
  if (issues.length === 0) return '';
  const lines = issues.map((i) => `  - ${i.path || '<root>'}: ${i.message}`);
  return `config.json validation: ${issues.length} issue(s)\n${lines.join('\n')}`;
}
