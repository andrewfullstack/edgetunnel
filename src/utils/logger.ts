// Debug logger.
//
// Takes the ProxyContext (so each request can opt-in/out via DEBUG env var)
// instead of relying on a module-level boolean.

import type { ProxyContext } from '../state.js';

export function makeLogger(ctx: ProxyContext) {
  return (...args: any[]): void => {
    if (ctx.debugLogEnabled) console.log(...args);
  };
}

export type LogFn = ReturnType<typeof makeLogger>;
