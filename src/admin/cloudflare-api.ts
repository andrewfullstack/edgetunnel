// Cloudflare account usage API.
//
// Queries the Cloudflare GraphQL Analytics API to get today's request
// counts for Pages Functions + Workers, used to display "X/100000" in
// the admin panel.

const CF_API_BASE = 'https://api.cloudflare.com/client/v4';
const FREE_TIER_LIMIT = 100000;

export interface CloudflareUsage {
  success: boolean;
  pages: number;
  workers: number;
  total: number;
  max: number;
}

interface AdaptiveGroup {
  sum?: { requests?: number };
}

const sumRequests = (groups: AdaptiveGroup[] | undefined | null): number =>
  groups?.reduce((total, item) => total + (item?.sum?.requests || 0), 0) || 0;

/**
 * Query Cloudflare's free-tier daily request usage.
 *
 * Auth modes:
 *   - APIToken (preferred): Bearer token
 *   - Email + GlobalAPIKey: legacy auth header
 *
 * Returns 0/0/0 with success=false if any error occurs (this is a
 * non-essential metric — we don't fail the request).
 */
export async function getCloudflareUsage(
  email: string | null,
  globalApiKey: string | null,
  accountId: string | null,
  apiToken: string | null,
  log: (...args: any[]) => void = () => {}
): Promise<CloudflareUsage> {
  const baseHeaders = { 'Content-Type': 'application/json' };
  const fallback = (): CloudflareUsage => ({
    success: false,
    pages: 0,
    workers: 0,
    total: 0,
    max: FREE_TIER_LIMIT,
  });

  try {
    if (!accountId && (!email || !globalApiKey)) return fallback();

    // Look up account ID if we have email/global-api-key but no explicit ID
    if (!accountId) {
      const r = await fetch(`${CF_API_BASE}/accounts`, {
        method: 'GET',
        headers: { ...baseHeaders, 'X-AUTH-EMAIL': email!, 'X-AUTH-KEY': globalApiKey! },
      });
      if (!r.ok) throw new Error(`account fetch failed: ${r.status}`);
      const d: any = await r.json();
      if (!d?.result?.length) throw new Error('No accounts found');
      const idx = d.result.findIndex(
        (a: any) => a.name?.toLowerCase().startsWith(email!.toLowerCase())
      );
      accountId = d.result[idx >= 0 ? idx : 0]?.id;
    }

    const startOfDay = new Date();
    startOfDay.setUTCHours(0, 0, 0, 0);
    const authHeaders: Record<string, string> = apiToken
      ? { ...baseHeaders, Authorization: `Bearer ${apiToken}` }
      : { ...baseHeaders, 'X-AUTH-EMAIL': email!, 'X-AUTH-KEY': globalApiKey! };

    const res = await fetch(`${CF_API_BASE}/graphql`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        query: `query getBillingMetrics($AccountID: String!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) {
          viewer { accounts(filter: {accountTag: $AccountID}) {
            pagesFunctionsInvocationsAdaptiveGroups(limit: 1000, filter: $filter) { sum { requests } }
            workersInvocationsAdaptive(limit: 10000, filter: $filter) { sum { requests } }
          } }
        }`,
        variables: {
          AccountID: accountId,
          filter: {
            datetime_geq: startOfDay.toISOString(),
            datetime_leq: new Date().toISOString(),
          },
        },
      }),
    });

    if (!res.ok) throw new Error(`query failed: ${res.status}`);
    const result: any = await res.json();
    if (result.errors?.length) throw new Error(result.errors[0].message);

    const acc = result?.data?.viewer?.accounts?.[0];
    if (!acc) throw new Error('No account data');

    const pages = sumRequests(acc.pagesFunctionsInvocationsAdaptiveGroups);
    const workers = sumRequests(acc.workersInvocationsAdaptive);
    const total = pages + workers;
    log(`Cloudflare usage: pages=${pages}, workers=${workers}, total=${total}, max=${FREE_TIER_LIMIT}`);
    return { success: true, pages, workers, total, max: FREE_TIER_LIMIT };
  } catch (error: any) {
    console.error('getCloudflareUsage error:', error.message);
    return fallback();
  }
}
