// Path / URL string mangling helpers used by subscription generation.

/**
 * A list of common URL path segments used in real websites — sampled
 * randomly to make WebSocket / gRPC paths look like normal traffic.
 *
 * Trimmed for readability; original includes ~250 entries.
 */
const COMMON_PATH_SEGMENTS = [
  'about', 'account', 'acg', 'act', 'activity', 'ad', 'ads', 'ajax', 'album',
  'albums', 'anime', 'api', 'app', 'apps', 'archive', 'archives', 'article',
  'articles', 'ask', 'auth', 'avatar', 'bbs', 'bd', 'blog', 'blogs', 'book',
  'books', 'bt', 'buy', 'cart', 'category', 'categories', 'cb', 'channel',
  'channels', 'chat', 'china', 'city', 'class', 'classify', 'clip', 'clips',
  'club', 'cn', 'code', 'collect', 'collection', 'comic', 'comics',
  'community', 'company', 'config', 'contact', 'content', 'course', 'courses',
  'cp', 'data', 'detail', 'details', 'dh', 'directory', 'discount', 'discuss',
  'dl', 'dload', 'doc', 'docs', 'document', 'documents', 'doujin', 'download',
  'downloads', 'drama', 'edu', 'en', 'ep', 'episode', 'episodes', 'event',
  'events', 'f', 'faq', 'favorite', 'favourites', 'favs', 'feedback', 'file',
  'files', 'film', 'films', 'forum', 'forums', 'friend', 'friends', 'game',
  'games', 'gif', 'go', 'go.html', 'go.php', 'group', 'groups', 'help',
  'home', 'hot', 'htm', 'html', 'image', 'images', 'img', 'index', 'info',
  'intro', 'item', 'items', 'ja', 'jp', 'jump', 'jump.html', 'jump.php',
  'jumping', 'knowledge', 'lang', 'lesson', 'lessons', 'lib', 'library',
  'link', 'links', 'list', 'live', 'lives', 'm', 'mag', 'magnet', 'mall',
  'manhua', 'map', 'member', 'members', 'message', 'messages', 'mobile',
  'movie', 'movies', 'music', 'my', 'new', 'news', 'note', 'novel', 'novels',
  'online', 'order', 'out', 'out.html', 'out.php', 'outbound', 'p', 'page',
  'pages', 'pay', 'payment', 'pdf', 'photo', 'photos', 'pic', 'pics',
  'picture', 'pictures', 'play', 'player', 'playlist', 'post', 'posts',
  'product', 'products', 'program', 'programs', 'project', 'qa', 'question',
  'rank', 'ranking', 'read', 'readme', 'redirect', 'redirect.html',
  'redirect.php', 'reg', 'register', 'res', 'resource', 'retrieve', 'sale',
  'search', 'season', 'seasons', 'section', 'seller', 'series', 'service',
  'services', 'setting', 'settings', 'share', 'shop', 'show', 'shows',
  'site', 'soft', 'sort', 'source', 'special', 'star', 'stars', 'static',
  'stock', 'store', 'stream', 'streaming', 'streams', 'student', 'study',
  'tag', 'tags', 'task', 'teacher', 'team', 'tech', 'temp', 'test', 'thread',
  'tool', 'tools', 'topic', 'topics', 'torrent', 'trade', 'travel', 'tv',
  'txt', 'type', 'u', 'upload', 'uploads', 'url', 'urls', 'user', 'users',
  'v', 'version', 'video', 'videos', 'view', 'vip', 'vod', 'watch', 'web',
  'wenku', 'wiki', 'work', 'www', 'zh', 'zh-cn', 'zh-tw', 'zip',
];

/**
 * Generate a random URL path by sampling 1-3 common path segments.
 *
 * If `fullNodePath` is "/", returns "/<random>" (just the random part).
 * Otherwise prepends the random part to the existing path: "/<random><path>".
 */
export function randomPath(fullNodePath: string = '/'): string {
  const count = Math.floor(Math.random() * 3 + 1);
  const sampled = [...COMMON_PATH_SEGMENTS]
    .sort(() => 0.5 - Math.random())
    .slice(0, count)
    .join('/');
  if (fullNodePath === '/') return `/${sampled}`;
  return `/${sampled + fullNodePath.replace('/?', '?')}`;
}

/**
 * Replace asterisks in a host pattern with random alphanumeric strings.
 * Used to expand wildcard host templates like "*.example.com" into
 * concrete-looking domains.
 */
export function replaceAsterisks(content: string): string {
  if (typeof content !== 'string' || !content.includes('*')) return content;
  const charset = 'abcdefghijklmnopqrstuvwxyz0123456789';
  return content.replace(/\*/g, () => {
    let s = '';
    const length = Math.floor(Math.random() * 14) + 3;
    for (let i = 0; i < length; i++) {
      s += charset[Math.floor(Math.random() * charset.length)];
    }
    return s;
  });
}

/**
 * Replace every "example.com" placeholder in `content` with hosts from
 * the `hosts` array, using each host for `groupSize` consecutive
 * replacements before moving to the next.
 *
 * Used by subscription-generation templates that contain "example.com"
 * placeholders that need to be filled with real domains.
 */
export function bulkReplaceDomains(
  content: string,
  hosts: string[],
  groupSize: number = 2
): string {
  const shuffledHosts = [...hosts].sort(() => Math.random() - 0.5);
  let count = 0;
  let currentRandomHost: string | null = null;
  return content.replace(/example\.com/g, () => {
    if (count % groupSize === 0) {
      const originalHost = shuffledHosts[Math.floor(count / groupSize) % shuffledHosts.length];
      currentRandomHost = replaceAsterisks(originalHost);
    }
    count++;
    return currentRandomHost!;
  });
}
