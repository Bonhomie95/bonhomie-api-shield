import { getClientIp } from '../fingerprint/getIp.js';

const BOT_UA_PATTERNS = [
  /bot/i,
  /crawl/i,
  /spider/i,
  /slurp/i,
  /headless/i,
  /phantomjs/i,
  /selenium/i,
  /puppeteer/i,
  /scrapy/i,
  /curl/i,
  /wget/i,
  /python-requests/i,
  /httpclient/i,
  /http-client/i,
  /postman/i,
  /insomnia/i,
  /java\/\d/i,
  /okhttp/i,
];

/**
 * Basic quick check for datacenter-like IPs (VERY heuristic).
 * You can extend this with your own CIDR checks.
 */
function isSuspiciousIp(ip) {
  if (!ip) return true;
  // Local / private ranges -> often proxies / internal tools
  return (
    ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    ip.startsWith('172.16.') ||
    ip.startsWith('172.17.') ||
    ip.startsWith('172.18.') ||
    ip.startsWith('172.19.') ||
    ip.startsWith('172.20.') ||
    ip.startsWith('172.21.') ||
    ip.startsWith('172.22.') ||
    ip.startsWith('172.23.') ||
    ip.startsWith('172.24.') ||
    ip.startsWith('172.25.') ||
    ip.startsWith('172.26.') ||
    ip.startsWith('172.27.') ||
    ip.startsWith('172.28.') ||
    ip.startsWith('172.29.') ||
    ip.startsWith('172.30.') ||
    ip.startsWith('172.31.') ||
    ip === '127.0.0.1' ||
    ip === '::1'
  );
}

/**
 * Detect bots based on UA, IP, and headers.
 *
 * @param {any} req
 * @param {{ threshold?: number }} [options]
 * @returns {{ isBot: boolean; score: number; reasons: string[]; ip: string | null; userAgent: string; }}
 */
export function detectBot(req, options = {}) {
  const { threshold = 50 } = options;

  const headers = req.headers || {};
  const userAgent = (headers['user-agent'] || '').toString();
  const acceptLang = headers['accept-language'];
  const xfwd = headers['x-forwarded-for'];
  const ip = getClientIp(req) || null;

  let score = 0;
  /** @type {string[]} */
  const reasons = [];

  // 1) User-Agent checks
  if (!userAgent || userAgent.trim() === '') {
    score += 40;
    reasons.push('Missing User-Agent header');
  } else {
    if (BOT_UA_PATTERNS.some((re) => re.test(userAgent))) {
      score += 50;
      reasons.push('User-Agent matches known bot/crawler pattern');
    }

    if (userAgent.length < 20) {
      score += 10;
      reasons.push('Very short User-Agent string');
    }
  }

  // 2) Accept-Language missing = suspicious (scripts often skip it)
  if (!acceptLang) {
    score += 10;
    reasons.push('Missing Accept-Language header');
  }

  // 3) X-Forwarded-For chain too long
  if (typeof xfwd === 'string') {
    const parts = xfwd.split(',').map((p) => p.trim());
    if (parts.length > 3) {
      score += 10;
      reasons.push('Long X-Forwarded-For chain (> 3 hops)');
    }
  }

  // 4) IP heuristics (very rough)
  if (isSuspiciousIp(ip || '')) {
    score += 10;
    reasons.push(
      'IP appears to be private/loopback (possible proxy or script)'
    );
  }

  const isBot = score >= threshold;

  return {
    isBot,
    score,
    reasons,
    ip,
    userAgent,
  };
}

/**
 * Express middleware:
 * - Attaches detection result to req.botDetection
 * - Optionally blocks bots with 403
 *
 * @param {{ threshold?: number; block?: boolean }} [options]
 */
export function botGuard(options = {}) {
  const { threshold = 50, block = false } = options;

  return function botGuardMiddleware(req, res, next) {
    const result = detectBot(req, { threshold });
    req.botDetection = result;

    if (block && result.isBot) {
      return res.status(403).json({
        success: false,
        error: {
          message: 'Access denied (suspected automated traffic)',
          statusCode: 403,
        },
      });
    }

    next();
  };
}
