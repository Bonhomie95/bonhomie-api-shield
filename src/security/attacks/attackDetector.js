import {
  SQLI_PATTERNS,
  XSS_PATTERNS,
  PATH_TRAVERSAL_PATTERNS,
  ENCODING_ATTACKS,
} from './patterns.js';
import { getClientIp } from '../../fingerprint/getIp.js';

/**
 * Check string for matching patterns
 */
function matchAny(str, patterns) {
  if (!str) return false;
  return patterns.some((re) => re.test(str));
}

function extractStrings(req) {
  const list = [];

  // Strings from query
  for (const v of Object.values(req.query || {})) {
    if (typeof v === 'string') list.push(v);
  }

  // Strings from params
  for (const v of Object.values(req.params || {})) {
    if (typeof v === 'string') list.push(v);
  }

  // Strings from body
  if (req.body && typeof req.body === 'object') {
    for (const v of Object.values(req.body)) {
      if (typeof v === 'string') list.push(v);
    }
  }

  return list;
}

/**
 * Detect multiple types of attacks
 *
 * @param {any} req
 */
export function detectAttack(req) {
  const ip = getClientIp(req);
  const ua = req.headers['user-agent'] || '';

  const reasons = [];
  let score = 0;

  const strings = extractStrings(req);

  for (const s of strings) {
    if (matchAny(s, SQLI_PATTERNS)) {
      score += 40;
      reasons.push('Possible SQL injection');
    }
    if (matchAny(s, XSS_PATTERNS)) {
      score += 40;
      reasons.push('Possible XSS attack');
    }
    if (matchAny(s, PATH_TRAVERSAL_PATTERNS)) {
      score += 30;
      reasons.push('Possible path traversal');
    }
    if (matchAny(s, ENCODING_ATTACKS)) {
      score += 10;
      reasons.push('Suspicious encoding detected');
    }
  }

  // Header anomalies
  if (!ua || ua.length < 10) {
    score += 10;
    reasons.push('Suspicious User-Agent');
  }

  return {
    ip,
    userAgent: ua,
    score,
    isAttack: score >= 40,
    reasons,
  };
}

/**
 * Express middleware
 *
 * @param {{ block?: boolean }} options
 */
export function attackGuard(options = {}) {
  const { block = false } = options;

  return (req, res, next) => {
    const result = detectAttack(req);
    req.attackDetection = result;

    if (block && result.isAttack) {
      return res.status(403).json({
        success: false,
        error: {
          message: 'Request blocked (suspicious input detected)',
          statusCode: 403,
          reasons: result.reasons,
        },
      });
    }

    next();
  };
}
