/**
 * @typedef {Object} MemoryRateLimiterOptions
 * @property {number} [windowMs]  Time window in ms
 * @property {number} [max]       Max requests in window
 * @property {(req: any) => string} [keyGenerator]  Key per client
 * @property {(req: any, res: any) => void} [onLimitReached]
 */

/**
 * In-memory rate limiter (per-process).
 * Good for small apps or single-instance setups.
 *
 * @param {MemoryRateLimiterOptions} options
 * @returns {(req: any, res: any, next: any) => void}
 */
export function createMemoryRateLimiter(options = {}) {
  const {
    windowMs = 60_000,
    max = 60,
    keyGenerator = (req) => req.ip || "global",
    onLimitReached
  } = options;

  /** @type {Map<string, number[]>} */
  const hits = new Map();

  return function memoryRateLimiter(req, res, next) {
    const key = keyGenerator(req);
    const now = Date.now();
    const windowStart = now - windowMs;

    const timestamps = hits.get(key) || [];
    const recent = timestamps.filter((ts) => ts > windowStart);
    recent.push(now);
    hits.set(key, recent);

    if (recent.length > max) {
      if (onLimitReached) {
        onLimitReached(req, res);
      }

      if (!res.headersSent) {
        res.status(429).json({
          success: false,
          message: "Too many requests, please try again later."
        });
      }
      return;
    }

    next();
  };
}
