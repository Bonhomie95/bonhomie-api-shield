/**
 * @typedef {Object} RedisRateLimiterOptions
 * @property {import("ioredis").Redis} redis     An ioredis client instance
 * @property {number} [windowMs]                 Time window in ms
 * @property {number} [max]                      Max requests in window
 * @property {(req: any) => string} [keyGenerator]
 * @property {string} [prefix]                   Redis key prefix
 * @property {(req: any, res: any) => void} [onLimitReached]
 */

/**
 * Redis-based rate limiter (fixed window).
 *
 * @param {RedisRateLimiterOptions} options
 * @returns {(req: any, res: any, next: any) => Promise<void>}
 */
export function createRedisRateLimiter(options) {
  const {
    redis,
    windowMs = 60_000,
    max = 60,
    keyGenerator = (req) => req.ip || "global",
    prefix = "api-shield:rl:",
    onLimitReached
  } = options;

  if (!redis) {
    throw new Error(
      "[api-shield] createRedisRateLimiter: 'redis' instance is required."
    );
  }

  const ttlSeconds = Math.ceil(windowMs / 1000);

  return async function redisRateLimiter(req, res, next) {
    const key = prefix + keyGenerator(req);

    try {
      const current = await redis.incr(key);
      if (current === 1) {
        await redis.expire(key, ttlSeconds);
      }

      if (current > max) {
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
    } catch (err) {
      // On Redis failure, don't block requests – just pass through.
      next(err);
    }
  };
}
