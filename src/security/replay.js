import crypto from 'crypto';

/**
 * Create anti-replay token:
 * random nonce + timestamp.
 *
 * @param {number} ttlMs
 */
export function createReplayToken(ttlMs = 30_000) {
  return {
    token: crypto.randomBytes(16).toString('hex') + '-' + Date.now(),
    ttl: ttlMs,
  };
}

/**
 * Create an in-memory replay store
 */
export function createReplayStoreMemory() {
  /** @type {Map<string, number>} */
  const used = new Map();

  return {
    /**
     * Returns true if token is fresh
     */
    verify(token) {
      const now = Date.now();
      const prev = used.get(token);

      if (prev && prev > now) {
        return false; // replay detected
      }

      // token valid → store until it expires
      const expiry = now + 30_000;
      used.set(token, expiry);
      return true;
    },
  };
}

/**
 * Create Redis-based store
 *
 * @param {import("ioredis").Redis} redis
 */
export function createReplayStoreRedis(redis) {
  return {
    async verify(token) {
      const key = 'api_shield_replay:' + token;

      const exists = await redis.exists(key);
      if (exists) return false;

      await redis.set(key, '1', 'PX', 30_000);
      return true;
    },
  };
}
