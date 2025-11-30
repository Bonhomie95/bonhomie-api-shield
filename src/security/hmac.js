import crypto from 'crypto';

/**
 * Create HMAC SHA256
 *
 * @param {string} secret
 * @param {string|Buffer} data
 */
export function createHmac(secret, data) {
  return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

/**
 * Verify HMAC securely
 */
export function verifyHmac(secret, data, expected) {
  const hash = createHmac(secret, data);

  return crypto.timingSafeEqual(
    Buffer.from(hash, 'hex'),
    Buffer.from(expected, 'hex')
  );
}
