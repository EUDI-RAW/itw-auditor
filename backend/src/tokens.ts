import * as crypto from 'crypto';

/**
 * Stateless challenges and registration tokens signed with HMAC-SHA256, as serverless functions
 * have no shared memory. Please note that without a storage a challenge can't be consumed: it can be
 * replayed until it expires, which is acceptable for a test backend but not for production.
 */

const b64url = (buffer: Buffer) => buffer.toString('base64url');

const hmac = (secret: Buffer, purpose: string, data: string) =>
  crypto.createHmac('sha256', secret).update(`${purpose}\n${data}`).digest();

const safeEqual = (a: Buffer, b: Buffer) =>
  a.length === b.length && crypto.timingSafeEqual(a, b);

/**
 * Issues a challenge: `<expiry in seconds>.<random>.<mac>`, 56 ASCII characters, well below the
 * 128 bytes limit of the attestation challenge.
 * @param secret - The server secret.
 * @param ttlSeconds - The validity of the challenge.
 * @param now - The current time in milliseconds.
 * @returns the challenge and its expiry.
 */
export const issueChallenge = (
  secret: Buffer,
  ttlSeconds: number,
  now = Date.now()
) => {
  const expiresAt = Math.floor(now / 1000) + ttlSeconds;
  const payload = `${expiresAt}.${b64url(crypto.randomBytes(16))}`;
  const mac = hmac(secret, 'challenge', payload).subarray(0, 16);
  return {
    challenge: `${payload}.${b64url(mac)}`,
    expiresAt: new Date(expiresAt * 1000).toISOString(),
  };
};

/**
 * Verifies a challenge issued by {@link issueChallenge}.
 * @param secret - The server secret.
 * @param challenge - The challenge.
 * @param now - The current time in milliseconds.
 * @throws {Error} - If the challenge is not valid or expired.
 */
export const verifyChallenge = (
  secret: Buffer,
  challenge: unknown,
  now = Date.now()
) => {
  if (typeof challenge !== 'string') throw new Error('Missing challenge');
  const parts = challenge.split('.');
  if (parts.length !== 3) throw new Error('Invalid challenge');
  const [expiry, random, mac] = parts as [string, string, string];
  const expected = hmac(secret, 'challenge', `${expiry}.${random}`).subarray(0, 16);
  if (!safeEqual(Buffer.from(mac, 'base64url'), expected)) {
    throw new Error('Invalid challenge signature');
  }
  if (!/^\d+$/.test(expiry) || Number(expiry) * 1000 < now) {
    throw new Error('Challenge expired');
  }
};

/**
 * Device state pinned at registration, carried by the registration token.
 */
export type RegistrationClaims = {
  /** Base64 SPKI of the hardware key. */
  hardwareKey: string;
  /** Base64 SPKI of the app attest key, if any. */
  attestKey?: string;
  verifiedBootState: number;
  verifiedBootKey: string;
  os: string;
  /** Registration time in seconds. */
  iat: number;
};

/**
 * Signs the registration claims: `<base64url JSON>.<base64url mac>`. The app stores the token and sends
 * it with each assertion, in place of the wallet instance stored by the Wallet Provider.
 */
export const signRegistration = (secret: Buffer, claims: RegistrationClaims) => {
  const payload = b64url(Buffer.from(JSON.stringify(claims), 'utf-8'));
  return `${payload}.${b64url(hmac(secret, 'registration', payload))}`;
};

/**
 * Verifies a registration token issued by {@link signRegistration}.
 * @throws {Error} - If the token is not valid.
 */
export const verifyRegistration = (
  secret: Buffer,
  token: unknown
): RegistrationClaims => {
  if (typeof token !== 'string') throw new Error('Missing registration token');
  const [payload, mac, ...rest] = token.split('.');
  if (!payload || !mac || rest.length > 0) {
    throw new Error('Invalid registration token');
  }
  if (
    !safeEqual(Buffer.from(mac, 'base64url'), hmac(secret, 'registration', payload))
  ) {
    throw new Error('Invalid registration token signature');
  }
  return JSON.parse(Buffer.from(payload, 'base64url').toString('utf-8'));
};
