import * as crypto from 'crypto';
import { getConfig, getGrapheneOsAllowlist, type Config } from './config';
import { describeChain } from './report';
import {
  issueChallenge,
  signRegistration,
  verifyChallenge,
  verifyRegistration,
} from './tokens';
import {
  parseCertificateChain,
  spkiBase64,
  verifyAssertion,
  verifyAttestation,
  type AttestationVerificationOptions,
} from './verification';

/**
 * Framework independent implementation of the endpoints, wrapped by the Vercel functions in `api/`
 * and by the local development server.
 */

export type JsonResponse = { status: number; body: unknown };

/**
 * Dependencies of the service, overridden by the tests.
 */
export type ServiceDeps = {
  config: Config;
  verificationOptions?: Partial<AttestationVerificationOptions>;
  now?: () => number;
};

const getDeps = async (deps?: ServiceDeps) => {
  const resolved = deps ?? { config: getConfig() };
  const allowlist = resolved.verificationOptions?.trustedSelfSignedBootKeys
    ? undefined
    : await getGrapheneOsAllowlist();
  const options: Omit<AttestationVerificationOptions, 'challenge'> = {
    packageNames: resolved.config.packageNames,
    signatureDigests: resolved.config.signatureDigests,
    trustedSelfSignedBootKeys: allowlist?.getKeys() ?? new Set(),
    ...resolved.verificationOptions,
  };
  return { ...resolved, options, now: resolved.now ?? Date.now };
};

const errorMessage = (e: unknown) => (e instanceof Error ? e.message : `${e}`);

const asObject = (body: unknown): Record<string, unknown> =>
  typeof body === 'object' && body !== null ? (body as Record<string, unknown>) : {};

/**
 * GET /api/challenge: issues a challenge for the registration or an assertion.
 */
export const getChallenge = async (deps?: ServiceDeps): Promise<JsonResponse> => {
  const { config, now } = await getDeps(deps);
  return {
    status: 200,
    body: issueChallenge(config.secret, config.challengeTtlSeconds, now()),
  };
};

/**
 * POST /api/register: verifies the key attestation of the hardware key, generated with a challenge
 * issued by {@link getChallenge}, as done by the Wallet Provider when the wallet instance is created.
 * Body: `{ challenge, certificates }`, the chain as base64 DER certificates from the hardware key to
 * the root (with the app attest key certificate right after the hardware key one).
 * On success it returns the registration token, which pins the hardware key, the attest key and the
 * device state, to be sent with the assertions.
 */
export const register = async (
  body: unknown,
  deps?: ServiceDeps
): Promise<JsonResponse> => {
  const { config, options, now } = await getDeps(deps);
  const { challenge, certificates } = asObject(body);
  let chain;
  try {
    verifyChallenge(config.secret, challenge, now());
    chain = parseCertificateChain(certificates);
  } catch (e) {
    return { status: 400, body: { ok: false, error: errorMessage(e) } };
  }
  const report = describeChain(chain);
  try {
    const verified = await verifyAttestation(chain, {
      ...options,
      challenge: challenge as string,
      now: new Date(now()),
    });
    const rootOfTrust = verified.record.rootOfTrust!;
    const registration = signRegistration(config.secret, {
      hardwareKey: spkiBase64(verified.publicKey),
      attestKey: verified.attestKeyPublicKey && spkiBase64(verified.attestKeyPublicKey),
      verifiedBootState: rootOfTrust.verifiedBootState,
      verifiedBootKey: rootOfTrust.verifiedBootKey,
      os: verified.os,
      iat: Math.floor(now() / 1000),
    });
    return {
      status: 200,
      body: {
        ok: true,
        result: 'Registration accepted',
        os: verified.os,
        attestKeyPinned: verified.attestKeyPublicKey !== undefined,
        // Without attest key the Wallet Provider requires Play Integrity for every assertion
        fallbackAvailable: verified.attestKeyPublicKey !== undefined,
        registration,
        report,
      },
    };
  } catch (e) {
    return {
      status: 422,
      body: { ok: false, result: 'Registration rejected', error: errorMessage(e), report },
    };
  }
};

/**
 * POST /api/assert: verifies an integrity assertion through the fresh hardware key attestation, as done
 * by the Wallet Provider for the Wallet Instance Attestation and Key Attestation requests when the Play
 * Integrity token is missing or not valid.
 * Body: `{ registration, clientData, signature, certificates }`:
 * - clientData: a JSON string with the `challenge` issued by {@link getChallenge};
 * - signature: the base64 DER ECDSA signature of clientData made with the hardware key;
 * - certificates: the fresh key attestation chain, generated with the SHA-256 hex digest of clientData
 *   as challenge and signed by the registered app attest key.
 */
export const assert = async (
  body: unknown,
  deps?: ServiceDeps
): Promise<JsonResponse> => {
  const { config, options, now } = await getDeps(deps);
  const { registration, clientData, signature, certificates } = asObject(body);
  let claims;
  let chain;
  try {
    claims = verifyRegistration(config.secret, registration);
    if (typeof clientData !== 'string' || typeof signature !== 'string') {
      throw new Error('clientData and signature must be strings');
    }
    verifyChallenge(config.secret, JSON.parse(clientData).challenge, now());
    chain = parseCertificateChain(certificates);
  } catch (e) {
    return { status: 400, body: { ok: false, error: errorMessage(e) } };
  }
  const report = describeChain(chain);
  const requestHash = crypto.createHash('sha256').update(clientData).digest('hex');
  try {
    const verified = await verifyAssertion(
      {
        publicKey: crypto.createPublicKey({
          key: Buffer.from(claims.hardwareKey, 'base64'),
          format: 'der',
          type: 'spki',
        }),
        attestKeyPublicKey: claims.attestKey
          ? crypto.createPublicKey({
              key: Buffer.from(claims.attestKey, 'base64'),
              format: 'der',
              type: 'spki',
            })
          : undefined,
        verifiedBootState: claims.verifiedBootState,
        verifiedBootKey: claims.verifiedBootKey,
      },
      { clientData, signature: signature as string, hardwareKeyAttestation: chain },
      { ...options, now: new Date(now()) }
    );
    return {
      status: 200,
      body: {
        ok: true,
        result: 'Assertion accepted through the hardware key attestation',
        method: 'key_attestation',
        os: verified.os,
        requestHash,
        report,
      },
    };
  } catch (e) {
    return {
      status: 422,
      body: {
        ok: false,
        result: 'Assertion rejected',
        error: errorMessage(e),
        requestHash,
        report,
      },
    };
  }
};

/**
 * GET /api/status: configuration and allowlist status, without secrets.
 */
export const getStatus = async (deps?: ServiceDeps): Promise<JsonResponse> => {
  const resolved = deps ?? { config: getConfig() };
  const allowlist = resolved.verificationOptions?.trustedSelfSignedBootKeys
    ? undefined
    : await getGrapheneOsAllowlist();
  return {
    status: 200,
    body: {
      ok: true,
      packageNames: resolved.config.packageNames,
      signatureDigests: resolved.config.signatureDigests,
      challengeTtlSeconds: resolved.config.challengeTtlSeconds,
      grapheneOsAllowlist: allowlist && {
        timestamp: allowlist.getTimestamp(),
        keys: allowlist.getKeys().size,
      },
    },
  };
};
