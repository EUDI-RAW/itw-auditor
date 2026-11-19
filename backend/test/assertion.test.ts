import { before, describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import * as crypto from 'crypto';
import { VerifiedBootState } from '@peculiar/asn1-android';
import { getConfig } from '../src/config';
import { assert as assertEndpoint, getChallenge, register, type ServiceDeps } from '../src/service';
import { issueChallenge, verifyChallenge, verifyRegistration } from '../src/tokens';
import {
  NOW,
  STOCK_BOOT_KEY,
  createAttestation,
  createTestRoot,
  grapheneOsParams,
  stockParams,
  testOptions,
  type TestAttestation,
  type TestAttestationParams,
  type TestRoot,
} from './helpers';

const SECRET = 'test-secret-with-at-least-32-characters';

describe('tokens', () => {
  const secret = Buffer.from(SECRET);

  it('issues challenges shorter than the 128 bytes attestation challenge limit', () => {
    const { challenge } = issueChallenge(secret, 300, NOW.getTime());
    assert.ok(challenge.length <= 64);
    verifyChallenge(secret, challenge, NOW.getTime());
  });

  it('rejects expired, tampered and foreign challenges', () => {
    const { challenge } = issueChallenge(secret, 300, NOW.getTime());
    assert.throws(() => verifyChallenge(secret, challenge, NOW.getTime() + 301_000), /expired/);
    const [expiry, random, mac] = challenge.split('.');
    assert.throws(
      () => verifyChallenge(secret, `${Number(expiry) + 1000}.${random}.${mac}`, NOW.getTime()),
      /signature/
    );
    assert.throws(
      () => verifyChallenge(Buffer.from(`${SECRET}-other`), challenge, NOW.getTime()),
      /signature/
    );
  });
});

describe('register and assert', () => {
  let root: TestRoot;

  before(async () => {
    root = await createTestRoot();
  });

  const deps = (overrides: Partial<ServiceDeps['verificationOptions']> = {}): ServiceDeps => {
    const { challenge: _, ...options } = testOptions(root, overrides);
    return {
      config: getConfig({ SERVER_SECRET: SECRET, ANDROID_PACKAGE_NAMES: options.packageNames.join(',') }),
      verificationOptions: options,
      now: () => NOW.getTime(),
    };
  };

  type Body = Record<string, unknown>;

  /**
   * Registers a device with a challenge issued by the service.
   */
  const registerDevice = async (
    params: (challenge: string) => TestAttestationParams,
    options: { attestKey?: null } = {},
    serviceDeps = deps()
  ) => {
    const { challenge } = (await getChallenge(serviceDeps)).body as { challenge: string };
    const attestation = await createAttestation(root, params(challenge), options);
    const response = await register(
      { challenge, certificates: attestation.encoded },
      serviceDeps
    );
    return { attestation, response: response as { status: number; body: Body } };
  };

  /**
   * Builds an assertion as done by the app: signs the client data with the hardware key and generates a
   * fresh key attestation with the SHA-256 hex digest of the client data, by default with the registered
   * attest key.
   */
  const buildAssertion = async (
    registered: TestAttestation,
    registration: string,
    params: (requestHash: string) => TestAttestationParams,
    options: { attestKey?: 'new' | null } = {},
    serviceDeps = deps()
  ) => {
    const { challenge } = (await getChallenge(serviceDeps)).body as { challenge: string };
    const clientData = JSON.stringify({ challenge, purpose: 'test' });
    const requestHash = crypto.createHash('sha256').update(clientData).digest('hex');
    const fresh = await createAttestation(root, params(requestHash), {
      attestKey:
        options.attestKey === null
          ? null
          : options.attestKey === 'new'
            ? undefined
            : registered.attestKey,
    });
    return {
      registration,
      clientData,
      signature: crypto
        .createSign('SHA256')
        .update(clientData)
        .sign(registered.privateKey, 'base64'),
      certificates: fresh.encoded,
    };
  };

  for (const [name, params, os] of [
    ['GrapheneOS (SelfSigned with allowlisted key)', grapheneOsParams, 'grapheneos'],
    ['the stock OS (Verified)', stockParams, 'stock'],
  ] as const) {
    it(`accepts the registration and the assertion of ${name}`, async () => {
      const { attestation, response } = await registerDevice((challenge) =>
        params({ challenge })
      );
      assert.equal(response.status, 200, JSON.stringify(response.body));
      assert.equal(response.body.os, os);
      assert.equal(response.body.attestKeyPinned, true);
      const claims = verifyRegistration(Buffer.from(SECRET), response.body.registration);
      assert.ok(claims.attestKey);

      const body = await buildAssertion(
        attestation,
        response.body.registration as string,
        (challenge) => params({ challenge })
      );
      const result = await assertEndpoint(body, deps());
      assert.equal(result.status, 200, JSON.stringify(result.body));
      assert.equal((result.body as Body).os, os);
      assert.equal((result.body as Body).method, 'key_attestation');
    });
  }

  it('reports the parsed attestation also when the registration is rejected', async () => {
    const { response } = await registerDevice((challenge) =>
      grapheneOsParams({ challenge, verifiedBootKey: '34'.repeat(32) })
    );
    assert.equal(response.status, 422);
    assert.match(response.body.error as string, /Verified boot key is not allowed/);
    const report = response.body.report as { attestedKey: { rootOfTrust: { verifiedBootKey: string } } };
    assert.equal(report.attestedKey.rootOfTrust.verifiedBootKey, '34'.repeat(32));
  });

  it('rejects a registration with a challenge not issued by the server', async () => {
    const attestation = await createAttestation(root, grapheneOsParams());
    const response = await register(
      { challenge: 'challenge', certificates: attestation.encoded },
      deps()
    );
    assert.equal(response.status, 400);
  });

  it('rejects GrapheneOS registered without attest key', async () => {
    const { response } = await registerDevice(
      (challenge) => grapheneOsParams({ challenge }),
      { attestKey: null }
    );
    assert.equal(response.status, 422);
    assert.match(response.body.error as string, /attest key is required/);
  });

  it('rejects the assertions of the stock OS registered without attest key (Play Integrity required)', async () => {
    const { attestation, response } = await registerDevice(
      (challenge) => stockParams({ challenge }),
      { attestKey: null }
    );
    assert.equal(response.status, 200);
    assert.equal(response.body.fallbackAvailable, false);
    const body = await buildAssertion(
      attestation,
      response.body.registration as string,
      (challenge) => stockParams({ challenge }),
      { attestKey: null }
    );
    const result = await assertEndpoint(body, deps());
    assert.equal(result.status, 422);
    assert.match((result.body as Body).error as string, /No attest key registered/);
  });

  const rejections: [
    string,
    (body: Record<string, unknown>) => Record<string, unknown>,
    (challenge: string) => TestAttestationParams,
    { attestKey?: 'new' | null },
    RegExp,
  ][] = [
    [
      'a fresh attestation relayed from another device',
      (body) => body,
      (challenge) => grapheneOsParams({ challenge }),
      { attestKey: 'new' },
      /not been signed by the registered attest key/,
    ],
    [
      'a fresh attestation with another challenge',
      (body) => body,
      () => grapheneOsParams({ challenge: 'other' }),
      {},
      /Challenge mismatch/,
    ],
    [
      'another verified boot state',
      (body) => body,
      (challenge) =>
        grapheneOsParams({
          challenge,
          verifiedBootState: VerifiedBootState.verified,
          verifiedBootKey: STOCK_BOOT_KEY,
        }),
      {},
      /root of trust does not match|Device state differs/,
    ],
    [
      'an unlocked bootloader',
      (body) => body,
      (challenge) => grapheneOsParams({ challenge, deviceLocked: false }),
      {},
      /Bootloader is unlocked|root of trust does not match/,
    ],
    [
      'a client data signed with another key',
      (body) => ({
        ...body,
        signature: crypto
          .createSign('SHA256')
          .update(body.clientData as string)
          .sign(crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey, 'base64'),
      }),
      (challenge) => grapheneOsParams({ challenge }),
      {},
      /Invalid hardware signature/,
    ],
  ];

  for (const [name, tamper, params, options, error] of rejections) {
    it(`rejects ${name}`, async () => {
      const { attestation, response } = await registerDevice((challenge) =>
        grapheneOsParams({ challenge })
      );
      const body = await buildAssertion(
        attestation,
        response.body.registration as string,
        params,
        options
      );
      const result = await assertEndpoint(tamper(body), deps());
      assert.equal(result.status, 422, JSON.stringify(result.body));
      assert.match((result.body as Body).error as string, error);
    });
  }

  it('rejects a forged registration token', async () => {
    const { attestation, response } = await registerDevice((challenge) =>
      grapheneOsParams({ challenge })
    );
    const [payload] = (response.body.registration as string).split('.');
    const body = await buildAssertion(
      attestation,
      `${payload}.${Buffer.alloc(32).toString('base64url')}`,
      (challenge) => grapheneOsParams({ challenge })
    );
    const result = await assertEndpoint(body, deps());
    assert.equal(result.status, 400);
    assert.match((result.body as Body).error as string, /registration token signature/);
  });

  it('requires the app signing certificate digests to accept the fresh attestation', async () => {
    const stockDeps = deps({ signatureDigests: [] });
    const { attestation, response } = await registerDevice(
      (challenge) => stockParams({ challenge }),
      {},
      stockDeps
    );
    assert.equal(response.status, 200);
    const body = await buildAssertion(
      attestation,
      response.body.registration as string,
      (challenge) => stockParams({ challenge }),
      {},
      stockDeps
    );
    const result = await assertEndpoint(body, stockDeps);
    assert.equal(result.status, 422);
    assert.match((result.body as Body).error as string, /digests are required/);
  });
});
