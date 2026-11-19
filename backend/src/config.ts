import * as crypto from 'crypto';
import { GrapheneOsAllowlist } from './grapheneosAllowlist';

/**
 * Configuration read from the environment variables, see the README.
 */
export type Config = {
  /** Secret used to sign the challenges and the registration tokens (HMAC-SHA256). */
  secret: Buffer;
  /** Allowed package names of the app. */
  packageNames: string[];
  /** Allowed SHA-256 digests (hex) of the app signing certificates. */
  signatureDigests: string[];
  /** Validity of the challenges in seconds. */
  challengeTtlSeconds: number;
};

export const DEFAULT_PACKAGE_NAME = 'it.capptests.itwattauditor';

let devSecret: Buffer | undefined;

const list = (value: string | undefined) =>
  (value ?? '')
    .split(',')
    .map((item) => item.trim())
    .filter((item) => item.length > 0);

/**
 * Reads the configuration. SERVER_SECRET is required on Vercel: without it each serverless instance
 * would sign with a different secret. Locally a random secret is generated for the process.
 * @param env - The environment variables.
 * @returns the {@link Config}.
 * @throws {Error} - If SERVER_SECRET is missing on Vercel or too short.
 */
export const getConfig = (env: NodeJS.ProcessEnv = process.env): Config => {
  let secret: Buffer;
  if (env.SERVER_SECRET) {
    secret = Buffer.from(env.SERVER_SECRET, 'utf-8');
    if (secret.length < 32) {
      throw new Error('SERVER_SECRET must be at least 32 characters long');
    }
  } else if (env.VERCEL) {
    throw new Error('SERVER_SECRET must be set in the Vercel project settings');
  } else {
    devSecret ??= crypto.randomBytes(32);
    secret = devSecret;
  }
  return {
    secret,
    packageNames: list(env.ANDROID_PACKAGE_NAMES).length
      ? list(env.ANDROID_PACKAGE_NAMES)
      : [DEFAULT_PACKAGE_NAME],
    // Digests may be copied from apksigner or keytool, with colons and uppercase
    signatureDigests: list(env.ANDROID_SIGNATURE_DIGESTS).map((digest) =>
      digest.replace(/:/g, '').toLowerCase()
    ),
    challengeTtlSeconds: Number(env.CHALLENGE_TTL_SECONDS) || 300,
  };
};

let grapheneOsAllowlist: GrapheneOsAllowlist | undefined;

/**
 * Gets the GrapheneOS allowlist of the serverless instance, refreshed at most every 24 hours.
 * GRAPHENEOS_ALLOWED_SIGNERS optionally overrides the pinned GrapheneOS allowed_signers.
 * @returns the {@link GrapheneOsAllowlist}.
 */
export const getGrapheneOsAllowlist = async () => {
  grapheneOsAllowlist ??= new GrapheneOsAllowlist({
    allowedSigners: process.env.GRAPHENEOS_ALLOWED_SIGNERS || undefined,
    timeoutMs: 5000,
  });
  await grapheneOsAllowlist.ensureFresh();
  return grapheneOsAllowlist;
};
