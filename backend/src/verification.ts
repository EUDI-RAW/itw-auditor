import * as crypto from 'crypto';
import { X509Certificate } from 'crypto';
import {
  findAttestationRecords,
  type AttestationRecord,
  type CertificateWithAttestation,
} from './keyDescription';
import {
  AttestationPolicyError,
  evaluateAttestKey,
  evaluateAttestationPolicy,
  type AttestationPolicy,
  type VerifiedOs,
} from './attestationPolicy';
import { GOOGLE_ROOT_PUBLIC_KEYS_PEM } from './googleRoots';

/**
 * Key attestation verification, adapted from the reference backend of
 * pagopa/io-react-native-integrity and the io-wallet Wallet Provider, without Play Integrity:
 * the fresh key attestation is always used as integrity proof, as done by the Wallet Provider
 * when the Play Integrity token is missing or not valid.
 */

/**
 * Simplified type definition of the Google attestation status list.
 * {@link https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status}
 */
export type CRL = {
  entries: Record<
    string,
    { status: string; expires?: string; reason?: string; comment?: string }
  >;
};

export const CRL_URL = 'https://android.googleapis.com/attestation/status';
const CRL_CACHE_MS = 60 * 60 * 1000;

let crlCache: { crl: CRL; fetchedAt: number } | undefined;

/**
 * Fetches the Google attestation status list, cached for one hour. If the refresh fails the cached
 * list is used for at most 24 hours, after that the verification fails closed.
 * @returns the {@link CRL}.
 */
export const fetchGoogleCrl = async (): Promise<CRL> => {
  const now = Date.now();
  if (crlCache && now - crlCache.fetchedAt < CRL_CACHE_MS) return crlCache.crl;
  try {
    const res = await fetch(CRL_URL, { signal: AbortSignal.timeout(10000) });
    if (!res.ok) throw new Error(`Failed to fetch the CRL: ${res.status}`);
    const crl = (await res.json()) as CRL;
    if (typeof crl?.entries !== 'object' || crl.entries === null) {
      throw new Error('Invalid CRL');
    }
    crlCache = { crl, fetchedAt: now };
    return crl;
  } catch (e) {
    if (crlCache && now - crlCache.fetchedAt < 24 * CRL_CACHE_MS) {
      console.warn(`[CRL] refresh failed, using the cached list: ${e}`);
      return crlCache.crl;
    }
    throw e;
  }
};

/**
 * @returns the public keys of the Google Hardware Attestation Root CAs.
 */
export const getGoogleRootPublicKeys = () =>
  GOOGLE_ROOT_PUBLIC_KEYS_PEM.map((pem) => crypto.createPublicKey(pem));

/**
 * Options to verify a key attestation.
 */
export type AttestationVerificationOptions = AttestationPolicy & {
  /** Trusted root public keys, the Google Hardware Attestation Root CAs by default. */
  rootPublicKeys?: crypto.KeyObject[];
  /** Loader of the revocation list, the Google attestation status list by default. */
  getCrl?: () => Promise<CRL>;
  /** The current time used to validate the certificates. */
  now?: Date;
  /**
   * The attest key public key pinned at registration. When set, the attested key must have been
   * attested by this attest key, which proves that the attestation comes from the registered device.
   */
  pinnedAttestKey?: crypto.KeyObject;
  /**
   * Whether devices running a self-signed OS (GrapheneOS) must use an app attest key, true by default.
   * All the devices supported by GrapheneOS support app attest keys, which allow to pin the device.
   */
  requireAttestKeyForSelfSigned?: boolean;
};

/**
 * Result of a successful key attestation verification.
 */
export type VerifiedAttestation = {
  /** The {@link VerifiedOs} running on the device. */
  os: VerifiedOs;
  /** The public key of the attested key pair. */
  publicKey: crypto.KeyObject;
  /** The parsed key attestation extension of the attested key. */
  record: AttestationRecord;
  /** The public key of the app attest key which attested the key, to be pinned at registration. */
  attestKeyPublicKey?: crypto.KeyObject;
  /** The parsed key attestation extension of the app attest key, if any. */
  attestKeyRecord?: AttestationRecord;
};

/**
 * Parses a certificate chain sent by the app, from the attested key to the root.
 * @param certificates - The base64 encoded DER certificates.
 * @returns the parsed certificates.
 * @throws {Error} - If the chain is empty, too long or a certificate is not valid.
 */
export const parseCertificateChain = (certificates: unknown) => {
  if (
    !Array.isArray(certificates) ||
    certificates.length === 0 ||
    certificates.length > 10 ||
    !certificates.every((c) => typeof c === 'string')
  ) {
    throw new Error('The certificate chain must be an array of 1 to 10 base64 certificates');
  }
  return certificates.map(
    (certificate: string) =>
      new X509Certificate(Buffer.from(certificate, 'base64'))
  );
};

/**
 * Verifies an Android key attestation, following
 * {@link https://developer.android.com/privacy-and-security/security-key-attestation#verifying}
 * and the GrapheneOS attestation compatibility guide:
 * - the chain must be rooted at a Google Hardware Attestation Root CA and none of its certificates revoked;
 * - the attestation record must satisfy the {@link AttestationPolicy}, see {@link evaluateAttestationPolicy};
 * - the app attest key, if any, must be consistent with the attested key and pinned as configured.
 * @param x509Chain - The certificate chain, from the attested key to the root.
 * @param options - The {@link AttestationVerificationOptions}.
 * @returns the {@link VerifiedAttestation}.
 * @throws {Error} - If the attestation is invalid.
 */
export const verifyAttestation = async (
  x509Chain: X509Certificate[],
  options: AttestationVerificationOptions
): Promise<VerifiedAttestation> => {
  validateIssuance(
    x509Chain,
    options.rootPublicKeys ?? getGoogleRootPublicKeys(),
    options.now ?? new Date()
  );
  validateRevocation(x509Chain, await (options.getCrl ?? fetchGoogleCrl)());
  const { leaf, attestKey } = findAttestationRecords(x509Chain);
  const os = evaluateAttestationPolicy(leaf.record, options);
  if (attestKey) {
    evaluateAttestKey(leaf.record, attestKey.record);
  }
  verifyAttestKeyPinning(attestKey, os, options);
  return {
    os,
    publicKey: leaf.certificate.publicKey,
    record: leaf.record,
    attestKeyPublicKey: attestKey?.certificate.publicKey,
    attestKeyRecord: attestKey?.record,
  };
};

const toSpki = (key: crypto.KeyObject) =>
  key.export({ format: 'der', type: 'spki' });

/**
 * Checks the app attest key of the chain:
 * - when a pinned attest key is provided (assertion), the attested key must have been attested by it;
 * - otherwise (registration) the attest key must have been generated with the same challenge and it is
 *   required for devices running a self-signed OS, see {@link AttestationVerificationOptions}.
 */
const verifyAttestKeyPinning = (
  attestKey: CertificateWithAttestation | undefined,
  os: VerifiedOs,
  options: AttestationVerificationOptions
) => {
  if (options.pinnedAttestKey) {
    if (
      !attestKey ||
      !toSpki(attestKey.certificate.publicKey).equals(
        toSpki(options.pinnedAttestKey)
      )
    ) {
      throw new AttestationPolicyError(
        'Attestation has not been signed by the registered attest key'
      );
    }
    return;
  }
  if (attestKey) {
    const expectedChallenge = Buffer.isBuffer(options.challenge)
      ? options.challenge
      : Buffer.from(options.challenge, 'utf-8');
    if (!attestKey.record.attestationChallenge.equals(expectedChallenge)) {
      throw new AttestationPolicyError('Attest key challenge mismatch');
    }
  } else if (
    os === 'grapheneos' &&
    (options.requireAttestKeyForSelfSigned ?? true)
  ) {
    throw new AttestationPolicyError(
      'An attest key is required for devices running a self-signed OS'
    );
  }
};

/**
 * The device state pinned at registration.
 */
export type RegisteredDevice = {
  /** The public key of the hardware key which signs the client data. */
  publicKey: crypto.KeyObject;
  /** The public key of the app attest key, if the hardware key has been attested by one. */
  attestKeyPublicKey?: crypto.KeyObject;
  verifiedBootState: number;
  verifiedBootKey: string;
};

/**
 * Data sent by the app to assert its integrity.
 */
export type AssertionRequest = {
  /** The client data signed by the hardware key. */
  clientData: string;
  /** The base64 encoded DER ECDSA signature of the client data made with the registered hardware key. */
  signature: string;
  /** The fresh key attestation generated with the SHA-256 hex digest of the client data as challenge. */
  hardwareKeyAttestation: X509Certificate[];
};

/**
 * Verifies an integrity assertion of a registered device through the fresh key attestation, as done by
 * the Wallet Provider when Play Integrity is missing or not valid:
 * 1. the client data must be signed by the hardware key pinned at registration;
 * 2. the device must have been registered with an attest key: the verified boot state and key identify
 *    the OS and not the individual device, so without attest key the fresh attestation is not accepted;
 * 3. the app signing certificate digests must be configured, as they replace the Play Integrity app
 *    recognition verdict for any verified boot state;
 * 4. the fresh attestation must satisfy the same policy of the registration, with the SHA-256 hex digest
 *    of the client data as challenge, and must be signed by the attest key pinned at registration;
 * 5. it must come from the same device state (verified boot state and key) of the registration.
 * @param device - The {@link RegisteredDevice}.
 * @param request - The {@link AssertionRequest}.
 * @param options - The {@link AttestationVerificationOptions}, without challenge.
 * @returns the {@link VerifiedAttestation} of the fresh key attestation.
 * @throws {Error} - If the assertion is invalid.
 */
export const verifyAssertion = async (
  device: RegisteredDevice,
  request: AssertionRequest,
  options: Omit<AttestationVerificationOptions, 'challenge' | 'pinnedAttestKey'>
): Promise<VerifiedAttestation> => {
  const isSignatureValid = crypto
    .createVerify('SHA256')
    .update(request.clientData)
    .verify(device.publicKey, request.signature, 'base64');
  if (!isSignatureValid) {
    throw new Error('Invalid hardware signature of the client data');
  }
  if (!device.attestKeyPublicKey) {
    throw new AttestationPolicyError(
      'No attest key registered with the device: the fresh key attestation is not accepted (Play Integrity required)'
    );
  }
  if (options.signatureDigests.length === 0) {
    throw new AttestationPolicyError(
      'App signing certificate digests are required to accept a hardware key attestation'
    );
  }
  const requestHash = crypto
    .createHash('sha256')
    .update(request.clientData)
    .digest('hex');
  const verified = await verifyAttestation(request.hardwareKeyAttestation, {
    ...options,
    challenge: requestHash,
    pinnedAttestKey: device.attestKeyPublicKey,
  });
  if (
    verified.record.rootOfTrust?.verifiedBootState !==
      device.verifiedBootState ||
    verified.record.rootOfTrust?.verifiedBootKey !== device.verifiedBootKey
  ) {
    throw new Error('Device state differs from the registration');
  }
  return verified;
};

/**
 * Verifies that the certificates are valid at the given time, that each certificate is signed by the
 * next one and that the last one is signed by a trusted root.
 * X509Certificate.checkIssued is not used as it applies the OpenSSL web PKI checks, which reject valid
 * Android attestation chains: e.g. the certificate of an app attest key has a non standard key usage.
 */
const validateIssuance = (
  x509Chain: X509Certificate[],
  rootPublicKeys: crypto.KeyObject[],
  now: Date
) => {
  if (x509Chain.length === 0) throw new Error('No certificates provided');
  const datesValid = x509Chain.every(
    (c) => new Date(c.validFrom) <= now && now <= new Date(c.validTo)
  );
  if (!datesValid) throw new Error('Certificates expired or not yet valid');
  for (let i = 0; i < x509Chain.length - 1; i++) {
    const subject = x509Chain[i]!;
    const issuer = x509Chain[i + 1]!;
    if (subject.issuer !== issuer.subject || !isSignedBy(subject, issuer.publicKey)) {
      throw new Error('Certificate chain is invalid');
    }
  }
  const rootCert = x509Chain[x509Chain.length - 1]!;
  if (!rootPublicKeys.some((pk) => isSignedBy(rootCert, pk))) {
    throw new Error(
      'Root certificate is not signed by a Google Hardware Attestation Root CA'
    );
  }
};

/**
 * Checks that none of the certificates of the chain has been revoked.
 */
const validateRevocation = (x509Chain: X509Certificate[], crl: CRL) => {
  // The CRL entries are indexed by lowercase hex serial numbers without leading zeros,
  // while X509Certificate returns uppercase hex serial numbers.
  const revokedSerials = new Set(
    Object.keys(crl.entries).map(normalizeSerialNumber)
  );
  if (
    x509Chain.some((cert) =>
      revokedSerials.has(normalizeSerialNumber(cert.serialNumber))
    )
  ) {
    throw new Error('Certificate is revoked');
  }
};

const isSignedBy = (certificate: X509Certificate, publicKey: crypto.KeyObject) => {
  try {
    return certificate.verify(publicKey);
  } catch {
    return false;
  }
};

/**
 * Normalizes a hex serial number to lowercase without leading zeros.
 */
export const normalizeSerialNumber = (serialNumber: string) =>
  serialNumber.toLowerCase().replace(/^0+(?=.)/, '');

/**
 * @param key - A public key.
 * @returns the base64 encoded DER SubjectPublicKeyInfo of the key.
 */
export const spkiBase64 = (key: crypto.KeyObject) =>
  toSpki(key).toString('base64');
