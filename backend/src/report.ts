import { X509Certificate } from 'crypto';
import { findAttestationRecords, SecurityLevel, VerifiedBootState, type AttestationRecord } from './keyDescription';

const SECURITY_LEVELS: Record<number, string> = {
  [SecurityLevel.software]: 'Software',
  [SecurityLevel.trustedEnvironment]: 'TrustedEnvironment',
  [SecurityLevel.strongBox]: 'StrongBox',
};

const BOOT_STATES: Record<number, string> = {
  [VerifiedBootState.verified]: 'Verified (green)',
  [VerifiedBootState.selfSigned]: 'SelfSigned (yellow)',
  [VerifiedBootState.unverified]: 'Unverified (orange)',
  [VerifiedBootState.failed]: 'Failed (red)',
};

const PURPOSES: Record<number, string> = {
  0: 'ENCRYPT',
  1: 'DECRYPT',
  2: 'SIGN',
  3: 'VERIFY',
  5: 'WRAP_KEY',
  6: 'AGREE_KEY',
  7: 'ATTEST_KEY',
};

/**
 * Describes an attestation record for the test reports, with readable names.
 */
export const describeRecord = (record: AttestationRecord) => ({
  attestationVersion: record.attestationVersion,
  attestationSecurityLevel: SECURITY_LEVELS[record.attestationSecurityLevel] ?? record.attestationSecurityLevel,
  keymasterVersion: record.keymasterVersion,
  keymasterSecurityLevel: SECURITY_LEVELS[record.keymasterSecurityLevel] ?? record.keymasterSecurityLevel,
  attestationChallenge: record.attestationChallenge.toString('utf-8'),
  purposes: record.purposes?.map((p) => PURPOSES[p] ?? p),
  origin: record.origin === 0 ? 'GENERATED' : record.origin,
  rootOfTrust: record.rootOfTrust && {
    deviceLocked: record.rootOfTrust.deviceLocked,
    verifiedBootState:
      BOOT_STATES[record.rootOfTrust.verifiedBootState] ?? record.rootOfTrust.verifiedBootState,
    verifiedBootKey: record.rootOfTrust.verifiedBootKey,
    verifiedBootHash: record.rootOfTrust.verifiedBootHash,
  },
  osVersion: record.osVersion,
  osPatchLevel: record.osPatchLevel,
  vendorPatchLevel: record.vendorPatchLevel,
  bootPatchLevel: record.bootPatchLevel,
  attestationApplicationId: record.attestationApplicationId,
});

/**
 * Describes a certificate chain and its attestation records for the test reports. It never throws, so
 * that the report is available also when the verification fails.
 * @param x509Chain - The certificate chain.
 * @returns the description of the chain.
 */
export const describeChain = (x509Chain: X509Certificate[]) => {
  const certificates = x509Chain.map((c) => ({
    subject: c.subject,
    issuer: c.issuer,
    serialNumber: c.serialNumber.toLowerCase(),
    validFrom: new Date(c.validFrom).toISOString(),
    validTo: new Date(c.validTo).toISOString(),
    publicKeyType: c.publicKey.asymmetricKeyType,
  }));
  try {
    const { leaf, attestKey } = findAttestationRecords(x509Chain);
    return {
      certificates,
      attestedKey: describeRecord(leaf.record),
      attestKey: attestKey ? describeRecord(attestKey.record) : undefined,
    };
  } catch (e) {
    return { certificates, parseError: e instanceof Error ? e.message : `${e}` };
  }
};
