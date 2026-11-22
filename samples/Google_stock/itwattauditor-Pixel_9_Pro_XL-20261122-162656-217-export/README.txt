ITW Att Auditor export

Each folder is a step of the test session: the registration with the hardware key (register),
an integrity assertion with a fresh key attestation (assert) or a local attestation (local).
- cert_N.der: the certificates of the chain, from the attested key (cert_0) to the root. With an
  app attest key, cert_1 is the attest key certificate.
- chain.pem: the same chain in PEM format, e.g. for openssl or the Android key attestation verifier.
- step.json: the challenge, the details, the request sent and the response of the backend.
device.json describes the device, the OS and the app signing certificate digests.
