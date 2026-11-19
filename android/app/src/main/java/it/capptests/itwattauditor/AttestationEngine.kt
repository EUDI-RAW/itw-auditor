package it.capptests.itwattauditor

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.annotation.RequiresApi
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.UUID

/**
 * Android Keystore operations of the IT-Wallet hardware key attestation fallback, ported from the
 * Android module of io-react-native-integrity (getAttestation with useAttestKey and
 * getAttestationAssertion), without Play Integrity:
 * - registration: an app attest key (PURPOSE_ATTEST_KEY, Android 12+) and the hardware key attested by
 *   it, both with the server challenge, StrongBox first and TEE as fallback. If the attest key can't be
 *   generated, the hardware key is generated without it (the backend then can't pin the device);
 * - assertion: the client data signed with the hardware key and a fresh attestation of a temporary key,
 *   attested by the same attest key, with the SHA-256 hex digest of the client data as challenge.
 */
class AttestationEngine(private val context: Context) {

    private val keyStore: KeyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }

    /**
     * Device capabilities relevant for the hardware key attestation.
     */
    data class Capabilities(
        val sdkInt: Int,
        val firstApiLevel: Int,
        val isHardwareAttestationSupported: Boolean,
        val hasAttestKey: Boolean,
        val hasStrongBox: Boolean,
    )

    /**
     * A generated key attestation.
     * @param chain the certificate chain, from the attested key to the root: with an attest key, the
     * certificate of the attested key followed by the chain of the attest key.
     * @param usedAttestKey whether the key has been attested by the app attest key.
     * @param strongBox whether the key has been generated in StrongBox.
     * @param fallbackReason why the attest key or StrongBox could not be used, if any.
     */
    data class Attestation(
        val chain: List<X509Certificate>,
        val usedAttestKey: Boolean,
        val strongBox: Boolean,
        val fallbackReason: String? = null,
    )

    fun capabilities(): Capabilities {
        val firstApiLevel = firstApiLevel()
        return Capabilities(
            sdkInt = Build.VERSION.SDK_INT,
            firstApiLevel = firstApiLevel,
            // Hardware key attestation is mandatory for devices launched with Android 8.0 or later
            isHardwareAttestationSupported = firstApiLevel > Build.VERSION_CODES.N_MR1,
            hasAttestKey = hasAttestKey(),
            hasStrongBox = hasStrongBox(),
        )
    }

    fun isRegistered() = keyStore.containsAlias(HARDWARE_KEY_ALIAS)

    /**
     * Generates the hardware key for the registration, replacing the existing one.
     * @param challenge the challenge issued by the backend.
     */
    fun generateRegistration(challenge: String): Attestation {
        reset()
        val challengeBytes = challenge.toByteArray(Charsets.UTF_8)
        if (hasAttestKey()) {
            try {
                return generateWithAttestKey(HARDWARE_KEY_ALIAS, challengeBytes)
            } catch (e: Exception) {
                // Some devices declare the app attest key feature without a working implementation
                Log.w(TAG, "Attest key generation failed, generating the key without attest key", e)
                reset()
                return generate(HARDWARE_KEY_ALIAS, challengeBytes, null)
                    .copy(fallbackReason = "Attest key generation failed: ${e.message}")
            }
        }
        return generate(HARDWARE_KEY_ALIAS, challengeBytes, null)
            .copy(fallbackReason = "App attest keys not supported (FEATURE_KEYSTORE_APP_ATTEST_KEY)")
    }

    /**
     * Generates a fresh key attestation of a temporary key, attested by the registered attest key when
     * available, then deletes the temporary key.
     * @param challenge the challenge, e.g. the SHA-256 hex digest of the client data.
     */
    fun generateFreshAttestation(challenge: String): Attestation {
        val alias = ASSERTION_KEY_ALIAS_PREFIX + UUID.randomUUID()
        try {
            val attestKeyAlias = ATTEST_KEY_ALIAS.takeIf { hasAttestKey() && keyStore.containsAlias(it) }
            return generate(alias, challenge.toByteArray(Charsets.UTF_8), attestKeyAlias)
        } finally {
            deleteQuietly(alias)
        }
    }

    /**
     * Signs data with the registered hardware key (SHA256withECDSA, DER encoded signature).
     */
    fun sign(data: ByteArray): ByteArray {
        val privateKey = keyStore.getKey(HARDWARE_KEY_ALIAS, null) as? PrivateKey
            ?: throw IllegalStateException("The device is not registered")
        return Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey)
            update(data)
            sign()
        }
    }

    /**
     * Deletes the hardware key and the attest key.
     */
    fun reset() {
        deleteQuietly(HARDWARE_KEY_ALIAS)
        deleteQuietly(ATTEST_KEY_ALIAS)
    }

    /**
     * @return the SHA-256 digests (hex) of the signing certificates of this app, as reported by the key
     * attestation and expected by the backend in ANDROID_SIGNATURE_DIGESTS.
     */
    fun signingCertificateDigests(): List<String> {
        val pm = context.packageManager
        val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val info = pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
            val signingInfo = info.signingInfo ?: return emptyList()
            if (signingInfo.hasMultipleSigners()) signingInfo.apkContentsSigners else signingInfo.signingCertificateHistory
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES).signatures
        } ?: return emptyList()
        return signatures.map { sha256Hex(it.toByteArray()) }.distinct()
    }

    @RequiresApi(Build.VERSION_CODES.S)
    private fun generateWithAttestKey(alias: String, challenge: ByteArray): Attestation {
        val build = { strongBox: Boolean ->
            deleteQuietly(ATTEST_KEY_ALIAS)
            generateKey(ATTEST_KEY_ALIAS, challenge, strongBox, null, KeyProperties.PURPOSE_ATTEST_KEY)
            generateKey(alias, challenge, strongBox, ATTEST_KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
        }
        val strongBox = hasStrongBox()
        var fallbackReason: String? = null
        val usedStrongBox = try {
            build(strongBox)
            strongBox
        } catch (e: Exception) {
            if (!strongBox) throw e
            Log.w(TAG, "StrongBox key generation failed, retrying with the TEE", e)
            fallbackReason = "StrongBox generation failed: ${e.message}"
            deleteQuietly(alias)
            build(false)
            false
        }
        return Attestation(chainOf(alias, ATTEST_KEY_ALIAS), true, usedStrongBox, fallbackReason)
    }

    private fun generate(alias: String, challenge: ByteArray, attestKeyAlias: String?): Attestation {
        val strongBox = hasStrongBox()
        var fallbackReason: String? = null
        val usedStrongBox = try {
            generateKey(alias, challenge, strongBox, attestKeyAlias, KeyProperties.PURPOSE_SIGN)
            strongBox
        } catch (e: Exception) {
            if (!strongBox) throw e
            Log.w(TAG, "StrongBox key generation failed, retrying with the TEE", e)
            fallbackReason = "StrongBox generation failed: ${e.message}"
            deleteQuietly(alias)
            // The attest key must have the same security level of the attested key: a StrongBox
            // generation also fails when the attest key has been generated in the TEE
            generateKey(alias, challenge, false, attestKeyAlias, KeyProperties.PURPOSE_SIGN)
            false
        }
        return Attestation(
            chainOf(alias, attestKeyAlias),
            attestKeyAlias != null,
            usedStrongBox,
            fallbackReason,
        )
    }

    private fun generateKey(
        alias: String,
        challenge: ByteArray,
        strongBox: Boolean,
        attestKeyAlias: String?,
        purposes: Int,
    ) {
        val builder = KeyGenParameterSpec.Builder(alias, purposes)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge)
        if (attestKeyAlias != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            builder.setAttestKeyAlias(attestKeyAlias)
        }
        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER).run {
            initialize(builder.build())
            generateKeyPair()
        }
        if (purposes == KeyProperties.PURPOSE_SIGN && !isHardwareBacked(alias)) {
            deleteQuietly(alias)
            throw IllegalStateException("The generated key is not hardware backed")
        }
    }

    private fun chainOf(alias: String, attestKeyAlias: String?): List<X509Certificate> {
        val chain = if (attestKeyAlias != null) {
            listOf(keyStore.getCertificate(alias)) + keyStore.getCertificateChain(attestKeyAlias)
        } else {
            keyStore.getCertificateChain(alias).toList()
        }
        return chain.map { it as X509Certificate }
    }

    private fun isHardwareBacked(alias: String): Boolean = try {
        val key = keyStore.getKey(alias, null) as PrivateKey
        val info = KeyFactory.getInstance(key.algorithm, KEYSTORE_PROVIDER).getKeySpec(key, KeyInfo::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            info.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
                info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX ||
                info.securityLevel == KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE
        } else {
            @Suppress("DEPRECATION")
            info.isInsideSecureHardware
        }
    } catch (e: Exception) {
        false
    }

    private fun hasStrongBox() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
        context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    private fun hasAttestKey() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
        context.packageManager.hasSystemFeature(PackageManager.FEATURE_KEYSTORE_APP_ATTEST_KEY)

    /**
     * The API level the device launched with, read from the ro.product.first_api_level system property
     * as done by the GrapheneOS Auditor app (Build.VERSION.DEVICE_INITIAL_SDK_INT is not a public API),
     * falling back to the current API level.
     */
    private fun firstApiLevel(): Int {
        val level = readSystemProperty("ro.product.first_api_level")?.toIntOrNull() ?: 0
        return if (level > 0) level else Build.VERSION.SDK_INT
    }

    private fun readSystemProperty(name: String): String? = try {
        @Suppress("PrivateApi")
        Class.forName("android.os.SystemProperties")
            .getMethod("get", String::class.java)
            .invoke(null, name) as? String
    } catch (e: Exception) {
        null
    }

    private fun deleteQuietly(alias: String) {
        try {
            keyStore.deleteEntry(alias)
        } catch (e: Exception) {
            Log.w(TAG, "Unable to delete $alias", e)
        }
    }

    companion object {
        private const val TAG = "AttestationEngine"
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        const val HARDWARE_KEY_ALIAS = "itwattauditor-hardware-key"
        const val ATTEST_KEY_ALIAS = "itwattauditor-hardware-key-attest-key"
        private const val ASSERTION_KEY_ALIAS_PREFIX = "itwattauditor-assertion-"

        fun sha256Hex(data: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }
    }
}
