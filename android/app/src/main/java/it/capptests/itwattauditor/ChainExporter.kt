package it.capptests.itwattauditor

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.util.Base64
import androidx.core.content.FileProvider
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.OutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Exports the recorded attestation chains as a ZIP file, which the user shares or saves explicitly:
 * - `device.json`: device, OS and app details (no hardware identifiers);
 * - for each step, a folder with the certificates (`cert_N.der`), the chain in PEM (`chain.pem`),
 *   the step details, the request sent and the response of the backend (`step.json`).
 */
class ChainExporter(private val context: Context) {

    /**
     * Writes the ZIP file to the given stream.
     */
    fun writeZip(records: List<StepRecord>, deviceInfo: JSONObject, output: OutputStream) {
        ZipOutputStream(output).use { zip ->
            zip.entry("device.json", deviceInfo.toString(2).toByteArray())
            zip.entry("README.txt", README.toByteArray())
            records.forEach { record ->
                val folder = record.id
                record.chain.forEachIndexed { index, certificate ->
                    zip.entry("$folder/cert_$index.der", Base64.decode(certificate, Base64.DEFAULT))
                }
                zip.entry("$folder/chain.pem", toPem(record.chain).toByteArray())
                zip.entry("$folder/step.json", record.toJson().toString(2).toByteArray())
            }
        }
    }

    /**
     * Creates the ZIP file in the app cache and returns the intent to share it with another app.
     */
    fun shareIntent(records: List<StepRecord>, deviceInfo: JSONObject): Intent {
        val dir = File(context.cacheDir, "exports").apply {
            mkdirs()
            listFiles()?.forEach { it.delete() }
        }
        val file = File(dir, fileName())
        file.outputStream().use { writeZip(records, deviceInfo, it) }
        val uri: Uri = FileProvider.getUriForFile(context, "${context.packageName}.exports", file)
        val send = Intent(Intent.ACTION_SEND)
            .setType("application/zip")
            .putExtra(Intent.EXTRA_STREAM, uri)
            .putExtra(Intent.EXTRA_SUBJECT, file.name)
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        return Intent.createChooser(send, file.name)
    }

    companion object {
        private const val README = """ITW Att Auditor export

Each folder is a step of the test session: the registration with the hardware key (register),
an integrity assertion with a fresh key attestation (assert) or a local attestation (local).
- cert_N.der: the certificates of the chain, from the attested key (cert_0) to the root. With an
  app attest key, cert_1 is the attest key certificate.
- chain.pem: the same chain in PEM format, e.g. for openssl or the Android key attestation verifier.
- step.json: the challenge, the details, the request sent and the response of the backend.
device.json describes the device, the OS and the app signing certificate digests.
"""

        fun fileName() = "itwattauditor-${Build.MODEL.replace(Regex("[^A-Za-z0-9]+"), "_")}-" +
            "${RecordStore.newId("export")}.zip"

        fun toPem(chain: List<String>) = chain.joinToString("") { certificate ->
            "-----BEGIN CERTIFICATE-----\n" +
                certificate.chunked(64).joinToString("\n") +
                "\n-----END CERTIFICATE-----\n"
        }

        private fun ZipOutputStream.entry(name: String, data: ByteArray) {
            putNextEntry(ZipEntry(name))
            write(data)
            closeEntry()
        }

        /**
         * Device, OS and app details for the export and the reports, without hardware identifiers.
         */
        fun deviceInfo(engine: AttestationEngine): JSONObject {
            val capabilities = engine.capabilities()
            return JSONObject()
                .put("manufacturer", Build.MANUFACTURER)
                .put("brand", Build.BRAND)
                .put("model", Build.MODEL)
                .put("device", Build.DEVICE)
                .put("product", Build.PRODUCT)
                .put("fingerprint", Build.FINGERPRINT)
                .put("release", Build.VERSION.RELEASE)
                .put("securityPatch", Build.VERSION.SECURITY_PATCH)
                .put("sdkInt", capabilities.sdkInt)
                .put("firstApiLevel", capabilities.firstApiLevel)
                .put("hardwareAttestationSupported", capabilities.isHardwareAttestationSupported)
                .put("appAttestKeySupported", capabilities.hasAttestKey)
                .put("strongBox", capabilities.hasStrongBox)
                .put("appVersion", BuildConfig.VERSION_NAME)
                .put("appSigningCertificateDigests", JSONArray(engine.signingCertificateDigests()))
        }
    }
}
