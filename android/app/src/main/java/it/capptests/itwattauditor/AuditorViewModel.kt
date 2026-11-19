package it.capptests.itwattauditor

import android.app.Application
import android.content.Context
import android.util.Base64
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.security.SecureRandom

/**
 * Test flows of the IT-Wallet hardware key attestation fallback, without Play Integrity:
 * 1. registration: GET /api/challenge, hardware key attested by the app attest key with the challenge,
 *    POST /api/register, which returns the registration token pinning the keys and the device state;
 * 2. assertion: GET /api/challenge, client data with the challenge signed by the hardware key, fresh key
 *    attestation with the SHA-256 hex digest of the client data, POST /api/assert;
 * 3. local attestation: a key attestation with a random challenge, without backend, only to export it.
 */
class AuditorViewModel(application: Application) : AndroidViewModel(application) {

    private val prefs = application.getSharedPreferences("settings", Context.MODE_PRIVATE)
    val engine = AttestationEngine(application)
    val records = RecordStore(application)

    var serverUrl by mutableStateOf(prefs.getString(KEY_SERVER_URL, null) ?: BuildConfig.DEFAULT_SERVER_URL)
        private set
    var registration by mutableStateOf(prefs.getString(KEY_REGISTRATION, null))
        private set
    var busy by mutableStateOf(false)
        private set
    var lastTitle by mutableStateOf("")
        private set
    var lastOutcome by mutableStateOf<Boolean?>(null)
        private set
    var lastOutput by mutableStateOf("")
        private set
    var recordCount by mutableStateOf(records.list().size)
        private set

    fun updateServerUrl(value: String) {
        serverUrl = value
        prefs.edit().putString(KEY_SERVER_URL, value.trim()).apply()
    }

    fun register() = run("Registration") {
        val client = BackendClient(serverUrl)
        val challenge = fetchChallenge(client)
        val attestation = engine.generateRegistration(challenge)
        val certificates = StepRecord.encodeChain(attestation.chain)
        val request = JSONObject()
            .put("challenge", challenge)
            .put("certificates", JSONArray(certificates))
        val response = client.post("/api/register", request)
        val ok = response.status == 200 && response.body.optBoolean("ok")
        if (ok) {
            registration = response.body.getString("registration")
            prefs.edit().putString(KEY_REGISTRATION, registration).apply()
        }
        save("register", challenge, certificates, attestation, request, response)
        ok to summary(attestation, response)
    }

    fun assert() = run("Assertion (hardware key attestation fallback)") {
        val token = registration ?: error("Register the device first")
        check(engine.isRegistered()) { "The hardware key is missing, register the device again" }
        val client = BackendClient(serverUrl)
        val challenge = fetchChallenge(client)
        val clientData = JSONObject()
            .put("challenge", challenge)
            .put("purpose", "itwattauditor-assertion")
            .put("timestamp", RecordStore.now())
            .toString()
        val signature = Base64.encodeToString(engine.sign(clientData.toByteArray(Charsets.UTF_8)), Base64.NO_WRAP)
        val requestHash = AttestationEngine.sha256Hex(clientData.toByteArray(Charsets.UTF_8))
        val attestation = engine.generateFreshAttestation(requestHash)
        val certificates = StepRecord.encodeChain(attestation.chain)
        val request = JSONObject()
            .put("registration", token)
            .put("clientData", clientData)
            .put("signature", signature)
            .put("certificates", JSONArray(certificates))
        val response = client.post("/api/assert", request)
        save("assert", requestHash, certificates, attestation, request, response)
        (response.status == 200 && response.body.optBoolean("ok")) to summary(attestation, response)
    }

    fun localAttestation() = run("Local attestation (no backend)") {
        val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
            .joinToString("") { "%02x".format(it) }
        // With a registration the fresh attestation is signed by the attest key, as for the assertions
        val attestation = if (engine.isRegistered()) {
            engine.generateFreshAttestation(challenge)
        } else {
            engine.generateRegistration(challenge).also { engine.reset() }
        }
        val certificates = StepRecord.encodeChain(attestation.chain)
        save("local", challenge, certificates, attestation, null, null)
        true to JSONObject()
            .put("challenge", challenge)
            .put("details", details(attestation))
            .put("note", "Not verified: export the ZIP to inspect the chain")
            .toString(2)
    }

    fun reset() = run("Reset") {
        engine.reset()
        registration = null
        prefs.edit().remove(KEY_REGISTRATION).apply()
        records.clear()
        true to "Keys, registration and recorded chains deleted"
    }

    fun deviceInfo(): JSONObject = ChainExporter.deviceInfo(engine)

    private fun fetchChallenge(client: BackendClient): String {
        val response = client.get("/api/challenge")
        return response.body.optString("challenge").takeIf { response.status == 200 && it.isNotEmpty() }
            ?: error("Challenge request failed (HTTP ${response.status}): ${response.body.optString("error")}")
    }

    private fun details(attestation: AttestationEngine.Attestation) = JSONObject()
        .put("usedAttestKey", attestation.usedAttestKey)
        .put("strongBox", attestation.strongBox)
        .put("fallbackReason", attestation.fallbackReason ?: JSONObject.NULL)
        .put("certificates", attestation.chain.size)

    private fun save(
        type: String,
        challenge: String,
        certificates: List<String>,
        attestation: AttestationEngine.Attestation,
        request: JSONObject?,
        response: BackendClient.Response?,
    ) {
        records.add(
            StepRecord(
                id = RecordStore.newId(type),
                type = type,
                createdAt = RecordStore.now(),
                challenge = challenge,
                chain = certificates,
                details = details(attestation),
                request = request,
                response = response?.body,
                httpStatus = response?.status,
            )
        )
    }

    private fun summary(attestation: AttestationEngine.Attestation, response: BackendClient.Response) =
        JSONObject()
            .put("httpStatus", response.status)
            .put("device", details(attestation))
            .put("backend", response.body.also { it.remove("registration") })
            .toString(2)

    private fun run(title: String, block: suspend () -> Pair<Boolean, String>) {
        if (busy) return
        busy = true
        lastTitle = title
        lastOutcome = null
        lastOutput = "…"
        viewModelScope.launch {
            val (ok, output) = try {
                withContext(Dispatchers.IO) { block() }
            } catch (e: Exception) {
                false to "${e.javaClass.simpleName}: ${e.message}"
            }
            lastOutcome = ok
            lastOutput = output
            recordCount = records.list().size
            busy = false
        }
    }

    companion object {
        private const val KEY_SERVER_URL = "serverUrl"
        private const val KEY_REGISTRATION = "registration"
    }
}
