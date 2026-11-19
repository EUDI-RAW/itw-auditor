package it.capptests.itwattauditor

import android.content.Context
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * A step of a test session (registration, assertion or local attestation) with the generated
 * certificate chain, the request and the backend response, kept in the app private storage so that
 * they can be exported later.
 */
data class StepRecord(
    val id: String,
    val type: String,
    val createdAt: String,
    val challenge: String,
    val chain: List<String>,
    val details: JSONObject,
    val request: JSONObject?,
    val response: JSONObject?,
    val httpStatus: Int?,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("id", id)
        .put("type", type)
        .put("createdAt", createdAt)
        .put("challenge", challenge)
        .put("certificates", JSONArray(chain))
        .put("details", details)
        .put("request", request ?: JSONObject.NULL)
        .put("response", response ?: JSONObject.NULL)
        .put("httpStatus", httpStatus ?: JSONObject.NULL)

    companion object {
        fun fromJson(json: JSONObject) = StepRecord(
            id = json.getString("id"),
            type = json.getString("type"),
            createdAt = json.getString("createdAt"),
            challenge = json.getString("challenge"),
            chain = json.getJSONArray("certificates").let { a -> List(a.length()) { a.getString(it) } },
            details = json.optJSONObject("details") ?: JSONObject(),
            request = json.optJSONObject("request"),
            response = json.optJSONObject("response"),
            httpStatus = if (json.isNull("httpStatus")) null else json.getInt("httpStatus"),
        )

        fun encodeChain(chain: List<X509Certificate>) =
            chain.map { Base64.encodeToString(it.encoded, Base64.NO_WRAP) }
    }
}

/**
 * Stores the [StepRecord]s of the test sessions as JSON files in the app private storage.
 */
class RecordStore(context: Context) {

    private val dir = File(context.filesDir, "records").apply { mkdirs() }

    fun add(record: StepRecord) {
        File(dir, "${record.id}.json").writeText(record.toJson().toString(2))
    }

    fun list(): List<StepRecord> = (dir.listFiles() ?: emptyArray())
        .filter { it.extension == "json" }
        .sortedBy { it.name }
        .mapNotNull { runCatching { StepRecord.fromJson(JSONObject(it.readText())) }.getOrNull() }

    fun clear() {
        dir.listFiles()?.forEach { it.delete() }
    }

    companion object {
        private val idFormat = SimpleDateFormat("yyyyMMdd-HHmmss-SSS", Locale.ROOT).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }
        private val isoFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.ROOT).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }

        fun newId(type: String, now: Date = Date()) = "${idFormat.format(now)}-$type"

        fun now(): String = isoFormat.format(Date())
    }
}
