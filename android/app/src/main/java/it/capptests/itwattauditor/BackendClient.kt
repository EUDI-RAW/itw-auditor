package it.capptests.itwattauditor

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/**
 * Minimal JSON client of the test backend.
 */
class BackendClient(baseUrl: String) {

    private val baseUrl = baseUrl.trim().trimEnd('/')

    data class Response(val status: Int, val body: JSONObject)

    fun get(path: String) = request("GET", path, null)

    fun post(path: String, body: JSONObject) = request("POST", path, body)

    private fun request(method: String, path: String, body: JSONObject?): Response {
        require(baseUrl.startsWith("https://") || baseUrl.startsWith("http://")) {
            "Set the backend URL, e.g. https://your-project.vercel.app"
        }
        val connection = URL("$baseUrl$path").openConnection() as HttpURLConnection
        try {
            connection.requestMethod = method
            connection.connectTimeout = 15_000
            connection.readTimeout = 30_000
            connection.setRequestProperty("Accept", "application/json")
            if (body != null) {
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
                connection.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
            }
            val status = connection.responseCode
            val stream = if (status >= 400) connection.errorStream else connection.inputStream
            val text = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
            val json = try {
                JSONObject(text)
            } catch (e: Exception) {
                JSONObject().put("ok", false).put("error", "Invalid response (HTTP $status): ${text.take(500)}")
            }
            return Response(status, json)
        } finally {
            connection.disconnect()
        }
    }
}
