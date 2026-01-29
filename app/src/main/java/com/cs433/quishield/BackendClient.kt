package com.cs433.quishield

// OkHttp imports (HTTP client library used to call the backend API)
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

// Lightweight JSON building (used to create the POST body)
import org.json.JSONObject

/**
 * Backend Client
 *
 * Helper class responsible for communicating with the backend
 */
class BackendClient (
    private val baseUrl: String
) {
    //OkHttpClient is the main object used to execute HTTP requests
    private val client = OkHttpClient()

    // MediaType for JSON request bodies
    private val jsonMediaType = "application/json; charset=utf-8".toMediaType()

    /**
     * scanUrl
     *
     * Sends a URL to the backend to be analyzed for safety
     *
     * Expected backend endpoints:
     *  POST {baseUrl}/scan
     *
     * Request body JSON:
     *  { "url": "https://example.com" }
     *
     * Response:
     * - Returns the backend response body as a raw JSON string
     *   (MainActivity currently displays it directly)
     * - In a future improvement, the app can parse this JSON into a Kotlin data class.
     */
    fun scanUrl(url: String): String {

        // Build the JSON request body that will be sent to the backend
        val bodyJson = JSONObject()
            .put("url", url)
            .toString()

        // Construct the HTTP POST request to {baseUrl}/scan with JSON payload
        val request = Request.Builder()
            .url("$baseUrl/scan")
            .post(bodyJson.toRequestBody(jsonMediaType))
            .build()

        client.newCall(request).execute().use { resp ->

            // Read the response body
            val respBody = resp.body?.string().orEmpty()

            if (!resp.isSuccessful) {
                throw RuntimeException("HTTP ${resp.code}: $respBody")
            }
            return respBody
        }
    }
}