package com.cs433.quishield

//From Melanies push import okhttp3.MediaType.Companion.toMediaType
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import com.squareup.moshi.Moshi
import com.squareup.moshi.Json
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

//From Miles's push
import android.util.Base64
import kotlinx.coroutines.delay

class VirusTotalClient(private val apiKey: String) {

    private val client = OkHttpClient()
    private val moshi = Moshi.Builder()
        .add(KotlinJsonAdapterFactory())
        .build()

    data class ScanResponse(
        @Json(name = "data") val data: Data
    ) {
        data class Data(@Json(name = "id") val id: String)
    }

    // GET /analyses/{id}
    data class AnalysisResponse(
        @Json(name = "data") val data: Data
    ) {
        data class Data(
            @Json(name = "attributes") val attributes: Attributes
        ) {
            data class Attributes(
                @Json(name = "status") val status: String? = null,

                // /analyses/{id} uses "stats", not "last_analysis_stats"
                @Json(name = "stats") val stats: Map<String, Int> = emptyMap()
            )
        }
    }

    // GET /urls/{url_id}
    data class UrlReportResponse(
        @Json(name = "data") val data: Data
    ) {
        data class Data(
            @Json(name = "attributes") val attributes: Attributes
        ) {
            data class Attributes(
                @Json(name = "last_analysis_stats")
                val lastAnalysisStats: Map<String, Int> = emptyMap(),

                @Json(name = "categories")
                val categories: Map<String, String> = emptyMap(),

                @Json(name = "reputation")
                val reputation: Int? = null,

                @Json(name = "total_votes")
                val totalVotes: TotalVotes? = null,

                @Json(name = "last_final_url")
                val lastFinal_Url: String? = null,

                @Json(name = "last_http_response_code")
                val lastHttpResponseCode: Int? = null
            )
            data class TotalVotes(
                @Json(name = "harmless") val harmless: Int? = null,
                @Json(name = "malicious") val malicious: Int? = null
            )
        }
    }

    suspend fun scanUrlStats(url: String): Map<String, Int> = withContext(Dispatchers.IO) {
        val analysisId = submitUrl(url)
        val analysis = pollUntilCompleted(analysisId)
        analysis.data.attributes.stats
    }

    // submit url, wait for analysis completion, then fetch the URL report.
    suspend fun scanUrlReport(url: String): UrlReportResponse = withContext(Dispatchers.IO) {
        val analysisId = submitUrl(url)
        pollUntilCompleted(analysisId)

        val urlId = toUrlId(url)

        val rReq = Request.Builder()
            .url("https://www.virustotal.com/api/v3/urls/$urlId")
            .get()
            .addHeader("x-apikey", apiKey)
            .build()

        val rResp = client.newCall(rReq).execute()
        if (rResp.code == 429) throw Exception("Rate limited by VirusTotal (429). Try again in a minute.")
        if (!rResp.isSuccessful) throw Exception("URL report failed: ${rResp.code}")

        val rJson = rResp.body?.string() ?: throw Exception("Empty url report response")
        moshi.adapter(UrlReportResponse::class.java).fromJson(rJson)
            ?: throw Exception("Failed parsing url report")
    }

    private fun submitUrl(url: String): String {
        val formBody = FormBody.Builder()
            .add("url", url.trim())
            .build()

        val submitReq = Request.Builder()
            .url("https://www.virustotal.com/api/v3/urls")
            .post(formBody)
            .addHeader("x-apikey", apiKey)
            .build()

        val submitResp = client.newCall(submitReq).execute()
        if(submitResp.code == 429) throw Exception("Rate limited by Virus (429). Try again in a minute.")
        if(!submitResp.isSuccessful) throw Exception("Scan failed: ${submitResp.code}")

        val submitJson = submitResp.body?.string() ?: throw Exception("Empty scan response")
        val scan = moshi.adapter(ScanResponse::class.java).fromJson(submitJson)
            ?: throw Exception("Failed parsing scan response")

        return scan.data.id
    }

    private suspend fun pollUntilCompleted(analysisId: String): AnalysisResponse {
        val analysisAdapter = moshi.adapter(AnalysisResponse::class.java)

        var tries = 0
        var maxTries = 10
        var pollDelayMs = 7000L
        var rateLimitBackoffMs = 15000L

        while (tries < maxTries) {
            val aReq = Request.Builder()
                .url("https://www.virustotal.com/api/v3/analyses/$analysisId")
                .get()
                .addHeader("x-apikey", apiKey)
                .build()

            val aResp = client.newCall(aReq).execute()

            if(aResp.code == 429) {
                tries ++
                delay(rateLimitBackoffMs)
                continue
            }

            if(!aResp.isSuccessful) {
                throw Exception("Analysis failed: ${aResp.code}")
            }

            val aJson = aResp.body?.string() ?: throw Exception("Empty analysis response")
            val analysis = analysisAdapter.fromJson(aJson) ?: throw Exception("Failed parsing analysis")

            val status = analysis.data.attributes.status
            if (status == "completed") return analysis

            tries ++
            delay(pollDelayMs)
        }

        throw Exception("VirusTotal is busy (free tier). Try again in a minute.")
    }

    // VT url_id is urlsafe base64 without padding
    private fun toUrlId(url: String): String {
        return Base64.encodeToString(
            url.trim().toByteArray(Charsets.UTF_8),
            Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
        )
    }
}
