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

class VirusTotalClient(private val apiKey: String) {

    private val client = OkHttpClient()
    private val moshi = Moshi.Builder()
        .add(KotlinJsonAdapterFactory())
        .build()

    data class ScanResponse(
        @Json(name = "data") val data: Data
    ) {
        data class Data(val id: String)
    }

    data class AnalysisResponse(
        @Json(name = "data") val data: Data
    ) {
        data class Data(
            @Json(name = "attributes") val attributes: Attributes
        ) {
            data class Attributes(
                @Json(name = "status") val status: String? = null,

                // /analyses/{id} uses "stats", not "last_analysis_stats"
                @Json(name = "stats") val lastAnalysisStats: Map<String, Int> = emptyMap()
            )
        }
    }

    suspend fun scanUrl(url: String): AnalysisResponse {
        return withContext(Dispatchers.IO) {
            // 1️⃣ Submit URL for scanning
            val formBody = FormBody.Builder()
                .add("url", url)
                .build()

            val request = Request.Builder()
                .url("https://www.virustotal.com/api/v3/urls")
                .post(formBody)
                .addHeader("x-apikey", apiKey)
                .build()

            val response = client.newCall(request).execute()
            if (!response.isSuccessful) throw Exception("Scan failed: ${response.code}")

            val scanJson = response.body?.string() ?: throw Exception("Empty response")
            val scanResponse = moshi.adapter(ScanResponse::class.java).fromJson(scanJson)
                ?: throw Exception("Failed parsing scan response")

            // 2️⃣ Get analysis result
            val analysisId = scanResponse.data.id
            val analysisRequest = Request.Builder()
                .url("https://www.virustotal.com/api/v3/analyses/$analysisId")
                .get()
                .addHeader("x-apikey", apiKey)
                .build()

            val analysisResponse = client.newCall(analysisRequest).execute()
            if (!analysisResponse.isSuccessful) throw Exception("Analysis failed: ${analysisResponse.code}")

            val analysisJson = analysisResponse.body?.string() ?: throw Exception("Empty analysis")
            moshi.adapter(AnalysisResponse::class.java).fromJson(analysisJson)
                ?: throw Exception("Failed parsing analysis")
        }
    }
}
