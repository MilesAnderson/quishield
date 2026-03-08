package com.cs433.quishield

import android.net.Uri
import java.util.Locale

object PhishingHeuristics {

    data class Result(
        val score: Int,
        val reasons: List<String>
    )

    private val suspiciousPathWords = listOf(
        "login", "signin", "verify", "verification", "secure",
        "account", "update", "reset", "password", "billing",
        "payment", "confirm", "unlock"
    )

    private val knownBrands = listOf(
        "paypal", "apple", "google", "microsoft", "amazon",
        "netflix", "instagram", "facebook", "bankofamerica",
        "chase", "wellsfargo"
    )

    fun assess(url: String): Result {
        val reasons = mutableListOf<String>()
        var score = 0

        val uri = try {
            Uri.parse(url)
        } catch (e: Exception) {
            return Result(
                score = 25,
                reasons = listOf("The link format appears unusual")
            )
        }

        val host = (uri.host ?: "").lowercase(Locale.US)
        val path = (uri.path ?: "").lowercase(Locale.US)
        val full = url.lowercase(Locale.US)

        if (host.isBlank()) {
            return Result(
                score = 25,
                reasons = listOf("The link does not contain a normal website host")
            )
        }

        // 1) Raw IP address
        val ipRegex = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")
        if (ipRegex.matches(host)) {
            score += 35
            reasons.add("The link uses a raw IP address instead of a normal domain")
        }

        // 2) Long / messy hostname
        if (host.length > 30) {
            score += 10
            reasons.add("The domain name is unusually long")
        }

        val hyphenCount = host.count { it == '-' }
        if (hyphenCount >= 3) {
            score += 10
            reasons.add("The domain uses many hyphens, which can be a phishing sign")
        }

        val digitCount = host.count { it.isDigit() }
        if (digitCount >= 4) {
            score += 10
            reasons.add("The domain contains many numbers")
        }

        // 3) Suspicious path words
        val matchedPathWords = suspiciousPathWords.filter { word ->
            path.contains(word) || full.contains(word)
        }
        if (matchedPathWords.size >= 2) {
            score += 5
        }

        // 4) Brand mention checks
        val matchedBrands = knownBrands.filter { brand -> full.contains(brand) }
        if (matchedBrands.isNotEmpty()) {
            val hostWithoutDots = host.replace(".", "")

            val suspiciousBrandUse = matchedBrands.any { brand ->
                !host.contains(brand) || isLookalike(hostWithoutDots, brand)
            }

            if (suspiciousBrandUse) {
                score += 25
                reasons.add("The link references a known brand in a suspicious way")
            }
        }

        // 5) '@' trick
        if (url.contains("@")) {
            score += 20
            reasons.add("The link contains '@', which can hide the true destination")
        }

        return Result(
            score = score.coerceIn(0, 100),
            reasons = reasons
        )
    }

    private fun isLookalike(text: String, brand: String): Boolean {
        val normalized = text
            .replace("0", "o")
            .replace("1", "l")
            .replace("3", "e")
            .replace("5", "s")
            .replace("7", "t")
            .replace("@", "a")
            .replace("$", "s")

        return normalized.contains(brand) && !text.contains(brand)
    }
}