package com.cs433.quishield

object RiskAssessment {

    data class Result(
        val level: String,
        val score: Int,
        val reasons: List<String>
    )

    fun assess(report: VirusTotalClient.UrlReportResponse, url: String): Result {

        val attr = report.data.attributes
        val stats = attr.lastAnalysisStats

        val malicious = stats["malicious"] ?: 0
        val suspicious = stats["suspicious"] ?: 0
        val harmless = stats["harmless"] ?: 0
        val undetected = stats["undetected"] ?: 0

        val reputation = attr.reputation ?: 0
        val httpCode = attr.lastHttpResponseCode ?: 0
        val maliciousVotes = attr.totalVotes?.malicious ?: 0
        val harmlessVotes = attr.totalVotes?.harmless ?: 0

        var score = 0
        val reasons = mutableListOf<String>()

        // 1) Strongest signal: vendor detections
        if (malicious > 0) {
            score += malicious * 35
            reasons.add("$malicious security vendor(s) flagged this URL as malicious")
        }

        if (suspicious > 0) {
            score += suspicious * 18
            reasons.add("$suspicious vendor(s) marked this URL as suspicious")
        }

        // 2) Reputation signal
        if (reputation < 0) {
            score += (-reputation / 10).coerceAtMost(20)
            reasons.add("The domain has a negative reputation score")
        } else if (reputation >= 100) {
            score -= 20
        } else if (reputation >= 20) {
            score -= 10
        }

        // 3) Community votes are weak evidence only
        if (maliciousVotes > harmlessVotes && maliciousVotes >= 10) {
            score += 10
            reasons.add("Community reports show some concern about this URL")
        } else if (harmlessVotes > maliciousVotes && harmlessVotes >= 10) {
            score -= 5
        }

        // 4) HTTP response behavior
        if (httpCode == 0 || httpCode >= 400) {
            score += 10
            reasons.add("The website returned an unusual response")
        }

        // 5) Weak confidence if very few harmless engines and many undetected
        if (harmless < 5 && undetected > 20) {
            score += 5
        }

        // 6) Benign category hints
        val categories = attr.categories.values.joinToString(" ").lowercase()

        if (
            categories.contains("education") ||
            categories.contains("reference") ||
            categories.contains("news") ||
            categories.contains("search engine") ||
            categories.contains("searchengines") ||
            categories.contains("portal")
        ) {
            score -= 10
        }

        // 7) Phishing heuristics
        val phishing = PhishingHeuristics.assess(url)
        score += phishing.score
        reasons.addAll(phishing.reasons)

        // Clamp final score
        score = score.coerceIn(0, 100)

        // 8) Human-readable explanations when nothing bad was found
        if (reasons.isEmpty()) {
            reasons.add("No security vendors flagged this URL")
        }

        if (malicious == 0 && suspicious == 0 && reputation >= 20) {
            reasons.add("The domain has a strong positive reputation")
        }

        if (httpCode in 200..399) {
            reasons.add("The site responded normally")
        }

        // 9) Final verdict
        val level = when {
            score >= 60 -> "🚫 Dangerous"
            score >= 25 -> "⚠️ Suspicious"
            else -> "✅ Low Risk"
        }

        return Result(level, score, reasons.distinct())
    }
}