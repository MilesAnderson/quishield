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

        // 1) Vendor detections: strongest signal
        if (malicious > 0) {
            score += 45 + (malicious - 1) * 15
            reasons.add("$malicious security vendor(s) flagged this URL as malicious")
        }

        if (suspicious > 0) {
            score += suspicious * 20
            reasons.add("$suspicious vendor(s) marked this URL as suspicious")
        }

        // 2) Reputation
        if (reputation < 0) {
            score += (-reputation / 8).coerceAtMost(25)
            reasons.add("The domain has a negative reputation score")
        } else if (reputation >= 100) {
            score -= 20
        } else if (reputation >= 20) {
            score -= 10
        }

        // 3) Community votes: only matter when reputation is not strongly positive
        if (reputation < 50) {
            if (maliciousVotes > harmlessVotes && maliciousVotes >= 5) {
                score += 12
                reasons.add("Community reports show concern about this URL")
            } else if (maliciousVotes >= 10) {
                score += 8
                reasons.add("Community reports show concern about this URL")
            }
        }

        if (harmlessVotes > maliciousVotes && harmlessVotes >= 10) {
            score -= 5
        }

        // 4) HTTP response
        if (httpCode == 0 || httpCode >= 400) {
            score += 10
            reasons.add("The website returned an unusual response")
        }

        // 5) Low-confidence / sparse benign support
        if (harmless < 5 && undetected > 20) {
            score += 10
            reasons.add("Very few engines marked this URL harmless")
        } else if (harmless < 10 && undetected > harmless) {
            score += 6
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

        score = score.coerceIn(0, 100)

        if (reasons.isEmpty()) {
            reasons.add("No security vendors flagged this URL")
        }

        if (malicious == 0 && suspicious == 0 && reputation >= 20) {
            reasons.add("The domain has a strong positive reputation")
        }

        if (httpCode in 200..399) {
            reasons.add("The site responded normally")
        }

        val level = when {
            score >= 55 -> "🚫 Dangerous"
            score >= 20 -> "⚠️ Suspicious"
            else -> "✅ Low Risk"
        }

        return Result(level, score, reasons.distinct())
    }
}