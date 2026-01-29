/**
* server.js (Quishield Backend)
*
* This is a minimal Express backend used by the Android app.
*
* Responsibilites:
* 1) Provide a /scan endpoint that accepts a URL and returns a security verdict
*/

const express = require("express");
const cors = require("cors");

const app = express();

/**
* Middleware
* - cors(): allows requests from the Android emulator/app during development
* - express.json(): automatically parses JSON request bodies into req.body
*/
app.use(cors());
app.use(express.json());

/**
* GET /health
* Quick endpoint to confirm the backend is running
* Example response:
*   { "ok": true }
*/
app.get("/health", (req, res) => {
    res.json({ ok: true});
});

/**
* POST /scan
* Purpose:
* - Accepts a URL from the mobile app
* - Performs basic validation and simple "suspicious host" checking
* - Returns a verdict + reasons describing the decision
*
* Request body (JSON):
*   { "url": "https://example.com" }
*
* Response body (JSON):
*   {
*       "verdict: "SAFE" | "SUSPICIOUS" | "BLOCKED" | "ERROR",
*       "reasons": ["..."],
*       "scannedUrl": "https://..."
*   }
*/
app.post("/scan", (req, res) => {
    // Destructure url from request body
    const { url } = req.body || {};

    if (typeof url !== "string" || url.trim().length === 0) {
        return res.status(400).json({ verdict: "ERROR", reasons: ["Missing url"] });
    }

    const u = url.trim();
    const lower = u.toLowerCase();

    // Allow List
    if (!(lower.startsWith("http://") || lower.startsWith("https://"))) {
        return res.json({ verdict: "BLOCKED", reasons: ["Unsupported URL scheme"], url: u});
    }

    // Known short-link / dynamic QR domains.
    const suspiciousHosts = ["qrto.org", "bit.ly", "tinyurl.com"];

    // Extract host from the URL
    let host = "";
    try {
        host = new URL(u).host;
    } catch {
        return res.json({ verdict: "BLOCKED", reasons: ["Invalid URL format"], url: u});
    }

    const reasons = ["URL is http/https", 'Host: ${host}'];
    let verdict = "SAFE"

    // Flag known shorteners/dynamic-QR hosts
    if (suspiciousHosts.includes(host)) {
        verdict = "SUSPICIOUS";
        reasons.push("Short-link/dynamic QR domain (resolve redirects before trusting");
    }

    // Return the result to the Android app
    res.json({ verdict, reasons, scannedUrl: u });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Backend Listening on http://localhost:${PORT}'));