const express = require("express");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

app.get("/health", (req, res) => {
    res.json({ ok: true});
});

app.post("/scan", (req, res) => {
    const { url } = req.body || {};

    if (typeof url !== "string" || url.trim().length === 0) {
        return res.status(400).json({ verdict: "ERROR", reasons: ["Missing url"] });
    }

    const u = url.trim();
    const lower = u.toLowerCase();

    if (!(lower.startsWith("http://") || lower.startsWith("https://"))) {
        return res.json({ verdict: "BLOCKED", reasons: ["Unsupported URL scheme"], url: u});
    }

    const suspiciousHosts = ["qrto.org", "bit.ly", "tinyurl.com"];
    let host = "";
    try {
        host = new URL(u).host;
    } catch {
        return res.json({ verdict: "BLOCKED", reasons: ["Invalid URL format"], url: u});
    }

    const reasons = ["URL is http/https", 'Host: ${host}'];
    let verdict = "SAFE"

    if (suspiciousHosts.includes(host)) {
        verdict = "SUSPICIOUS";
        reasons.push("Short-link/dynamic QR domain (resolve redirects before trusting");
    }

    res.json({ verdict, reasons, scannedUrl: u });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Backend Listening on http://localhost:${PORT}'));