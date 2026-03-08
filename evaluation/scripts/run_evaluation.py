import csv
import json
import os
import sys
import time
import base64
import urllib.request
import urllib.parse
import urllib.error
from pathlib import Path
from urllib.parse import urlparse

# =========================
# Configuration
# =========================

INPUT_FILE = Path("../data/sample_urls.csv")
PREDICTIONS_FILE = Path("../results/predictions.csv")
METRICS_FILE = Path("../results/metrics.txt")

API_KEY = os.environ.get("VT_API_KEY", "").strip()

# Public API is tight. Be conservative.
REQUEST_SPACING_SECONDS = 16
MAX_POLL_TRIES = 4
POLL_DELAYS = [2, 3, 4, 4]

# =========================
# Helpers
# =========================

def require_api_key():
    if not API_KEY:
        raise RuntimeError(
            "Missing VT_API_KEY environment variable.\n"
            "macOS/Linux:\n"
            "  export VT_API_KEY='your_key_here'\n"
            "Windows PowerShell:\n"
            "  $env:VT_API_KEY='your_key_here'"
        )

def ensure_dirs():
    PREDICTIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
    METRICS_FILE.parent.mkdir(parents=True, exist_ok=True)

def vt_headers():
    return {
        "x-apikey": API_KEY,
        "Accept": "application/json",
    }

def url_to_vt_id(url: str) -> str:
    raw = url.strip().encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")

def sleep_rate_limit():
    time.sleep(REQUEST_SPACING_SECONDS)

def http_json(method: str, url: str, data=None) -> dict:
    req = urllib.request.Request(
        url=url,
        data=data,
        headers=vt_headers(),
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8")
            sleep_rate_limit()
            return json.loads(body)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        sleep_rate_limit()
        raise RuntimeError(f"HTTP {e.code} for {url}: {body}") from e
    except urllib.error.URLError as e:
        sleep_rate_limit()
        raise RuntimeError(f"Network error for {url}: {e}") from e

def get_url_report(url: str):
    vt_id = url_to_vt_id(url)
    endpoint = f"https://www.virustotal.com/api/v3/urls/{vt_id}"
    try:
        return http_json("GET", endpoint)
    except RuntimeError as e:
        msg = str(e)
        if "HTTP 404" in msg:
            return None
        raise

def submit_url(url: str) -> str:
    endpoint = "https://www.virustotal.com/api/v3/urls"
    payload = urllib.parse.urlencode({"url": url}).encode("utf-8")
    data = http_json("POST", endpoint, data=payload)
    return data["data"]["id"]

def poll_analysis(analysis_id: str) -> dict:
    endpoint = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

    for i in range(MAX_POLL_TRIES):
        data = http_json("GET", endpoint)
        status = data.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            return data
        time.sleep(POLL_DELAYS[min(i, len(POLL_DELAYS) - 1)])

    raise RuntimeError("VirusTotal analysis did not complete in time")

def get_or_create_report(url: str) -> dict:
    cached = get_url_report(url)
    cached_stats = (
        cached.get("data", {})
        .get("attributes", {})
        .get("last_analysis_stats", {})
        if cached else {}
    )

    if cached and cached_stats:
        return cached

    analysis_id = submit_url(url)
    poll_analysis(analysis_id)

    fresh = get_url_report(url)
    if not fresh:
        raise RuntimeError("Report was still unavailable after analysis completed")
    return fresh

# =========================
# Heuristics + Risk
# =========================

def phishing_heuristics(url: str):
    reasons = []
    score = 0

    try:
        parsed = urlparse(url)
    except Exception:
        return 25, ["The link format appears unusual"]

    host = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    full = url.lower()

    if not host:
        return 25, ["The link does not contain a normal website host"]

    # 1) Raw IPv4 host
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        score += 35
        reasons.append("The link uses a raw IP address instead of a normal domain")

    # 2) Long / noisy host
    if len(host) > 30:
        score += 10
        reasons.append("The domain name is unusually long")

    hyphens = host.count("-")
    if hyphens >= 3:
        score += 10
        reasons.append("The domain uses many hyphens, which can be a phishing sign")

    digits = sum(ch.isdigit() for ch in host)
    if digits >= 4:
        score += 10
        reasons.append("The domain contains many numbers")

    # 3) Suspicious path words
    suspicious_words = [
        "login", "signin", "verify", "verification", "secure",
        "account", "update", "reset", "password", "billing",
        "payment", "confirm", "unlock"
    ]
    matched_words = [w for w in suspicious_words if w in path or w in full]
    if matched_words:
        score += 15
        reasons.append("The link uses account or verification language")
        if len(set(matched_words)) >= 2:
            score += 5

    # 4) @ trick
    if "@" in url:
        score += 20
        reasons.append("The link contains '@', which can hide the true destination")

    # 5) Very simple lookalike brand checks
    known_brands = [
        "paypal", "apple", "google", "microsoft", "amazon",
        "netflix", "instagram", "facebook", "bankofamerica",
        "chase", "wellsfargo"
    ]

    host_compact = host.replace(".", "")
    normalized = (
        host_compact
        .replace("0", "o")
        .replace("1", "l")
        .replace("3", "e")
        .replace("5", "s")
        .replace("7", "t")
        .replace("@", "a")
        .replace("$", "s")
    )

    for brand in known_brands:
        if brand in full:
            legitimate_host_use = brand in host
            lookalike = (brand in normalized) and (brand not in host_compact)
            if (not legitimate_host_use) or lookalike:
                score += 25
                reasons.append("The link references a known brand in a suspicious way")
                break

    return min(score, 100), reasons

def assess_risk(report: dict, url: str):
    attr = report.get("data", {}).get("attributes", {})
    stats = attr.get("last_analysis_stats", {}) or {}

    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)

    reputation = int(attr.get("reputation", 0) or 0)
    http_code = int(attr.get("last_http_response_code", 0) or 0)

    total_votes = attr.get("total_votes", {}) or {}
    malicious_votes = int(total_votes.get("malicious", 0) or 0)
    harmless_votes = int(total_votes.get("harmless", 0) or 0)

    categories = " ".join((attr.get("categories", {}) or {}).values()).lower()

    score = 0
    reasons = []

    # 1) Vendor detections: strongest signal
    if malicious > 0:
        score += 45 + (malicious - 1) * 15
        reasons.append(f"{malicious} security vendor(s) flagged this URL as malicious")

    if suspicious > 0:
        score += suspicious * 20
        reasons.append(f"{suspicious} vendor(s) marked this URL as suspicious")

    # 2) Reputation
    if reputation < 0:
        score += min(abs(reputation) // 8, 25)
        reasons.append("The domain has a negative reputation score")
    elif reputation >= 100:
        score -= 20
    elif reputation >= 20:
        score -= 10

    # 3) Community votes: only matter when reputation is not strongly positive
    if reputation < 50:
        if malicious_votes > harmless_votes and malicious_votes >= 5:
            score += 12
            reasons.append("Community reports show concern about this URL")
        elif malicious_votes >= 10:
            score += 8
            reasons.append("Community reports show concern about this URL")

    if harmless_votes > malicious_votes and harmless_votes >= 10:
        score -= 5

    # 4) HTTP response
    if http_code == 0 or http_code >= 400:
        score += 10
        reasons.append("The website returned an unusual response")

    # 5) Low-confidence / sparse benign support
    if harmless < 5 and undetected > 20:
        score += 10
        reasons.append("Very few engines marked this URL harmless")
    elif harmless < 10 and undetected > harmless:
        score += 6

    # 6) Benign category hints
    benign_terms = [
        "education", "reference", "news",
        "search engine", "searchengines", "portal"
    ]
    if any(term in categories for term in benign_terms):
        score -= 10

    # 7) Phishing heuristics
    phish_score, phish_reasons = phishing_heuristics(url)
    score += phish_score
    reasons.extend(phish_reasons)

    # 8) Clamp
    score = max(0, min(score, 100))

    # 9) Friendly explanations
    if not reasons:
        reasons.append("No security vendors flagged this URL")

    if malicious == 0 and suspicious == 0 and reputation >= 20:
        reasons.append("The domain has a strong positive reputation")

    if 200 <= http_code <= 399:
        reasons.append("The site responded normally")

    reasons = list(dict.fromkeys(reasons))

    # 10) Final verdict
    if score >= 55:
        level = "Dangerous"
    elif score >= 20:
        level = "Suspicious"
    else:
        level = "Low Risk"

    return level, score, reasons

def level_to_binary(level: str) -> str:
    return "malicious" if level in ("Suspicious", "Dangerous") else "benign"

# =========================
# Resume support
# =========================

def load_completed_urls() -> set:
    if not PREDICTIONS_FILE.exists():
        return set()

    done = set()
    with PREDICTIONS_FILE.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            done.add(row["url"].strip())
    return done

def append_prediction(row: dict):
    file_exists = PREDICTIONS_FILE.exists()
    with PREDICTIONS_FILE.open("a", newline="", encoding="utf-8") as f:
        fieldnames = [
            "url",
            "true_label",
            "predicted_level",
            "predicted_label",
            "score",
            "status",
            "reasons",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)

# =========================
# Metrics
# =========================

def compute_metrics():
    tp = tn = fp = fn = failures = 0
    total = 0
    successful = 0

    if not PREDICTIONS_FILE.exists():
        print("No predictions file found yet.")
        return

    with PREDICTIONS_FILE.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            total += 1

            status = row["status"].strip().lower()
            if status != "ok":
                failures += 1
                continue

            successful += 1
            true_label = row["true_label"].strip().lower()
            predicted = row["predicted_label"].strip().lower()

            if true_label == "malicious" and predicted == "malicious":
                tp += 1
            elif true_label == "benign" and predicted == "benign":
                tn += 1
            elif true_label == "benign" and predicted == "malicious":
                fp += 1
            elif true_label == "malicious" and predicted == "benign":
                fn += 1

    accuracy = (tp + tn) / successful if successful else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    scan_failure_rate = failures / total if total else 0.0

    summary = (
        f"Total rows: {total}\n"
        f"Successful analyses: {successful}\n"
        f"Failures: {failures}\n\n"
        f"TP: {tp}\n"
        f"TN: {tn}\n"
        f"FP: {fp}\n"
        f"FN: {fn}\n\n"
        f"Accuracy: {accuracy:.3f}\n"
        f"False Positive Rate: {fpr:.3f}\n"
        f"False Negative Rate: {fnr:.3f}\n"
        f"Failure Rate: {scan_failure_rate:.3f}\n"
    )

    with METRICS_FILE.open("w", encoding="utf-8") as f:
        f.write(summary)

    print(summary)

# =========================
# Main
# =========================

def main():
    require_api_key()
    ensure_dirs()

    if not INPUT_FILE.exists():
        raise FileNotFoundError(f"Input file not found: {INPUT_FILE}")

    completed = load_completed_urls()

    with INPUT_FILE.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    remaining = [r for r in rows if r["url"].strip() not in completed]
    print(f"Loaded {len(rows)} rows")
    print(f"Already completed: {len(completed)}")
    print(f"Remaining: {len(remaining)}")

    for i, row in enumerate(remaining, start=1):
        url = row["url"].strip()
        true_label = row["label"].strip().lower()

        print(f"[{i}/{len(remaining)}] {url}")

        try:
            report = get_or_create_report(url)
            level, score, reasons = assess_risk(report, url)
            predicted_label = level_to_binary(level)

            append_prediction({
                "url": url,
                "true_label": true_label,
                "predicted_level": level,
                "predicted_label": predicted_label,
                "score": score,
                "status": "ok",
                "reasons": " | ".join(reasons),
            })

        except Exception as e:
            append_prediction({
                "url": url,
                "true_label": true_label,
                "predicted_level": "",
                "predicted_label": "",
                "score": "",
                "status": f"failed: {e}",
                "reasons": "",
            })
            print(f"  FAILED: {e}")

    compute_metrics()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped by user. Partial results were saved.")
        sys.exit(1)