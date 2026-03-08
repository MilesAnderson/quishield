import csv
import random
from pathlib import Path

# -------- CONFIG --------

INPUT_FILE = Path("../data/balanced_urls.csv")        # change if needed
OUTPUT_FILE = Path("../data/sample_urls.csv")

BENIGN_N = 50
MALICIOUS_N = 50

random.seed(42)

# ------------------------

benign_rows = []
malicious_rows = []

with open(INPUT_FILE, newline="", encoding="utf-8") as f:
    reader = csv.DictReader(f)

    # detect column names
    columns = [c.lower() for c in reader.fieldnames]

    if "url" not in columns:
        raise ValueError("CSV must contain a 'url' column")

    # guess label column
    label_col = None
    for c in reader.fieldnames:
        if c.lower() in ["label", "class", "type"]:
            label_col = c
            break

    if label_col is None:
        raise ValueError("Could not find label column")

    for row in reader:
        url = row["url"]
        label = row[label_col].lower()

        if label in ["benign", "good", "safe", "0"]:
            benign_rows.append({"url": url, "label": "benign"})

        elif label in ["malicious", "bad", "phishing", "1"]:
            malicious_rows.append({"url": url, "label": "malicious"})


print(f"Found {len(benign_rows)} benign URLs")
print(f"Found {len(malicious_rows)} malicious URLs")

if len(benign_rows) < BENIGN_N or len(malicious_rows) < MALICIOUS_N:
    raise ValueError("Dataset does not contain enough samples")

sample = (
        random.sample(benign_rows, BENIGN_N) +
        random.sample(malicious_rows, MALICIOUS_N)
)

random.shuffle(sample)

OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["url", "label"])
    writer.writeheader()
    writer.writerows(sample)

print(f"\nSample written to: {OUTPUT_FILE}")
print(f"Total rows: {len(sample)}")