import csv
from pathlib import Path

PREDICTIONS_FILE = Path("../results/predictions.csv")

with PREDICTIONS_FILE.open(newline="", encoding="utf-8") as f:
    reader = csv.DictReader(f)

    false_positives = [
        row for row in reader
        if row["status"].strip().lower() == "ok"
           and row["true_label"].strip().lower() == "benign"
           and row["predicted_label"].strip().lower() == "malicious"
    ]

print(f"False positives found: {len(false_positives)}\n")

for row in false_positives:
    print("URL:", row["url"])
    print("Predicted level:", row["predicted_level"])
    print("Score:", row["score"])
    print("Reasons:", row["reasons"])
    print("-" * 60)