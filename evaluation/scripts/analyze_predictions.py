import pandas as pd
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
import seaborn as sns

# Load predictions
df = pd.read_csv("../results/predictions.csv")

# Keep only successful analyses
df = df[df["status"] == "ok"]

# -----------------------------
# Compute confusion matrix values
# -----------------------------

tp = ((df.true_label == "malicious") & (df.predicted_label == "malicious")).sum()
tn = ((df.true_label == "benign") & (df.predicted_label == "benign")).sum()
fp = ((df.true_label == "benign") & (df.predicted_label == "malicious")).sum()
fn = ((df.true_label == "malicious") & (df.predicted_label == "benign")).sum()

# -----------------------------
# 1. Confusion Matrix Figure
# -----------------------------
y_true = df["true_label"]
y_pred = df["predicted_label"]
labels = sorted(df["true_label"].unique())
cm = confusion_matrix(y_true, y_pred, labels=labels)
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=labels)
disp.plot(cmap="Blues")
plt.title("Confusion Matrix")
plt.tight_layout()
plt.savefig("../results/confusion_matrix.png")
plt.close()
'''
cm = [[tp, fn],
      [fp, tn]]

accuracy = (tp + tn) / (tp + tn + fp + fn)
fpr = fp / (fp + tn)
fnr = fn / (fn + tp)

plt.figure(figsize=(6,5))

cm_labels = [
    [f"TP\n{tp}", f"FN\n{fn}"],
    [f"FP\n{fp}", f"TN\n{tn}"]
]

sns.heatmap(
    cm,
    annot=cm_labels,
    fmt="",
    cmap="Blues",
    xticklabels=["Predicted Malicious", "Predicted Benign"],
    yticklabels=["Actual Malicious", "Actual Benign"]
)

plt.title(
    f"Quishield Security Analysis\n"
    f"Accuracy={accuracy:.2f}  FPR={fpr:.2f}  FNR={fnr:.2f}"
)

plt.tight_layout()
plt.savefig("../results/confusion_matrix.png")
plt.close()
'''

# -----------------------------
# 2. Error Breakdown Bar Chart
# -----------------------------

counts = {
    "True Positive": tp,
    "True Negative": tn,
    "False Positive": fp,
    "False Negative": fn
}

plt.figure(figsize=(7,5))
plt.bar(counts.keys(), counts.values())
plt.title("Security Analysis Classification Results")
plt.ylabel("Count")
plt.xticks(rotation=20)
plt.tight_layout()
plt.savefig("../results/classification_breakdown.png")
plt.close()

# -----------------------------
# 3. Risk Level Distribution
# -----------------------------

risk_counts = df["predicted_level"].value_counts()

plt.figure(figsize=(6,5))
risk_counts.plot(kind="bar")
plt.title("Distribution of Risk Levels Assigned by Quishield")
plt.ylabel("Count")
plt.xlabel("Risk Level")
plt.xticks(rotation=0)
plt.tight_layout()
plt.savefig("../results/risk_distribution.png")
plt.close()

print("Figures saved to evaluation/results/")