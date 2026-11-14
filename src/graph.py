
import json
from pathlib import Path

import numpy as np
import matplotlib.pyplot as plt

# Paths
BASE = Path(__file__).parent
METADATA = BASE / "models" / "model_metadata.json"
OUTPUT = BASE / "model_accuracy_comparison.png"

if not METADATA.exists():
    raise FileNotFoundError(
        f"Metadata not found: {METADATA}\n"
        "Run your model training script first."
    )

with open(METADATA, "r", encoding="utf-8") as file:
    metadata = json.load(file)

models = metadata["cv_results"]
model_names = list(models.keys())

# CV accuracy is available in the saved metadata.
cv_accuracy = [
    models[name]["accuracy"]["mean"] * 100
    for name in model_names
]

cv_std = [
    models[name]["accuracy"]["std"] * 100
    for name in model_names
]

# The current training script does not save training accuracy.
# Calculate it by loading the saved models and original dataset.
import joblib
import pandas as pd
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

DATA = BASE / "dataset" / "privesc_dataset.csv"

df = pd.read_csv(DATA)
features = metadata["features"]

X = df[features].astype(float)

# Reproduce the original split and label encoding.
encoder = LabelEncoder()
y = encoder.fit_transform(df["label"].astype(str))

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=metadata["test_size"],
    stratify=y,
    random_state=metadata["random_state"]
)

model_files = {
    "Logistic Regression": "logistic_regression.pkl",
    "Random Forest": "random_forest.pkl",
    "XGBoost": "xgboost.pkl"
}

train_accuracy = []

for name in model_names:
    model = joblib.load(BASE / "models" / model_files[name])
    predictions = model.predict(X_train)

    train_accuracy.append(
        accuracy_score(y_train, predictions) * 100
    )

# Plot
x = np.arange(len(model_names))
width = 0.34

fig, ax = plt.subplots(figsize=(9, 5.5))

bars_train = ax.bar(
    x - width / 2,
    train_accuracy,
    width,
    label="Training Accuracy"
)

bars_cv = ax.bar(
    x + width / 2,
    cv_accuracy,
    width,
    yerr=cv_std,
    capsize=4,
    label="5-Fold CV Accuracy"
)

ax.set_xlabel("Machine Learning Models")
ax.set_ylabel("Accuracy (%)")
ax.set_title("Training vs. Cross-Validation Accuracy")
ax.set_xticks(x)
ax.set_xticklabels(model_names, rotation=10, ha="right")
ax.set_ylim(0, 105)
ax.legend()
ax.grid(axis="y", linestyle="--", alpha=0.35)

ax.bar_label(bars_train, fmt="%.2f%%", padding=3, fontsize=8)
ax.bar_label(bars_cv, fmt="%.2f%%", padding=3, fontsize=8)

fig.tight_layout()
fig.savefig(OUTPUT, dpi=600, bbox_inches="tight")
plt.show()

print(f"Graph saved to: {OUTPUT}")
