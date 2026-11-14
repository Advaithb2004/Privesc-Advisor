"""Train and compare Logistic Regression, Random Forest and XGBoost.

Protocol:
1) Reserve a stratified 20% hold-out test set.
2) Run stratified 5-fold CV on the remaining 80% only.
3) Select the model with the highest mean CV weighted F1.
4) Fit each model on the 80% training split and evaluate once on hold-out test.

The included dataset is synthetic; these metrics are not real-world performance claims.
"""
import json
import warnings
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler
from xgboost import XGBClassifier

BASE = Path(__file__).parent
DATA = BASE / "dataset" / "privesc_dataset.csv"
MODELS = BASE / "models"
MODELS.mkdir(exist_ok=True)
RANDOM_STATE = 42
TEST_SIZE = 0.20
N_SPLITS = 5

if not DATA.exists():
    raise FileNotFoundError(f"Dataset not found: {DATA}. Run generate_dataset.py first.")

df = pd.read_csv(DATA)
if "label" not in df.columns:
    raise ValueError("Dataset must contain a 'label' column.")
if df.isnull().any().any():
    raise ValueError("Dataset contains missing values. Clean them before training.")

features = [c for c in df.columns if c != "label"]
X = df[features].astype(float)
le = LabelEncoder()
y = le.fit_transform(df["label"].astype(str))
class_counts = pd.Series(y).value_counts()
if class_counts.min() < N_SPLITS:
    raise ValueError(f"Every class needs at least {N_SPLITS} rows for {N_SPLITS}-fold stratified CV.")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=TEST_SIZE, stratify=y, random_state=RANDOM_STATE
)
num_classes = len(le.classes_)
models = {
    "Logistic Regression": Pipeline([
        ("scale", StandardScaler()),
        ("model", LogisticRegression(max_iter=3000, class_weight="balanced", C=5.0, random_state=RANDOM_STATE)),
    ]),
    "Random Forest": RandomForestClassifier(
        n_estimators=200, max_depth=14, min_samples_leaf=2,
        class_weight="balanced", random_state=RANDOM_STATE, n_jobs=-1,
    ),
    "XGBoost": XGBClassifier(
        objective="multi:softprob", num_class=num_classes, eval_metric="mlogloss",
        n_estimators=160, max_depth=4, learning_rate=0.08,
        subsample=0.9, colsample_bytree=0.9, reg_lambda=1.0,
        random_state=RANDOM_STATE, tree_method="hist", n_jobs=-1,
    ),
}

cv = StratifiedKFold(n_splits=N_SPLITS, shuffle=True, random_state=RANDOM_STATE)
scoring = {
    "accuracy": "accuracy",
    "precision_weighted": "precision_weighted",
    "recall_weighted": "recall_weighted",
    "f1_weighted": "f1_weighted",
}
cv_results = {}
holdout_results = {}

for name, estimator in models.items():
    print(f"\nEvaluating {name} with {N_SPLITS}-fold stratified cross-validation...")
    with warnings.catch_warnings():
        warnings.simplefilter("default")
        scores = cross_validate(
            estimator, X_train, y_train, cv=cv, scoring=scoring,
            return_train_score=False, n_jobs=1, error_score="raise",
        )
    cv_results[name] = {}
    for metric in scoring:
        values = scores[f"test_{metric}"]
        cv_results[name][metric] = {
            "mean": float(values.mean()),
            "std": float(values.std(ddof=1)),
            "fold_scores": [float(v) for v in values],
        }

    # Fit a separate final estimator on the complete training split.
    estimator.fit(X_train, y_train)
    predictions = estimator.predict(X_test)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, predictions, average="weighted", zero_division=0
    )
    holdout_results[name] = {
        "accuracy": float(accuracy_score(y_test, predictions)),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
    }
    filename = {
        "Logistic Regression": "logistic_regression.pkl",
        "Random Forest": "random_forest.pkl",
        "XGBoost": "xgboost.pkl",
    }[name]
    joblib.dump(estimator, MODELS / filename)

# Select based on CV mean weighted F1, not hold-out test results.
best_name = max(cv_results, key=lambda n: cv_results[n]["f1_weighted"]["mean"])
best_file = {
    "Logistic Regression": "logistic_regression.pkl",
    "Random Forest": "random_forest.pkl",
    "XGBoost": "xgboost.pkl",
}[best_name]
joblib.dump(joblib.load(MODELS / best_file), MODELS / "best_model.pkl")
joblib.dump(le, MODELS / "label_encoder.pkl")

metadata = {
    "features": features,
    "best_model": best_name,
    "selection_metric": "mean 5-fold cross-validation weighted F1-score on training split",
    "cv_folds": N_SPLITS,
    "cv_results": cv_results,
    "results": holdout_results,
    "classes": le.classes_.tolist(),
    "dataset_rows": int(len(df)),
    "samples_per_class": {str(k): int(v) for k, v in df["label"].value_counts().sort_index().items()},
    "test_size": TEST_SIZE,
    "random_state": RANDOM_STATE,
    "evaluation": "stratified 5-fold CV on 80% training split plus one stratified 20% hold-out test evaluation",
    "dataset_type": "controlled synthetic benchmark",
}
(MODELS / "model_metadata.json").write_text(json.dumps(metadata, indent=2))
print("\n=== Cross-validation (mean ± standard deviation) ===")
for name, values in cv_results.items():
    print(f"{name:20s} accuracy={values['accuracy']['mean']:.4f}±{values['accuracy']['std']:.4f}; "
          f"precision={values['precision_weighted']['mean']:.4f}; "
          f"recall={values['recall_weighted']['mean']:.4f}; f1={values['f1_weighted']['mean']:.4f}±{values['f1_weighted']['std']:.4f}")
print(f"\nSelected model by CV weighted F1: {best_name}")
print("\n=== Hold-out test results ===")
print(json.dumps(holdout_results, indent=2))
