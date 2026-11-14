# PrivEsc Advisor — Explainable Privilege Escalation Recommendation System

Web-based VAPT research prototype for authorized lab/CTF environments.

## Project pipeline

LinPEAS / Linux enumeration output → feature parser → ML classifier → Top-5 recommendation ranking → path-specific SHAP explanation → exploitation guide → mitigations.

The application **displays** commands for authorized lab analysis; it does not execute them.

## Dataset

`dataset/privesc_dataset.csv` contains **2,400 controlled synthetic samples**, balanced across 20 privilege-escalation classes (120 samples per class) and 20 binary Linux-configuration features.

The dataset is synthetic and is intended for development/testing. It should not be presented as a real-world benchmark. For final thesis evaluation, augment or replace it with labelled LinPEAS outputs collected from authorized vulnerable lab machines and manually verified labels.

## Model evaluation

The training script compares three classifiers: **Logistic Regression**, **Random Forest**, and **XGBoost**. It first reserves a stratified 20% hold-out test set. On the remaining 80%, it runs **5-fold Stratified Cross-Validation** and records mean and standard deviation for accuracy, weighted precision, weighted recall, and weighted F1. The model is selected using mean cross-validation weighted F1, then each model is fitted on the full training split and evaluated once on the hold-out test set. The hold-out test set is not used to select the model.

After training, `models/model_metadata.json` stores both cross-validation and hold-out metrics. The web dashboard displays the model comparison table. Metrics are produced by running `python train_model.py`; do not assume earlier numbers remain valid after changing the dataset, model settings, or library versions.

The dataset is synthetic and controlled. Cross-validation measures consistency within this dataset; it does not establish real-world performance. For final thesis evaluation, also test on labelled LinPEAS outputs from authorized vulnerable VMs with manually verified labels.

## Run

```bash
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

To regenerate the controlled dataset and models:

```bash
python generate_dataset.py
python train_model.py
```

## Important research note

The current synthetic benchmark is controlled to test the ML pipeline. It is not evidence that the system achieves the same performance on arbitrary Linux systems. A stronger final evaluation should use real, labelled outputs from authorized vulnerable VMs and report the test protocol, class distribution, confusion matrix, and per-class metrics.
