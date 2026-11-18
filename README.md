# PrivEsc Advisor
### An Explainable Privilege Escalation Recommendation System Using Linux Configuration Analysis

## 1. Project Overview

**PrivEsc Advisor** is a web-based Explainable AI (XAI) research prototype designed to identify and recommend potential Linux privilege escalation paths by analyzing system configuration information.

The system processes Linux enumeration output, including LinPEAS results, extracts security-related configuration indicators, and uses machine learning models to predict potential privilege escalation paths.

It combines machine learning predictions, evidence-based ranking, SHAP explainability, risk assessment, and mitigation recommendations to help users understand potential security weaknesses.

The application is intended for authorized penetration testing, cybersecurity research, educational purposes, and controlled laboratory environments.

## 2. Objectives

- Analyze Linux configuration information and enumeration output.
- Extract relevant security indicators such as sudo permissions, SUID binaries, Linux capabilities, writable files, and kernel vulnerabilities.
- Predict possible privilege escalation paths using machine learning.
- Compare Logistic Regression, Random Forest, and XGBoost classifiers.
- Rank the top five privilege escalation recommendations.
- Explain model predictions using SHAP.
- Calculate configuration-based risk scores.
- Provide security mitigation recommendations.

## 3. System Architecture

The system follows the pipeline below:

1. **Input Collection:** Accepts LinPEAS or manually provided Linux configuration information.
2. **Feature Extraction:** Identifies relevant security indicators using the feature parser.
3. **Preprocessing:** Converts extracted indicators into a numerical feature vector.
4. **Model Prediction:** Uses the selected trained machine learning classifier to predict privilege escalation classes.
5. **Recommendation Ranking:** Combines ML probability and evidence scores to rank potential paths.
6. **Explainability:** Uses SHAP to identify the features contributing to individual predictions.
7. **Risk Assessment:** Calculates a heuristic risk score based on detected configuration indicators.
8. **Final Output:** Displays recommendations, explanations, risk levels, and mitigation strategies.

   ![PrivEsc Advisor Workflow](privesc_workflow.png)

## 4. Project Structure

The repository is organized into the following directories:

```text
PrivEsc-Advisor/
│
├── src/
│   ├── app.py
│   ├── parser.py
│   ├── train_model.py
│   ├── generate_dataset.py
│   └── graph.py
│
├── data/
│   └── privesc_dataset.csv
│
├── exp/
│   └── model_accuracy_comparison.png
│
├── models/
│   ├── best_model.pkl
│   ├── logistic_regression.pkl
│   ├── random_forest.pkl
│   ├── xgboost.pkl
│   ├── label_encoder.pkl
│   └── model_metadata.json
│
├── templates/
│   └── index.html
│
├── static/
│   ├── app.js
│   └── style.css
│
├── architecture.png
├── README.md
├── requirements.txt
└── .gitignore
```

### Directory Description

| Directory | Description |
|---|---|
| `src/` | Python source code and application logic |
| `data/` | Dataset used for model training and evaluation |
| `exp/` | Experimental outputs and model comparison results |
| `models/` | Saved machine learning models and metadata |
| `templates/` | HTML frontend |
| `static/` | JavaScript and CSS files |

## 5. Dataset Description

The project currently uses a controlled synthetic dataset containing:

- Total samples: 2,400
- Number of classes: 20
- Samples per class: 120
- Number of features: 20
- Dataset type: Synthetic and balanced

The features represent Linux security configuration indicators, including:

- Sudo permissions
- SUID binaries
- Linux capabilities
- Writable system files
- Kernel vulnerabilities
- NFS configuration

The dataset contains 20 target classes, including `no_path`, which represents the baseline scenario.

**Research limitation:** The current dataset is synthetic and is intended for development and testing. Its evaluation results should not be interpreted as real-world performance. Further validation using manually labelled LinPEAS outputs from authorized vulnerable laboratory systems is required.

## 6. Machine Learning Models

Three machine learning algorithms are implemented and compared.

### Logistic Regression
Used as a baseline classification model. StandardScaler is applied through a machine learning pipeline.

### Random Forest
An ensemble learning algorithm used to classify potential privilege escalation paths using multiple decision trees.

### XGBoost
A gradient boosting algorithm used for comparison with the other classification models.

### Model Evaluation

The evaluation methodology consists of:

1. Stratified 80:20 training and testing split.
2. Five-fold stratified cross-validation on the training portion.
3. Model selection using mean cross-validation weighted F1-score.
4. Final evaluation on the reserved hold-out test set.

The evaluation metrics include:

- Accuracy
- Weighted Precision
- Weighted Recall
- Weighted F1-score

The selected model and evaluation metadata are stored in the `models/` directory.

## 7. Explainable AI Using SHAP

SHAP (SHapley Additive exPlanations) is integrated to explain the predictions generated by the selected machine learning model.

It identifies the contribution of individual Linux configuration features to the predicted privilege escalation class.

The system provides:

- Feature contribution values.
- Positive and negative feature contributions.
- Global prediction explanations.
- Path-specific explanations for recommended paths.

This improves the interpretability of machine learning predictions.

## 8. Recommendation Ranking

The application generates the top five privilege escalation recommendations.

The ranking mechanism combines machine learning probability and evidence score:

**Final Score = 0.70 × ML Probability + 0.30 × Evidence Score**

The evidence score is based on whether the corresponding configuration indicator was detected by the feature parser.

Recommendations are sorted according to their final scores.

## 9. Risk Assessment

The application calculates a heuristic risk score based on detected Linux configuration indicators.

The score is limited to a maximum of 100 and categorized into four levels:

| Risk Score | Risk Level |
|---|---|
| 0–24 | LOW |
| 25–49 | MEDIUM |
| 50–74 | HIGH |
| 75–100 | CRITICAL |

The risk score is calculated independently of the machine learning prediction.

## 10. Technologies Used

**Programming Language**
- Python

**Machine Learning**
- Scikit-learn
- XGBoost
- Pandas
- NumPy

**Explainable AI**
- SHAP

**Backend**
- Flask

**Frontend**
- HTML
- CSS
- JavaScript

**Model Storage**
- Joblib
- JSON

## 11. Installation and Execution

### Prerequisites

- Python 3.10 or later (use a version compatible with the installed dependencies).
- pip package manager.
- Git.

### Step 1: Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/PrivEsc-Advisor.git
```

### Step 2: Navigate to the Project

```bash
cd PrivEsc-Advisor
```

### Step 3: Create a Virtual Environment

```bash
python -m venv venv
```

Activate the environment on Windows:

```bash
venv\Scripts\activate
```

On Linux:

```bash
source venv/bin/activate
```

### Step 4: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 5: Generate Dataset (Optional)

```bash
python src/generate_dataset.py
```

### Step 6: Train the Models

```bash
python src/train_model.py
```

### Step 7: Run the Application

```bash
python src/app.py
```

Open the following address in your browser:

```text
http://127.0.0.1:5000
```

**Important:** The commands above assume that the scripts have been updated to use the reorganized `src/`, `data/`, and `models/` paths. Update the file paths in the Python scripts before using this structure. Alternatively, run the application using the original project layout until that refactoring is complete.

## 12. Application Features

- LinPEAS output input.
- File upload for enumeration output.
- Automatic feature extraction.
- Machine learning-based classification.
- Top-five recommendation ranking.
- SHAP-based prediction explanations.
- Risk score calculation.
- Mitigation recommendations.
- Model evaluation comparison.

## 13. Research Limitations

The current implementation uses a controlled synthetic dataset. Although the model evaluation demonstrates the functionality of the classification pipeline, it does not establish generalization to arbitrary real-world Linux systems.

Future evaluation should include labelled enumeration outputs from authorized vulnerable virtual machines, manually verified ground-truth labels, and detailed per-class performance analysis.

## 14. Future Enhancements

- Expand the dataset using real and manually labelled Linux enumeration outputs.
- Improve feature extraction across different Linux distributions.
- Incorporate additional Linux misconfigurations and privilege escalation techniques.
- Improve model generalization and prediction reliability.
- Extend explainability and recommendation mechanisms.
- Evaluate the system using controlled penetration testing environments.

## 15. Security and Ethical Considerations

This project is developed exclusively for authorized cybersecurity research, educational use, and controlled penetration testing environments.

Users must obtain explicit permission before analyzing or testing any system.

The application displays suggested commands and security recommendations; it does not automatically execute privilege escalation commands on target systems.

---

**Project:** PrivEsc Advisor  
**Category:** Explainable Artificial Intelligence and Cybersecurity  
**Application:** Web-based Linux Privilege Escalation Recommendation System
