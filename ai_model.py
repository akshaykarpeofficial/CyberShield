import pandas as pd
import joblib
import os

from sklearn.tree import DecisionTreeClassifier


# =========================================================
# MODEL FILE
# =========================================================

MODEL_FILE = "cybershield_ai_model.pkl"


# =========================================================
# TRAINING DATA
# =========================================================

data = pd.DataFrame([
    [0, 0, 0, 0, 0, "Normal Activity"],
    [1, 0, 0, 0, 0, "Normal Activity"],
    [2, 0, 0, 0, 0, "Normal Activity"],
    [3, 0, 0, 0, 0, "Normal Activity"],

    [5, 0, 0, 0, 1, "Brute Force Attack"],
    [7, 0, 0, 0, 1, "Brute Force Attack"],
    [8, 0, 0, 0, 1, "Brute Force Attack"],
    [10, 0, 0, 0, 1, "Brute Force Attack"],

    [1, 1, 0, 0, 0, "Suspicious Login"],
    [2, 1, 0, 0, 0, "Suspicious Login"],
    [3, 1, 0, 0, 0, "Suspicious Login"],

    [0, 0, 1, 0, 0, "Malware Activity"],
    [1, 0, 1, 0, 0, "Malware Activity"],
    [2, 0, 1, 0, 0, "Malware Activity"],

    [0, 0, 0, 1, 0, "SQL Injection Attack"],
    [1, 0, 0, 1, 0, "SQL Injection Attack"],
    [2, 0, 0, 1, 0, "SQL Injection Attack"]
], columns=[
    "failed_attempts",
    "suspicious_login",
    "malware",
    "sql_injection",
    "failed_status",
    "threat"
])


# =========================================================
# FEATURES AND TARGET
# =========================================================

X = data[
    [
        "failed_attempts",
        "suspicious_login",
        "malware",
        "sql_injection",
        "failed_status"
    ]
]

y = data["threat"]


# =========================================================
# TRAIN AI MODEL
# =========================================================

model = DecisionTreeClassifier(random_state=42)

model.fit(X, y)


# =========================================================
# SAVE MODEL
# =========================================================

joblib.dump(model, MODEL_FILE)


# =========================================================
# AI THREAT PREDICTION
# =========================================================

def predict_threat(failed_attempts, event_type, status):

    event_type = event_type.lower()
    status = status.upper()

    suspicious_login = 1 if event_type == "suspicious_login" else 0
    malware = 1 if event_type == "malware" else 0
    sql_injection = 1 if event_type == "sql_injection" else 0
    failed_status = 1 if status == "FAILED" else 0

    input_data = pd.DataFrame([
        {
            "failed_attempts": failed_attempts,
            "suspicious_login": suspicious_login,
            "malware": malware,
            "sql_injection": sql_injection,
            "failed_status": failed_status
        }
    ])

    prediction = model.predict(input_data)[0]

    # Risk Level
    if prediction == "Brute Force Attack":
        risk = "HIGH"

    elif prediction == "Malware Activity":
        risk = "CRITICAL"

    elif prediction == "SQL Injection Attack":
        risk = "CRITICAL"

    elif prediction == "Suspicious Login":
        risk = "MEDIUM"

    else:
        risk = "LOW"

    return prediction, risk


# =========================================================
# TEST
# =========================================================

if __name__ == "__main__":

    prediction, risk = predict_threat(
        8,
        "login",
        "FAILED"
    )

    print("================================")
    print(" CyberShield AI Threat Prediction")
    print("================================")

    print("AI Prediction :", prediction)
    print("Risk Level    :", risk)