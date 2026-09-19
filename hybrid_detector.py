import pandas as pd
import joblib
from datetime import datetime
import csv
import os

from rule_engine import check_rules


print("=" * 70)
print("       HYBRID INTRUSION DETECTION & PREVENTION SYSTEM")
print("=" * 70)


# ---------------------------------------------------------
# 1. Load AI model
# ---------------------------------------------------------

print("\n1. Loading AI model...")

model = joblib.load("model/intrusion_detection_model.pkl")

print("AI model loaded successfully!")


# ---------------------------------------------------------
# 2. Load dataset
# ---------------------------------------------------------

print("\n2. Loading test data...")

df = pd.read_csv("data/training_dataset.csv")

print("Dataset loaded!")
print("Dataset shape:", df.shape)


# ---------------------------------------------------------
# 3. Separate features and labels
# ---------------------------------------------------------

X = df.drop("Label", axis=1)
y = df["Label"]


# ---------------------------------------------------------
# 4. Take first 10 records
# ---------------------------------------------------------

sample = df.head(10)

X_sample = sample.drop("Label", axis=1)


# ---------------------------------------------------------
# 5. AI predictions
# ---------------------------------------------------------

print("\n3. Asking AI for predictions...")

ai_predictions = model.predict(X_sample)

ai_probabilities = model.predict_proba(X_sample)

print("AI predictions completed!")


# ---------------------------------------------------------
# 6. Prepare security log
# ---------------------------------------------------------

print("\n4. Running Hybrid Detection...\n")

# Create logs folder
os.makedirs("logs", exist_ok=True)

log_file = "logs/security_events.csv"


# Create a NEW log file for this run
with open(log_file, "w", newline="") as file:

    writer = csv.writer(file)

    writer.writerow([
        "Time",
        "Record",
        "Actual Label",
        "AI Prediction",
        "AI Confidence",
        "Rule Alerts",
        "Rule Score",
        "Risk Score",
        "Severity",
        "Final Decision"
    ])


# ---------------------------------------------------------
# 7. Hybrid Detection
# ---------------------------------------------------------

for i in range(len(sample)):

    row = sample.iloc[i]

    actual_label = row["Label"]

    ai_prediction = ai_predictions[i]

    # AI confidence
    ai_confidence = max(ai_probabilities[i]) * 100

    # Run rule engine
    rule_alerts = check_rules(row)

    # Rule score
    if rule_alerts:
        rule_score = 1
    else:
        rule_score = 0


    # -----------------------------------------------------
    # Determine final decision
    # -----------------------------------------------------

    if ai_prediction != "BENIGN" and rule_alerts:

        decision = "HIGH CONFIDENCE THREAT"
        severity = "HIGH"

        risk_score = min(100, ai_confidence + 10)

    elif ai_prediction != "BENIGN":

        decision = "AI DETECTED THREAT"
        severity = "MEDIUM"

        risk_score = ai_confidence

    elif rule_alerts:

        decision = "SUSPICIOUS - RULE TRIGGERED"
        severity = "LOW"

        risk_score = 50

    else:

        decision = "NORMAL"
        severity = "NONE"

        risk_score = 0


    # -----------------------------------------------------
    # Timestamp
    # -----------------------------------------------------

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")


    # -----------------------------------------------------
    # Display result
    # -----------------------------------------------------

    print("=" * 70)

    print("SECURITY EVENT")

    print("Time:", timestamp)

    print("Record:", i)

    print("Actual Label:", actual_label)

    print("AI Prediction:", ai_prediction)

    print(f"AI Confidence: {ai_confidence:.2f}%")

    print(
        "Rule Alerts:",
        rule_alerts if rule_alerts else "None"
    )

    print("Rule Score:", rule_score)

    print(f"Hybrid Risk Score: {risk_score:.2f}")

    print("Severity:", severity)

    print("FINAL DECISION:", decision)


    # -----------------------------------------------------
    # Save this event to CSV
    # -----------------------------------------------------

    with open(log_file, "a", newline="") as file:

        writer = csv.writer(file)

        writer.writerow([
            timestamp,
            i,
            actual_label,
            ai_prediction,
            round(ai_confidence, 2),
            ", ".join(rule_alerts) if rule_alerts else "None",
            rule_score,
            round(risk_score, 2),
            severity,
            decision
        ])


# ---------------------------------------------------------
# 8. Finished
# ---------------------------------------------------------

print("\n" + "=" * 70)
print("HYBRID DETECTION COMPLETED")
print("=" * 70)

print("\nSecurity events saved to:")
print(log_file)