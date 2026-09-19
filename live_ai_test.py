import joblib
import numpy as np

from flow_features import create_features


print("=" * 70)
print("LIVE AI INTRUSION DETECTION TEST")
print("=" * 70)


# ============================================================
# 1. LOAD AI MODEL
# ============================================================

print("\n1. Loading AI model...")

model = joblib.load(
    "model/intrusion_detection_model.pkl"
)

print("AI model loaded successfully!")


# ============================================================
# 2. CREATE A TEST LIVE FLOW
# ============================================================

print("\n2. Creating test live flow...")

test_flow = {

    "destination_port": 443,

    "duration": 5.0,

    "forward_packets": 100,

    "backward_packets": 80,

    "forward_bytes": 50000,

    "backward_bytes": 40000,

    "forward_packet_sizes": [
        60,
        100,
        500,
        1200,
        1500
    ],

    "backward_packet_sizes": [
        60,
        100,
        500,
        1000
    ],

    "syn_count": 1,

    "rst_count": 0,

    "fin_count": 0,

    "psh_count": 0,

    "ack_count": 1
}


print("Test flow created!")


# ============================================================
# 3. CONVERT FLOW → 78 FEATURES
# ============================================================

print("\n3. Converting flow into 78 features...")

features = create_features(test_flow)

print(
    "Feature shape:",
    features.shape
)


# ============================================================
# 4. ASK RANDOM FOREST FOR PREDICTION
# ============================================================

print("\n4. Asking AI for prediction...")

prediction = model.predict(features)[0]


# ============================================================
# 5. GET AI CONFIDENCE
# ============================================================

probabilities = model.predict_proba(features)[0]

confidence = np.max(probabilities) * 100


# ============================================================
# 6. DISPLAY RESULT
# ============================================================

print("\n" + "=" * 70)

print("AI DETECTION RESULT")

print("=" * 70)

print(
    "AI Prediction :",
    prediction
)

print(
    "AI Confidence :",
    f"{confidence:.2f}%"
)

print("=" * 70)