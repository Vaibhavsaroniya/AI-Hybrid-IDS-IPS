import joblib

MODEL_PATH = "model/intrusion_detection_model.pkl"

print("=" * 70)
print("CHECKING MODEL FEATURES")
print("=" * 70)

model = joblib.load(MODEL_PATH)

print("\nNumber of features expected by model:")
print(len(model.feature_names_in_))

print("\nExact feature names:")
for i, feature in enumerate(model.feature_names_in_):
    print(i, repr(feature))