import pandas as pd
import joblib

MODEL_FILE = "model/intrusion_detection_model.pkl"
DATA_FILE = "data/training_dataset.csv"

print("1. Loading AI model...")

model = joblib.load(MODEL_FILE)

print("2. AI model loaded successfully!")

print("3. Loading dataset...")

df = pd.read_csv(DATA_FILE)

print("4. Dataset loaded!")
print("Dataset shape:", df.shape)

print("\n5. Separating features and labels...")

X = df.drop("Label", axis=1)
y = df["Label"]

print("Features:", X.shape)
print("Labels:", y.shape)

print("\n6. Taking first 10 records...")

sample = X.head(10)
actual = y.head(10)

print("Sample created!")

print("\n7. Asking AI for predictions...")

predictions = model.predict(sample)

print("8. Predictions completed!")

print("\n" + "=" * 60)
print("RESULTS")
print("=" * 60)

for i in range(len(predictions)):
    print(f"\nRecord {i + 1}")
    print(f"Actual:      {actual.iloc[i]}")
    print(f"AI Prediction: {predictions[i]}")

print("\nPrediction test completed!")