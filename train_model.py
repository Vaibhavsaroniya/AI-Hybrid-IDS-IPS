import pandas as pd
import joblib
import os

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

print("Loading training dataset...")

df = pd.read_csv("data/training_dataset.csv")

print("Dataset loaded!")
print("Dataset shape:", df.shape)

# Separate features and label
X = df.drop("Label", axis=1)
y = df["Label"]

print("\nFeatures:", X.shape[1])
print("Records:", X.shape[0])

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining records:", len(X_train))
print("Testing records:", len(X_test))

# Create Random Forest model
print("\nTraining Random Forest...")

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

os.makedirs("model", exist_ok=True)

joblib.dump(model, "model/intrusion_detection_model.pkl")

print("\nModel saved successfully!")
print("\nTraining completed!")

# Make predictions
print("\nTesting model...")

y_pred = model.predict(X_test)

# Accuracy
accuracy = accuracy_score(y_test, y_pred)

print("\nAccuracy:")
print(accuracy)

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))