import pandas as pd

print("Loading dataset...")

df = pd.read_csv("data/training_dataset.csv")

print("Dataset loaded!")
print("Shape:", df.shape)

# Columns we want to study
columns = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "SYN Flag Count",
    "RST Flag Count"
]

print("\nAnalyzing traffic characteristics...\n")

# Calculate average values for every traffic type
result = df.groupby("Label")[columns].mean()

print(result)