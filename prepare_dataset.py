import pandas as pd
import os

INPUT_FOLDER = "Dataset/MachineLearningCSV/MachineLearningCVE"
OUTPUT_FILE = "data/training_dataset.csv"

# Attack types we want in our first model
SELECTED_LABELS = [
    "BENIGN",
    "DDoS",
    "PortScan",
    "DoS Hulk",
    "FTP-Patator",
    "SSH-Patator"
]

# Maximum number of records we keep for each class
MAX_PER_CLASS = 20000

files = [f for f in os.listdir(INPUT_FOLDER) if f.endswith(".csv")]

all_data = []

print("Starting dataset preparation...\n")

for file in files:

    print("=" * 70)
    print("Processing:", file)
    print("=" * 70)

    file_path = os.path.join(INPUT_FOLDER, file)

    for chunk in pd.read_csv(
        file_path,
        chunksize=50000,
        low_memory=False
    ):

        # Remove spaces from column names
        chunk.columns = chunk.columns.str.strip()

        # Keep only the attack classes we selected
        chunk = chunk[chunk["Label"].isin(SELECTED_LABELS)]

        if len(chunk) > 0:
            all_data.append(chunk)

        print("Collected:", len(chunk), "selected records")

# Combine everything
print("\nCombining data...")

df = pd.concat(all_data, ignore_index=True)

print("Records before cleaning:", len(df))

# Replace infinite values with missing values
df = df.replace([float("inf"), float("-inf")], pd.NA)

# Remove rows containing missing values
df = df.dropna()

# Remove duplicate rows
df = df.drop_duplicates()

print("Records after cleaning:", len(df))

# Balance the dataset
print("\nBalancing classes...")

balanced_data = []

for label in SELECTED_LABELS:

    class_data = df[df["Label"] == label]

    if len(class_data) > MAX_PER_CLASS:
        class_data = class_data.sample(
            n=MAX_PER_CLASS,
            random_state=42
        )

    balanced_data.append(class_data)

    print(label, ":", len(class_data))

# Combine balanced classes
final_df = pd.concat(
    balanced_data,
    ignore_index=True
)

# Shuffle the dataset
final_df = final_df.sample(
    frac=1,
    random_state=42
).reset_index(drop=True)

# Create output folder if needed
os.makedirs("data", exist_ok=True)

# Save
final_df.to_csv(
    OUTPUT_FILE,
    index=False
)

print("\n" + "=" * 70)
print("DATASET PREPARATION COMPLETE!")
print("=" * 70)

print("\nFinal dataset size:")
print(final_df.shape)

print("\nFinal class distribution:")
print(final_df["Label"].value_counts())

print("\nSaved to:")
print(OUTPUT_FILE)