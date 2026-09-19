import pandas as pd
import os

folder = "Dataset/MachineLearningCSV/MachineLearningCVE"

files = [f for f in os.listdir(folder) if f.endswith(".csv")]

for file in files:
    print("\n" + "=" * 70)
    print("FILE:", file)
    print("=" * 70)

    file_path = os.path.join(folder, file)

    label_counts = {}

    for chunk in pd.read_csv(file_path, chunksize=50000, low_memory=False):
        labels = chunk[" Label"].value_counts()

        for label, count in labels.items():
            label_counts[label] = label_counts.get(label, 0) + count

    print("\nLabels:")
    
    for label, count in label_counts.items():
        print(f"{label}: {count}")