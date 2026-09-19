import pandas as pd
import os

folder = "Dataset/MachineLearningCSV/MachineLearningCVE"

files = [f for f in os.listdir(folder) if f.endswith(".csv")]

print("Checking datasets...\n")

for file in files:

    print("=" * 70)
    print("FILE:", file)
    print("=" * 70)

    file_path = os.path.join(folder, file)

    df = pd.read_csv(file_path, nrows=50000, low_memory=False)

    print("Rows checked:", len(df))

    print("Missing values:", df.isnull().sum().sum())

    print("Duplicate rows:", df.duplicated().sum())

    print("Infinite values:", df.isin([float("inf"), float("-inf")]).sum().sum())

    print()