import pandas as pd

file = "Dataset/MachineLearningCSV/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv"

print("Loading dataset...")

df = pd.read_csv(file)

print("\nDataset loaded successfully!")

print("\nDataset size:")
print(df.shape)

print("\nTraffic types:")
print(df[" Label"].value_counts())