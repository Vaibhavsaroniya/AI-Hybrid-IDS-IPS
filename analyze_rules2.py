import pandas as pd

print("Loading dataset...")

df = pd.read_csv("data/training_dataset.csv")

print("Dataset loaded!")
print("Shape:", df.shape)

columns = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "SYN Flag Count",
    "RST Flag Count"
]

print("\nTraffic statistics:\n")

for label in df["Label"].unique():

    print("\n" + "=" * 70)
    print("TRAFFIC TYPE:", label)
    print("=" * 70)

    subset = df[df["Label"] == label]

    for column in columns:

        values = subset[column]

        print(f"\n{column}")
        print(f"  Minimum : {values.min():.2f}")
        print(f"  Median  : {values.median():.2f}")
        print(f"  95%     : {values.quantile(0.95):.2f}")
        print(f"  Maximum : {values.max():.2f}")