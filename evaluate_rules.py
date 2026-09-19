import pandas as pd

print("Loading dataset...")

df = pd.read_csv("data/training_dataset.csv")

print("Dataset loaded!")
print("Total records:", len(df))


def rule_portscan(row):
    return (
        row["Flow Duration"] <= 100
        and row["Total Fwd Packets"] <= 1
    )


def rule_ssh_patator(row):
    return (
        row["Total Fwd Packets"] >= 20
        and row["Total Backward Packets"] >= 30
    )


print("\nTesting Rule 1: Possible PortScan")

portscan_matches = df.apply(rule_portscan, axis=1)

print("\nTraffic matched by Rule 1:")
print(df.loc[portscan_matches, "Label"].value_counts())


print("\n" + "=" * 60)

print("\nTesting Rule 2: Possible SSH-Patator")

ssh_matches = df.apply(rule_ssh_patator, axis=1)

print("\nTraffic matched by Rule 2:")
print(df.loc[ssh_matches, "Label"].value_counts())