import pandas as pd

from rule_engine import check_rules

df = pd.read_csv("data/training_dataset.csv")

sample = df.head(10)

for index, row in sample.iterrows():

    alerts = check_rules(row)

    print("=" * 50)
    print("Record:", index)
    print("Actual Label:", row["Label"])

    if alerts:
        print("Rule Engine: 🚨 SUSPICIOUS")
        print("Alerts:", alerts)
    else:
        print("Rule Engine: 🟢 NORMAL")