def check_rules(row):
    """
    Independent heuristic detection layer. Operates on the same feature
    row (dict or pandas Series) that gets passed to the ML model, so
    column names must match exactly what live_flow_to_features() produces.
    """
    alerts = []

    # Rule 1: Possible Port Scan
    if (
        row["Total Fwd Packets"] >= 5
        and row["Total Backward Packets"] <= 1
        and row["Flow Duration"] <= 3_000_000
    ):
        alerts.append("Possible PortScan")

    # Rule 2: Possible SSH Brute Force (port 22 specifically)
    if (
        row["Total Fwd Packets"] >= 20
        and row["Total Backward Packets"] >= 20
        and row.get("Destination Port", None) == 22
    ):
        alerts.append("Possible SSH-Patator")

    # Rule 3: Possible SYN Flood
    if (
        row["SYN Flag Count"] >= 10
        and row["ACK Flag Count"] <= 2
        and row["Total Fwd Packets"] >= 10
    ):
        alerts.append("Possible SYN Flood")

    # Rule 4: Possible High-Volume DoS
    if (
        row["Flow Packets/s"] >= 1000
        and row["Total Fwd Packets"] >= 50
    ):
        alerts.append("Possible High Volume DoS")

    return alerts
