import pandas as pd
import numpy as np


# ============================================================
# EXACT 78 FEATURES EXPECTED BY THE TRAINED MODEL
# ============================================================

FEATURE_COLUMNS = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min"
]


# ============================================================
# CHECK FEATURE COUNT
# ============================================================

if len(FEATURE_COLUMNS) != 78:
    raise ValueError(
        f"FEATURE_COLUMNS must contain exactly 78 features. "
        f"Found {len(FEATURE_COLUMNS)}."
    )


# ============================================================
# HELPER FUNCTIONS FOR TIMING-BASED FEATURES
# ============================================================

def _iat_stats(times):
    """Given a sorted list of packet timestamps, returns
    (total, mean, std, max, min) of inter-arrival times, in seconds."""
    if len(times) < 2:
        return 0.0, 0.0, 0.0, 0.0, 0.0
    times = sorted(times)
    diffs = [b - a for a, b in zip(times, times[1:])]
    return (
        sum(diffs),
        float(np.mean(diffs)),
        float(np.std(diffs)) if len(diffs) > 1 else 0.0,
        max(diffs),
        min(diffs),
    )


def _active_idle_periods(times, idle_threshold=1.0):
    """Splits a sorted list of packet timestamps into active bursts
    and idle gaps, using idle_threshold seconds as the cutoff between
    'still active' and 'went idle'. Returns (active_durations, idle_durations)."""
    if len(times) < 2:
        return [], []
    times = sorted(times)
    active_durations = []
    idle_durations = []
    segment_start = times[0]
    last_time = times[0]
    for t in times[1:]:
        gap = t - last_time
        if gap >= idle_threshold:
            active_durations.append(last_time - segment_start)
            idle_durations.append(gap)
            segment_start = t
        last_time = t
    active_durations.append(last_time - segment_start)
    return active_durations, idle_durations


# ============================================================
# LIVE FLOW -> 78 FEATURES
# ============================================================

def live_flow_to_features(flow):

    # Create exactly 78 features.
    # Features that are not currently collected by Scapy
    # remain 0.0.

    features = {
        column: 0.0
        for column in FEATURE_COLUMNS
    }

    # ========================================================
    # BASIC FLOW INFORMATION
    # ========================================================

    destination_port = flow.get(
        "destination_port",
        0
    )

    duration = flow.get(
        "duration",
        0
    )

    fwd_packets = flow.get(
        "forward_packets",
        0
    )

    bwd_packets = flow.get(
        "backward_packets",
        0
    )

    fwd_bytes = flow.get(
        "forward_bytes",
        0
    )

    bwd_bytes = flow.get(
        "backward_bytes",
        0
    )

    # ========================================================
    # BASIC FEATURES
    # ========================================================

    features["Destination Port"] = destination_port

    # CICIDS2017 uses microseconds.
    features["Flow Duration"] = (
        duration * 1_000_000
    )

    features["Total Fwd Packets"] = (
        fwd_packets
    )

    features["Total Backward Packets"] = (
        bwd_packets
    )

    features["Total Length of Fwd Packets"] = (
        fwd_bytes
    )

    features["Total Length of Bwd Packets"] = (
        bwd_bytes
    )

    # ========================================================
    # PACKET SIZE LISTS
    # ========================================================

    fwd_sizes = flow.get(
        "forward_packet_sizes",
        []
    )

    bwd_sizes = flow.get(
        "backward_packet_sizes",
        []
    )

    if fwd_sizes is None:
        fwd_sizes = []

    if bwd_sizes is None:
        bwd_sizes = []

    fwd_sizes = list(fwd_sizes)
    bwd_sizes = list(bwd_sizes)

    # ========================================================
    # FORWARD PACKET STATISTICS
    # ========================================================

    if fwd_sizes:

        features["Fwd Packet Length Max"] = (
            max(fwd_sizes)
        )

        features["Fwd Packet Length Min"] = (
            min(fwd_sizes)
        )

        features["Fwd Packet Length Mean"] = (
            np.mean(fwd_sizes)
        )

        if len(fwd_sizes) > 1:

            features["Fwd Packet Length Std"] = (
                np.std(fwd_sizes)
            )

    # ========================================================
    # BACKWARD PACKET STATISTICS
    # ========================================================

    if bwd_sizes:

        features["Bwd Packet Length Max"] = (
            max(bwd_sizes)
        )

        features["Bwd Packet Length Min"] = (
            min(bwd_sizes)
        )

        features["Bwd Packet Length Mean"] = (
            np.mean(bwd_sizes)
        )

        if len(bwd_sizes) > 1:

            features["Bwd Packet Length Std"] = (
                np.std(bwd_sizes)
            )

    # ========================================================
    # FLOW RATES
    # ========================================================

    if duration > 0:

        total_bytes = (
            fwd_bytes + bwd_bytes
        )

        total_packets = (
            fwd_packets + bwd_packets
        )

        features["Flow Bytes/s"] = (
            total_bytes / duration
        )

        features["Flow Packets/s"] = (
            total_packets / duration
        )

        features["Fwd Packets/s"] = (
            fwd_packets / duration
        )

        features["Bwd Packets/s"] = (
            bwd_packets / duration
        )

    # ========================================================
    # ALL PACKET STATISTICS
    # ========================================================

    all_sizes = (
        fwd_sizes + bwd_sizes
    )

    if all_sizes:

        features["Min Packet Length"] = (
            min(all_sizes)
        )

        features["Max Packet Length"] = (
            max(all_sizes)
        )

        features["Packet Length Mean"] = (
            np.mean(all_sizes)
        )

        if len(all_sizes) > 1:

            features["Packet Length Std"] = (
                np.std(all_sizes)
            )

            features["Packet Length Variance"] = (
                np.var(all_sizes)
            )

    # ========================================================
    # TCP FLAGS
    # ========================================================

    features["FIN Flag Count"] = flow.get(
        "fin_count",
        0
    )

    features["SYN Flag Count"] = flow.get(
        "syn_count",
        0
    )

    features["RST Flag Count"] = flow.get(
        "rst_count",
        0
    )

    features["PSH Flag Count"] = flow.get(
        "psh_count",
        0
    )

    features["ACK Flag Count"] = flow.get(
        "ack_count",
        0
    )

    # ========================================================
    # DOWN / UP RATIO
    # ========================================================

    if fwd_packets > 0:

        features["Down/Up Ratio"] = (
            bwd_packets / fwd_packets
        )

    # ========================================================
    # AVERAGE PACKET SIZE
    # ========================================================

    total_packets = (
        fwd_packets + bwd_packets
    )

    total_bytes = (
        fwd_bytes + bwd_bytes
    )

    if total_packets > 0:

        features["Average Packet Size"] = (
            total_bytes / total_packets
        )

    # ========================================================
    # SEGMENT SIZE
    # ========================================================

    if fwd_sizes:

        features["Avg Fwd Segment Size"] = (
            np.mean(fwd_sizes)
        )

    if bwd_sizes:

        features["Avg Bwd Segment Size"] = (
            np.mean(bwd_sizes)
        )

    # ========================================================
    # SUBFLOW INFORMATION
    # ========================================================

    features["Subflow Fwd Packets"] = (
        fwd_packets
    )

    features["Subflow Fwd Bytes"] = (
        fwd_bytes
    )

    features["Subflow Bwd Packets"] = (
        bwd_packets
    )

    features["Subflow Bwd Bytes"] = (
        bwd_bytes
    )

    # ========================================================
    # INTER-ARRIVAL TIME (IAT) FEATURES
    # ========================================================

    all_times = flow.get("all_packet_times", [])
    fwd_times = flow.get("forward_packet_times", [])
    bwd_times = flow.get("backward_packet_times", [])

    flow_total, flow_mean, flow_std, flow_max, flow_min = _iat_stats(all_times)
    features["Flow IAT Mean"] = flow_mean * 1_000_000
    features["Flow IAT Std"] = flow_std * 1_000_000
    features["Flow IAT Max"] = flow_max * 1_000_000
    features["Flow IAT Min"] = flow_min * 1_000_000

    fwd_total, fwd_mean, fwd_std, fwd_max, fwd_min = _iat_stats(fwd_times)
    features["Fwd IAT Total"] = fwd_total * 1_000_000
    features["Fwd IAT Mean"] = fwd_mean * 1_000_000
    features["Fwd IAT Std"] = fwd_std * 1_000_000
    features["Fwd IAT Max"] = fwd_max * 1_000_000
    features["Fwd IAT Min"] = fwd_min * 1_000_000

    bwd_total, bwd_mean, bwd_std, bwd_max, bwd_min = _iat_stats(bwd_times)
    features["Bwd IAT Total"] = bwd_total * 1_000_000
    features["Bwd IAT Mean"] = bwd_mean * 1_000_000
    features["Bwd IAT Std"] = bwd_std * 1_000_000
    features["Bwd IAT Max"] = bwd_max * 1_000_000
    features["Bwd IAT Min"] = bwd_min * 1_000_000

    # ========================================================
    # ACTIVE / IDLE FEATURES
    # ========================================================

    active_durations, idle_durations = _active_idle_periods(all_times)

    if active_durations:
        features["Active Mean"] = float(np.mean(active_durations)) * 1_000_000
        features["Active Std"] = (float(np.std(active_durations)) * 1_000_000
                                   if len(active_durations) > 1 else 0.0)
        features["Active Max"] = max(active_durations) * 1_000_000
        features["Active Min"] = min(active_durations) * 1_000_000

    if idle_durations:
        features["Idle Mean"] = float(np.mean(idle_durations)) * 1_000_000
        features["Idle Std"] = (float(np.std(idle_durations)) * 1_000_000
                                 if len(idle_durations) > 1 else 0.0)
        features["Idle Max"] = max(idle_durations) * 1_000_000
        features["Idle Min"] = min(idle_durations) * 1_000_000

    # ========================================================
    # HEADER LENGTH / WINDOW SIZE / SEGMENT FEATURES
    # ========================================================

    features["Fwd Header Length"] = flow.get("fwd_header_len_total", 0)
    features["Fwd Header Length.1"] = flow.get("fwd_header_len_total", 0)
    features["Bwd Header Length"] = flow.get("bwd_header_len_total", 0)

    init_win_fwd = flow.get("init_win_forward")
    features["Init_Win_bytes_forward"] = init_win_fwd if init_win_fwd is not None else 0

    init_win_bwd = flow.get("init_win_backward")
    features["Init_Win_bytes_backward"] = init_win_bwd if init_win_bwd is not None else 0

    features["act_data_pkt_fwd"] = flow.get("act_data_pkt_fwd", 0)

    min_seg = flow.get("min_seg_size_forward")
    features["min_seg_size_forward"] = min_seg if min_seg is not None else 0

    features["CWE Flag Count"] = flow.get("cwe_count", 0)
    features["ECE Flag Count"] = flow.get("ece_count", 0)

    # ========================================================
    # CLEAN INVALID VALUES
    # ========================================================

    for column in FEATURE_COLUMNS:

        value = features[column]

        if not np.isfinite(value):

            features[column] = 0.0

    # ========================================================
    # CREATE DATAFRAME
    # ========================================================

    df = pd.DataFrame(
        [features],
        columns=FEATURE_COLUMNS
    )

    return df


# ============================================================
# COMPATIBILITY FUNCTION
# ============================================================
#
# live_hybrid_detector.py and live_flow_builder.py currently
# use:
#
#     from flow_features import create_features
#
# Therefore this function MUST exist.
# ============================================================

def create_features(flow):

    return live_flow_to_features(flow)


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    test_flow = {

        "destination_port": 443,

        "duration": 5.0,

        "forward_packets": 100,

        "backward_packets": 80,

        "forward_bytes": 50000,

        "backward_bytes": 40000,

        "forward_packet_sizes": [
            60,
            100,
            500,
            1200,
            1500
        ],

        "backward_packet_sizes": [
            60,
            100,
            500,
            1000
        ],

        "syn_count": 1,

        "rst_count": 0,

        "fin_count": 0,

        "psh_count": 0,

        "ack_count": 1
    }

    df = live_flow_to_features(
        test_flow
    )

    print("=" * 70)
    print("LIVE FLOW FEATURE TEST")
    print("=" * 70)

    print()

    print(
        "Number of features:",
        len(df.columns)
    )

    print(
        "Feature shape:",
        df.shape
    )

    print()

    print("First features:")

    print(
        df.iloc[0, :15]
    )

    print()

    print(
        "Feature extraction successful!"
    )

    print()

    print(
        "All 78 features present:",
        len(df.columns) == 78
    )

    print(
        "Feature names exactly match expected model:",
        list(df.columns) == FEATURE_COLUMNS
    )