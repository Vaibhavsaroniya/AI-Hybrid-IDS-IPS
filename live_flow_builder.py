from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import time
import joblib
import numpy as np
import csv
import os
from port_scan_tracker import check_port_scan_event
import threading

from flow_features import live_flow_to_features
from rule_engine import check_rules


# ============================================================
# CONFIGURATION
# ============================================================

MODEL_PATH = "model/intrusion_detection_model.pkl"

LOG_FILE = "logs/live_security_events.csv"

FLOW_TIMEOUT = 2


# ============================================================
# CREATE LOG DIRECTORY
# ============================================================

os.makedirs("logs", exist_ok=True)


# ============================================================
# CSV COLUMNS
# ============================================================

CSV_COLUMNS = [
    "Time",
    "Source",
    "Destination",
    "Protocol",
    "Source Port",
    "Destination Port",
    "AI Prediction",
    "AI Confidence",
    "AI Status",
    "Rule Alerts",
    "Rule Score",
    "Risk Score",
    "Severity",
    "Final Decision"
]


# ============================================================
# CREATE CSV IF IT DOES NOT EXIST
# ============================================================

if not os.path.exists(LOG_FILE):

    with open(
        LOG_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=CSV_COLUMNS
        )

        writer.writeheader()


# ============================================================
# LOAD AI MODEL
# ============================================================

print("=" * 70)
print("       LIVE HYBRID INTRUSION DETECTION SYSTEM")
print("=" * 70)

print()
print("1. Loading AI model...")

try:

    model = joblib.load(MODEL_PATH)

    print("AI model loaded successfully!")

except Exception as e:

    print("ERROR: Could not load AI model.")
    print(e)

    exit()


# ============================================================
# FLOW STORAGE
# ============================================================

flows = {}


# ============================================================
# CREATE FLOW KEY
# ============================================================

def get_flow_key(packet):

    if not packet.haslayer(IP):

        return None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    protocol = packet[IP].proto


    if packet.haslayer(TCP):

        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif packet.haslayer(UDP):

        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    else:

        src_port = 0
        dst_port = 0


    endpoint1 = (src_ip, src_port)
    endpoint2 = (dst_ip, dst_port)


    if endpoint1 <= endpoint2:

        return (
            endpoint1,
            endpoint2,
            protocol
        )

    else:

        return (
            endpoint2,
            endpoint1,
            protocol
        )


# ============================================================
# HYBRID DECISION
# ============================================================

def calculate_hybrid_decision(
    prediction,
    confidence,
    rule_alerts
):

    # AI considers everything except BENIGN as a threat

    ai_threat = str(prediction).upper() != "BENIGN"


    # Number of triggered rules

    rule_score = len(rule_alerts)


    # --------------------------------------------------------
    # AI + RULE AGREE
    # --------------------------------------------------------

    if ai_threat and rule_score > 0:

        risk_score = 100

        severity = "HIGH"

        final_decision = "HIGH CONFIDENCE THREAT"


    # --------------------------------------------------------
    # AI ONLY
    # --------------------------------------------------------

    elif ai_threat:

        risk_score = 100

        severity = "MEDIUM"

        final_decision = "AI DETECTED THREAT"


    # --------------------------------------------------------
    # RULE ONLY
    # --------------------------------------------------------

    elif rule_score > 0:

        risk_score = 50

        severity = "LOW"

        final_decision = "SUSPICIOUS - RULE TRIGGERED"


    # --------------------------------------------------------
    # NORMAL
    # --------------------------------------------------------

    else:

        risk_score = 0

        severity = "NONE"

        final_decision = "NORMAL"


    return (
        rule_score,
        risk_score,
        severity,
        final_decision
    )


# ============================================================
# SAVE SECURITY EVENT
# ============================================================

def save_security_event(
    flow,
    prediction,
    confidence,
    ai_status,
    rule_alerts,
    rule_score,
    risk_score,
    severity,
    final_decision
):

    with open(
        LOG_FILE,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=CSV_COLUMNS
        )

        writer.writerow({

            "Time":
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),

            "Source":
                flow.get("first_ip", ""),

            "Destination":
                flow.get("second_ip", ""),

            "Protocol":
                flow.get("protocol", ""),

            "Source Port":
                flow.get("first_port", 0),

            "Destination Port":
                flow.get("second_port", 0),

            "AI Prediction":
                prediction,

            "AI Confidence":
                round(confidence, 2),

            "AI Status":
                ai_status,

            "Rule Alerts":
                "; ".join(rule_alerts)
                if rule_alerts
                else "None",

            "Rule Score":
                rule_score,

            "Risk Score":
                risk_score,

            "Severity":
                severity,

            "Final Decision":
                final_decision
        })


# ============================================================
# LOG A CROSS-FLOW PORT SCAN ALERT
# ============================================================

def log_port_scan_alert(src_ip, dst_ip):
    with open(LOG_FILE, "a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=CSV_COLUMNS)
        writer.writerow({
            "Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Source": src_ip,
            "Destination": dst_ip,
            "Protocol": "MULTI",
            "Source Port": "",
            "Destination Port": "",
            "AI Prediction": "N/A",
            "AI Confidence": "",
            "AI Status": "N/A",
            "Rule Alerts": "Possible PortScan (multi-port, cross-flow)",
            "Rule Score": 1,
            "Risk Score": 100,
            "Severity": "HIGH",
            "Final Decision": "HIGH CONFIDENCE THREAT"
        })


# ============================================================
# ANALYZE ONE FLOW
# ============================================================

def analyze_flow(flow):

    try:

        # ====================================================
        # BASIC FLOW INFORMATION
        # ====================================================

        duration = (
            flow["last_time"]
            - flow["start_time"]
        )


        if duration <= 0:

            duration = 0.000001


        total_packets = (
            flow["forward_packets"]
            + flow["backward_packets"]
        )


        total_bytes = (
            flow["forward_bytes"]
            + flow["backward_bytes"]
        )


        bytes_per_second = (
            total_bytes / duration
        )


        packets_per_second = (
            total_packets / duration
        )


        # ====================================================
        # PREPARE FLOW FOR FEATURE EXTRACTION
        # ====================================================

        flow_for_model = dict(flow)


        flow_for_model["destination_port"] = (
            flow["second_port"]
        )


        flow_for_model["packet_sizes"] = (

            flow["forward_packet_sizes"]
            +
            flow["backward_packet_sizes"]

        )


        flow_for_model["bytes_per_second"] = (
            bytes_per_second
        )


        flow_for_model["packets_per_second"] = (
            packets_per_second
        )
        flow_for_model["duration"] = duration
        flow_for_model["forward_packet_times"] = flow.get("forward_packet_times", [])
        flow_for_model["backward_packet_times"] = flow.get("backward_packet_times", [])
        flow_for_model["all_packet_times"] = flow.get("packet_times", [])
        flow_for_model["init_win_forward"] = flow.get("init_win_forward")
        flow_for_model["init_win_backward"] = flow.get("init_win_backward")
        flow_for_model["act_data_pkt_fwd"] = flow.get("act_data_pkt_fwd", 0)
        flow_for_model["fwd_header_len_total"] = flow.get("fwd_header_len_total", 0)
        flow_for_model["bwd_header_len_total"] = flow.get("bwd_header_len_total", 0)
        flow_for_model["min_seg_size_forward"] = flow.get("min_seg_size_forward")
        flow_for_model["urg_count"] = flow.get("urg_count", 0)
        flow_for_model["cwe_count"] = flow.get("cwe_count", 0)
        flow_for_model["ece_count"] = flow.get("ece_count", 0)


        # ====================================================
        # CREATE 78 FEATURES
        # ====================================================

        features = live_flow_to_features(flow_for_model)

        


        if features.shape != (1, 78):

            print()
            print("ERROR: Feature shape is incorrect!")
            print("Expected: (1, 78)")
            print("Received:", features.shape)

            return


        # ====================================================
        # AI PREDICTION
        # ====================================================

        prediction = model.predict(
            features
        )[0]


        probabilities = model.predict_proba(
            features
        )[0]


        confidence = (
            np.max(probabilities)
            * 100
        )


        # ====================================================
        # RULE ENGINE
        # ====================================================

        rule_alerts = check_rules(
            features.iloc[0]
        )


        # ====================================================
        # HYBRID DECISION
        # ====================================================

        (
            rule_score,
            risk_score,
            severity,
            final_decision

        ) = calculate_hybrid_decision(

            prediction,
            confidence,
            rule_alerts

        )


        # ====================================================
        # AI STATUS
        # ====================================================

        if str(prediction).upper() == "BENIGN":

            ai_status = "NORMAL"

        else:

            ai_status = "THREAT"


        # ====================================================
        # DISPLAY FLOW
        # ====================================================

        print()
        print("=" * 70)
        print("                 LIVE HYBRID ANALYSIS")
        print("=" * 70)

        print()

        print(
            "Time:",
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )

        print()

        print("Flow:")

        print(
            f"{flow['first_ip']}:{flow['first_port']}"
            f"  <-->  "
            f"{flow['second_ip']}:{flow['second_port']}"
        )

        print()

        print(
            "Protocol:",
            flow["protocol"]
        )

        print()

        print(
            "Forward packets :",
            flow["forward_packets"]
        )

        print(
            "Backward packets:",
            flow["backward_packets"]
        )

        print(
            "Forward bytes   :",
            flow["forward_bytes"]
        )

        print(
            "Backward bytes  :",
            flow["backward_bytes"]
        )

        print(
            "Total packets   :",
            total_packets
        )

        print(
            "Total bytes     :",
            total_bytes
        )

        print(
            "Duration        :",
            round(duration, 4),
            "seconds"
        )

        print(
            "Bytes/sec       :",
            round(bytes_per_second, 2)
        )

        print(
            "Packets/sec     :",
            round(packets_per_second, 2)
        )


        # ====================================================
        # AI RESULT
        # ====================================================

        print()
        print("-" * 70)
        print("                     AI RESULT")
        print("-" * 70)

        print(
            "AI Prediction :",
            prediction
        )

        print(
            "AI Confidence :",
            round(confidence, 2),
            "%"
        )

        print(
            "AI Status     :",
            ai_status
        )


        # ====================================================
        # RULE RESULT
        # ====================================================

        print()
        print("-" * 70)
        print("                    RULE ENGINE")
        print("-" * 70)

        if rule_alerts:

            print(
                "Rule Alerts :",
                rule_alerts
            )

        else:

            print(
                "Rule Alerts : None"
            )

        print(
            "Rule Score  :",
            rule_score
        )


        # ====================================================
        # HYBRID RESULT
        # ====================================================

        print()
        print("-" * 70)
        print("                   HYBRID RESULT")
        print("-" * 70)

        print(
            "Risk Score     :",
            risk_score
        )

        print(
            "Severity       :",
            severity
        )

        print(
            "Final Decision :",
            final_decision
        )

        print("-" * 70)


        # ====================================================
        # SAVE TO CSV
        # ====================================================

        save_security_event(

            flow,

            prediction,

            confidence,

            ai_status,

            rule_alerts,

            rule_score,

            risk_score,

            severity,

            final_decision
        )


        print()
        print(
            "✓ Security event saved to:"
        )

        print(LOG_FILE)


    except Exception as e:

        print()
        print("=" * 70)
        print("ERROR DURING HYBRID ANALYSIS")
        print("=" * 70)

        print(e)

        print("=" * 70)


# ============================================================
# PROCESS EXPIRED FLOWS
# ============================================================

def process_expired_flows():

    current_time = time.time()

    expired_flows = []


    for flow_key, flow in list(flows.items()):

        idle_time = (
            current_time
            - flow["last_time"]
        )


        if idle_time >= FLOW_TIMEOUT:

            expired_flows.append(
                flow_key
            )


    for flow_key in expired_flows:

        flow = flows[flow_key]

        analyze_flow(flow)

        del flows[flow_key]


# ============================================================
# PACKET CALLBACK
# ============================================================

def packet_callback(packet):

    if not packet.haslayer(IP):

        return


    flow_key = get_flow_key(packet)


    if flow_key is None:

        return


    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    packet_size = len(packet)


    # ========================================================
    # PROTOCOL / PORTS
    # ========================================================

    if packet.haslayer(TCP):

        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        protocol = "TCP"


    elif packet.haslayer(UDP):

        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

        protocol = "UDP"


    else:

        src_port = 0
        dst_port = 0

        protocol = str(
            packet[IP].proto
        )

    if packet.haslayer(TCP) or packet.haslayer(UDP):
        if check_port_scan_event(src_ip, dst_port):
            log_port_scan_alert(src_ip, dst_ip)

    current_time = time.time()


    # ========================================================
    # CREATE NEW FLOW
    # ========================================================

    if flow_key not in flows:

        flows[flow_key] = {

            "first_ip":
                src_ip,

            "first_port":
                src_port,

            "second_ip":
                dst_ip,

            "second_port":
                dst_port,

            "protocol":
                protocol,

            "start_time":
                current_time,

            "last_time":
                current_time,

            "forward_packets":
                0,

            "backward_packets":
                0,

            "forward_bytes":
                0,

            "backward_bytes":
                0,

            "forward_packet_sizes":
                [],

            "backward_packet_sizes":
                [],

            "syn_count":
                0,

            "rst_count":
                0,

            "fin_count":
                0,

            "psh_count":
                0,

            "ack_count":
                0,

            "packet_times":
                [],

            "forward_packet_times":
                [],

            "backward_packet_times":
                [],

            "init_win_forward":
                None,

            "init_win_backward":
                None,

            "act_data_pkt_fwd":
                0,

            "fwd_header_len_total":
                0,

            "bwd_header_len_total":
                0,

            "min_seg_size_forward":
                None,

            "urg_count":
                0,

            "cwe_count":
                0,

            "ece_count":
                0,

            "port_scan_detected":
                False
        }


    flow = flows[flow_key]


    flow["last_time"] = (
        current_time
    )


    flow["packet_times"].append(
        current_time
    )


    # ========================================================
    # DETERMINE DIRECTION
    # ========================================================

    if (

        src_ip == flow["first_ip"]

        and

        src_port == flow["first_port"]

    ):

        # FORWARD

        flow["forward_packets"] += 1

        flow["forward_bytes"] += (
            packet_size
        )

        flow[
            "forward_packet_sizes"
        ].append(
            packet_size
        )

        flow["forward_packet_times"].append(current_time)

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            header_len = tcp_layer.dataofs * 4 if tcp_layer.dataofs else 20
            flow["fwd_header_len_total"] += header_len

            if flow["min_seg_size_forward"] is None or header_len < flow["min_seg_size_forward"]:
                flow["min_seg_size_forward"] = header_len

            if flow["init_win_forward"] is None:
                flow["init_win_forward"] = tcp_layer.window

            payload_len = len(bytes(tcp_layer.payload))
            if payload_len > 0:
                flow["act_data_pkt_fwd"] += 1


    else:

        # BACKWARD

        flow["backward_packets"] += 1

        flow["backward_bytes"] += (
            packet_size
        )

        flow[
            "backward_packet_sizes"
        ].append(
            packet_size
        )

        flow["backward_packet_times"].append(current_time)

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            header_len = tcp_layer.dataofs * 4 if tcp_layer.dataofs else 20
            flow["bwd_header_len_total"] += header_len

            if flow["init_win_backward"] is None:
                flow["init_win_backward"] = tcp_layer.window


    # ========================================================
    # TCP FLAGS
    # ========================================================

    if packet.haslayer(TCP):

        flags = packet[TCP].flags


        if flags & 0x02:

            flow["syn_count"] += 1


        if flags & 0x04:

            flow["rst_count"] += 1


        if flags & 0x01:

            flow["fin_count"] += 1


        if flags & 0x08:

            flow["psh_count"] += 1


        if flags & 0x10:

            flow["ack_count"] += 1

        if flags & 0x20:

            flow["urg_count"] += 1

        if flags & 0x40:

            flow["ece_count"] += 1

        if flags & 0x80:

            flow["cwe_count"] += 1


    # ========================================================
    # PROCESS OLD FLOWS
    # ========================================================

    # process_expired_flows()  # now handled by background thread


# ============================================================
# START SYSTEM
# ============================================================

print()
def flow_flush_worker():
    while True:
        time.sleep(1)
        process_expired_flows()

threading.Thread(target=flow_flush_worker, daemon=True).start()

print("2. Starting live packet capture...")
print()

print(
    "Generate normal traffic by browsing the internet."
)

print(
    "Open websites, YouTube, etc."
)

print()

print(
    "A flow is analyzed after",
    FLOW_TIMEOUT,
    "seconds of inactivity."
)

print()

print("Results will be saved automatically to:")

print(
    LOG_FILE
)

print()

print("Press CTRL + C to stop.")

print()

print("=" * 70)


# ============================================================
# START PACKET CAPTURE
# ============================================================

try:

    sniff(
        iface="enp0s8",
        prn=packet_callback,
        store=False
    )


except KeyboardInterrupt:

    print()
    print()
    print("=" * 70)
    print("Stopping packet capture...")
    print("=" * 70)

    print()

    # Analyze remaining flows

    if flows:

        print(
            "Analyzing remaining flows..."
        )

        print()

        for flow in list(
            flows.values()
        ):

            analyze_flow(flow)

    else:

        print(
            "No remaining flows."
        )


    flows.clear()

    print()

    print("=" * 70)
    print("LIVE HYBRID DETECTION STOPPED")
    print("=" * 70)