import time

port_scan_tracker = {}

PORT_SCAN_WINDOW = 10
PORT_SCAN_THRESHOLD = 8
ALERT_COOLDOWN = 10  # don't re-alert for the same source within this many seconds


def check_port_scan_event(src_ip, dst_port):
    current_time = time.time()

    if src_ip not in port_scan_tracker:
        port_scan_tracker[src_ip] = {
            "entries": [],        # list of (timestamp, port) tuples
            "last_alert_time": 0,
        }

    tracker = port_scan_tracker[src_ip]

    tracker["entries"].append((current_time, dst_port))

    # prune entries older than the window -- this now correctly drops
    # the PORT along with its timestamp, unlike the old version
    tracker["entries"] = [
        (t, p) for (t, p) in tracker["entries"]
        if current_time - t <= PORT_SCAN_WINDOW
    ]

    distinct_ports = {p for (_, p) in tracker["entries"]}

    if len(distinct_ports) >= PORT_SCAN_THRESHOLD:
        if current_time - tracker["last_alert_time"] >= ALERT_COOLDOWN:
            tracker["last_alert_time"] = current_time

            print()
            print("!" * 70)
            print("PORT SCAN DETECTED")
            print("Source IP:", src_ip)
            print("Distinct ports touched:", len(distinct_ports))
            print("Within window (s):", PORT_SCAN_WINDOW)
            print("!" * 70)

            return True

    return False
