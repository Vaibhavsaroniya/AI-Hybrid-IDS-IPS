import shutil
import time
import os

SOURCE = "logs/live_security_events.csv"
DEST = "/media/sf_AI-Hybrid-IDS-IPS/logs/live_security_events.csv"

print("Syncing", SOURCE, "->", DEST)
print("Press CTRL+C to stop.")

while True:
    try:
        if os.path.exists(SOURCE):
            shutil.copyfile(SOURCE, DEST)
    except Exception as e:
        print("Sync error:", e)
    time.sleep(2)
