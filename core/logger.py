# core/logger.py

import datetime
from core.config import LOG_FILE


def log(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {message}\n"

    with open(LOG_FILE, "a") as f:
        f.write(entry)
