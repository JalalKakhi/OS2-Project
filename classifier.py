import json
import os
import re
import time
from prometheus_client import Counter, start_http_server

LOG_FILE = os.getenv("NGINX_ACCESS_LOG", "/var/log/nginx/access.log")
STATUS_RE = re.compile(r'"\s(?P<status>\d{3})\s')

# Rule-based counters. No ML or training is used: each metric is incremented
# only when a parsed Nginx status code matches the explicit rule below.
OPERATIONAL_ERRORS = Counter("nginx_operational_errors_total", "HTTP 500 responses")
SECURITY_ALERTS = Counter("nginx_security_alerts_total", "HTTP 401/403 responses")
DDOS_TRAFFIC = Counter("nginx_ddos_traffic_total", "HTTP 429 responses from rate limiting")
PARSED_LINES = Counter("nginx_log_lines_parsed_total", "Nginx access log lines parsed")


def classify(status):
    if status >= 500:
        OPERATIONAL_ERRORS.inc()
    elif status in (401, 403):
        SECURITY_ALERTS.inc()
    elif status == 429:
        DDOS_TRAFFIC.inc()


def parse_status(line):
    try:
        entry = json.loads(line)
        return int(entry.get("status", 0))
    except (ValueError, json.JSONDecodeError):
        # Fallback regex keeps the classifier rule-based even if the log format
        # changes to a common Nginx access-log style.
        match = STATUS_RE.search(line)
        return int(match.group("status")) if match else 0


def follow_log(path):
    while not os.path.exists(path):
        time.sleep(1)

    log_file = None
    current_inode = None

    def open_current_log():
        opened_file = open(path, "r", encoding="utf-8")
        opened_file.seek(0, os.SEEK_END)
        return opened_file, os.stat(path).st_ino

    while True:
        if log_file is None:
            while not os.path.exists(path):
                time.sleep(1)
            log_file, current_inode = open_current_log()

        try:
            stat = os.stat(path)
            if stat.st_ino != current_inode or stat.st_size < log_file.tell():
                log_file.close()
                log_file, current_inode = open_current_log()
        except OSError:
            log_file.close()
            log_file = None
            current_inode = None
            time.sleep(1)
            continue

        line = log_file.readline()
        if not line:
            time.sleep(0.5)
            continue

        status = parse_status(line)
        if not status:
            continue
        PARSED_LINES.inc()
        classify(status)


if __name__ == "__main__":
    start_http_server(8000)
    follow_log(LOG_FILE)
