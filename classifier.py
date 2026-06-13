import json
import os
import re
import time
import urllib.parse
import urllib.request
import urllib.error
from collections import OrderedDict
from prometheus_client import Counter, start_http_server

LOG_FILE = os.getenv("APACHE_ACCESS_LOG", "/var/log/apache2/access.log")
STATUS_RE = re.compile(r'"\s(?P<status>\d{3})\s')

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
GEMINI_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    f"{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
)

OPERATIONAL_ERRORS = Counter("apache_operational_errors_total", "HTTP 500 responses")
SECURITY_ALERTS = Counter("apache_security_alerts_total", "HTTP 401/403 responses")
DDOS_TRAFFIC = Counter("apache_ddos_traffic_total", "HTTP 429 responses from rate limiting")
PARSED_LINES = Counter("apache_log_lines_parsed_total", "Apache access log lines parsed")

SUSPICIOUS_REQUESTS = Counter(
    "apache_suspicious_requests_total", "Requests flagged as suspicious by the rule pre-filter"
)
AI_SQLI = Counter("apache_ai_sqli_total", "Requests classified as SQL injection by Gemini")
AI_XSS = Counter("apache_ai_xss_total", "Requests classified as cross-site scripting by Gemini")
AI_PATH_TRAVERSAL = Counter(
    "apache_ai_path_traversal_total", "Requests classified as path traversal by Gemini"
)
AI_BENIGN = Counter(
    "apache_ai_benign_total", "Suspicious-looking requests Gemini judged benign"
)
AI_CALLS = Counter("apache_ai_calls_total", "Gemini API calls made")
AI_ERRORS = Counter("apache_ai_errors_total", "Gemini API calls that failed")

SUSPICIOUS_RE = re.compile(
    r"""
    (\bunion\b.*\bselect\b) |
    (\bselect\b.*\bfrom\b)  |
    (\bor\b\s+\d+\s*=\s*\d+) |
    (--|\#|;)               |
    (\bdrop\b\s+\btable\b)  |
    (<\s*script)            |
    (onerror\s*=)           |
    (onload\s*=)            |
    (javascript:)          |
    (\.\./)                 |
    (%2e%2e)                |
    (%27|%22|'|")           |
    (etc/passwd)            |
    (\bexec\b|\beval\b)
    """,
    re.IGNORECASE | re.VERBOSE,
)

AI_LABELS = {
    "sql_injection": AI_SQLI,
    "xss": AI_XSS,
    "path_traversal": AI_PATH_TRAVERSAL,
    "normal": AI_BENIGN,
}


class TTLCache:
    def __init__(self, maxsize=512):
        self.maxsize = maxsize
        self.store = OrderedDict()

    def get(self, key):
        if key in self.store:
            self.store.move_to_end(key)
            return self.store[key]
        return None

    def set(self, key, value):
        self.store[key] = value
        self.store.move_to_end(key)
        if len(self.store) > self.maxsize:
            self.store.popitem(last=False)


ai_cache = TTLCache()


def classify_status(status):
    if status >= 500:
        OPERATIONAL_ERRORS.inc()
    elif status in (401, 403):
        SECURITY_ALERTS.inc()
    elif status == 429:
        DDOS_TRAFFIC.inc()


def ask_gemini(request):
    cached = ai_cache.get(request)
    if cached is not None:
        return cached

    if not GEMINI_API_KEY:
        return None

    prompt = (
        "You are a web security log analyzer. Classify the following HTTP request "
        "line into exactly one label from this set: sql_injection, xss, "
        "path_traversal, normal. Reply with only the single label, no other text.\n"
        f"Request: {request}"
    )
    payload = json.dumps(
        {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0,
                "maxOutputTokens": 20,
                "thinkingConfig": {"thinkingBudget": 0},
            },
        }
    ).encode("utf-8")

    req = urllib.request.Request(
        GEMINI_URL, data=payload, headers={"Content-Type": "application/json"}
    )
    AI_CALLS.inc()
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))
        label = data["candidates"][0]["content"]["parts"][0]["text"].strip().lower()
    except (urllib.error.URLError, KeyError, IndexError, ValueError) as exc:
        AI_ERRORS.inc()
        print(f"[ai] classification failed: {exc}", flush=True)
        return None

    label = next((name for name in AI_LABELS if name in label), "normal")
    ai_cache.set(request, label)
    return label


def classify_request(request):
    if not request:
        return
    decoded = urllib.parse.unquote(request)
    if not SUSPICIOUS_RE.search(decoded):
        return
    SUSPICIOUS_REQUESTS.inc()
    label = ask_gemini(decoded)
    if label and label in AI_LABELS:
        AI_LABELS[label].inc()
        if label != "normal":
            print(f"[ai] {label}: {decoded}", flush=True)


def parse_entry(line):
    try:
        entry = json.loads(line)
        return int(entry.get("status", 0)), entry.get("request", "")
    except (ValueError, json.JSONDecodeError):
        match = STATUS_RE.search(line)
        return (int(match.group("status")) if match else 0), ""


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

        status, request = parse_entry(line)
        if not status:
            continue
        PARSED_LINES.inc()
        classify_status(status)
        classify_request(request)


if __name__ == "__main__":
    start_http_server(8000)
    mode = "enabled" if GEMINI_API_KEY else "disabled (no GEMINI_API_KEY)"
    print(f"[classifier] started, Gemini AI analysis {mode}, model={GEMINI_MODEL}", flush=True)
    follow_log(LOG_FILE)
