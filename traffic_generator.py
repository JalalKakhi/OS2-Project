import argparse
import concurrent.futures
import time
import urllib.error
import urllib.parse
import urllib.request


ATTACK_PAYLOADS = [
    "/products?id=1' OR '1'='1",
    "/products?id=1 UNION SELECT username, password FROM users--",
    "/login?user=admin'--",
    "/search?q=<script>alert(document.cookie)</script>",
    "/comment?text=<img src=x onerror=alert(1)>",
    "/page?next=javascript:alert(1)",
    "/download?file=../../../../etc/passwd",
    "/static?path=..%2f..%2f..%2fetc%2fpasswd",
]


def hit(url):
    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code
    except Exception:
        return 0


def run_flood(base_url, total, workers):
    counts = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for status in pool.map(hit, [base_url] * total):
            counts[status] = counts.get(status, 0) + 1

    print("Status code counts:")
    for status, count in sorted(counts.items()):
        print(f"{status}: {count}")

    rate_limited = counts.get(429, 0)
    if rate_limited:
        print(f"SUCCESS: DDoS simulation triggered Apache rate limiting ({rate_limited} HTTP 429 responses).")
    else:
        print("FAILURE: No HTTP 429 responses were triggered. Increase --requests or --workers and try again.")


def run_attack(base_url, rounds, delay):
    base = base_url.rstrip("/")
    print("Sending malicious-looking requests for the AI classifier to analyze.")
    print("(Paths may return 404 from Flask; the AI detects the attack from the logged request itself.)\n")
    for _ in range(rounds):
        for payload in ATTACK_PAYLOADS:
            path, _, query = payload.partition("?")
            url = base + urllib.parse.quote(path)
            if query:
                url += "?" + urllib.parse.quote(query, safe="=&")
            status = hit(url)
            print(f"{status}  {payload}")
            time.sleep(delay)
    print("\nDone. Check apache_ai_sqli_total / apache_ai_xss_total / "
          "apache_ai_path_traversal_total at http://localhost:8000/metrics")


def main():
    parser = argparse.ArgumentParser(description="Generate traffic for the Apache + AI monitoring demo.")
    parser.add_argument("--url", default="http://localhost/", help="Target URL behind Apache")
    parser.add_argument("--requests", type=int, default=200, help="Total requests for the DDoS flood")
    parser.add_argument("--workers", type=int, default=50, help="Concurrent workers for the DDoS flood")
    parser.add_argument("--attack", action="store_true",
                        help="Send SQLi/XSS/path-traversal payloads for the AI classifier instead of flooding")
    parser.add_argument("--rounds", type=int, default=1, help="How many times to send the attack payload set")
    parser.add_argument("--delay", type=float, default=0.4,
                        help="Seconds between attack requests (keeps them under the rate limit)")
    args = parser.parse_args()

    if args.attack:
        run_attack(args.url, args.rounds, args.delay)
    else:
        run_flood(args.url, args.requests, args.workers)


if __name__ == "__main__":
    main()
