import argparse
import concurrent.futures
import urllib.error
import urllib.request
import ssl


def hit(url):
    try:
        context = ssl._create_unverified_context()
        with urllib.request.urlopen(url, timeout=3 , context=context) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code
    except Exception:
        return 0


def main():
    parser = argparse.ArgumentParser(description="Generate traffic to trigger Nginx HTTP 429 rate limiting.")
    parser.add_argument("--url", default="http://localhost/", help="Target URL behind Nginx")
    parser.add_argument("--requests", type=int, default=200, help="Total number of requests")
    parser.add_argument("--workers", type=int, default=50, help="Concurrent workers")
    args = parser.parse_args()

    counts = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        for status in pool.map(hit, [args.url] * args.requests):
            counts[status] = counts.get(status, 0) + 1

    print("Status code counts:")
    for status, count in sorted(counts.items()):
        print(f"{status}: {count}")

    rate_limited = counts.get(429, 0)
    if rate_limited:
        print(f"SUCCESS: DDoS simulation triggered Nginx rate limiting ({rate_limited} HTTP 429 responses).")
    else:
        print("FAILURE: No HTTP 429 responses were triggered. Increase --requests or --workers and try again.")


if __name__ == "__main__":
    main()
