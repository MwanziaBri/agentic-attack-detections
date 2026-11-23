#!/usr/bin/env python3
"""Build exposure/consoles.csv: exposed agent consoles that Shodan has seen.

Reads the searches in exposure/shodan-queries.csv and pages through each one on Shodan. Needs a Shodan API key in the
SHODAN_API_KEY environment variable; each page of 100 results costs one query credit. The key is never printed.

    SHODAN_API_KEY=... python3 tools/exposure_snapshot.py            # full run
    SHODAN_API_KEY=... python3 tools/exposure_snapshot.py --count    # totals only, costs no credits
    SHODAN_API_KEY=... python3 tools/exposure_snapshot.py --only cairn,strix   # refresh some frameworks, keep the rest

This is a record of what is exposed, not a detection feed: nothing here is read by tools/build_feeds.py.
"""
import argparse, csv, datetime as dt, ipaddress, json, os, sys, time, urllib.error, urllib.parse, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
QUERIES = ROOT / "exposure" / "shodan-queries.csv"
OUT = ROOT / "exposure" / "consoles.csv"
FIELDS = "ip_str,port,asn,location.country_code,timestamp,http.title"
COLUMNS = ["address", "port", "framework", "matched_on", "page_title", "asn", "country", "last_seen"]


def call(path, key, **params):
    params["key"] = key
    url = "https://api.shodan.io" + path + "?" + urllib.parse.urlencode(params)
    for attempt in range(6):
        try:
            with urllib.request.urlopen(url, timeout=60) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504) and attempt < 5:
                time.sleep(4 * (attempt + 1))
                continue
            raise SystemExit(f"Shodan answered HTTP {e.code} for {path}")
        except OSError as e:  # timeouts and connection resets: the URL holds the key, so do not print the error
            if attempt < 5:
                time.sleep(4 * (attempt + 1))
                continue
            raise SystemExit(f"Shodan did not answer for {path}: {type(e).__name__}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--count", action="store_true", help="print the total for each search and stop (no query credits)")
    ap.add_argument("--max-pages", type=int, default=60, help="stop a search after this many pages of 100 (default 60)")
    ap.add_argument("--only", default="", metavar="FRAMEWORKS", help="comma-separated frameworks to refresh; rows of the others are kept as they are")
    args = ap.parse_args()
    key = os.environ.get("SHODAN_API_KEY", "").strip()
    if not key:
        raise SystemExit("Set SHODAN_API_KEY first.")
    searches = list(csv.DictReader(QUERIES.open(encoding="utf-8")))
    rows, pages = {}, 0
    only = {f.strip() for f in args.only.split(",") if f.strip()}
    if only:
        unknown = only - {s["framework"] for s in searches}
        if unknown:
            raise SystemExit(f"No search for: {', '.join(sorted(unknown))}")
        searches = [s for s in searches if s["framework"] in only]
        if not args.count and OUT.exists():
            for r in csv.DictReader(OUT.open(encoding="utf-8")):
                if r["framework"] not in only:
                    rows[(r["address"], int(r["port"]))] = dict(r, port=int(r["port"]))
    for s in searches:
        label = f"{s['framework']}: {s['matched_on']}"
        if args.count:
            total = call("/shodan/host/count", key, query=s["query"]).get("total")
            print(f"{label:44} {total}")
            time.sleep(1.2)
            continue
        page, total, kept = 1, None, 0
        while page <= args.max_pages:
            r = call("/shodan/host/search", key, query=s["query"], page=page, fields=FIELDS, minify="false")
            pages += 1
            total = r.get("total", 0)
            matches = r.get("matches", [])
            for m in matches:
                title = " ".join(((m.get("http") or {}).get("title") or "").split())[:120]
                if s["title_contains"] and s["title_contains"].lower() not in title.lower():
                    continue
                k = (m["ip_str"], int(m["port"]))
                if k in rows:
                    continue
                rows[k] = {"address": m["ip_str"], "port": int(m["port"]), "framework": s["framework"],
                           "matched_on": s["matched_on"], "page_title": title, "asn": m.get("asn") or "",
                           "country": (m.get("location") or {}).get("country_code") or "",
                           "last_seen": (m.get("timestamp") or "")[:10]}
                kept += 1
            if not matches or page * 100 >= total:
                break
            page += 1
            time.sleep(1.2)
        print(f"{label:44} {total} on Shodan, {kept} new rows", flush=True)
        time.sleep(1.2)
    if args.count:
        return
    ordered = sorted(rows.values(), key=lambda r: (r["framework"], ipaddress.ip_address(r["address"]).version,
                                                   int(ipaddress.ip_address(r["address"])), r["port"]))
    with OUT.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS, lineterminator="\n")
        w.writeheader()
        w.writerows(ordered)
    print(f"\n{len(ordered)} services on {len({r['address'] for r in ordered})} addresses written to {OUT.relative_to(ROOT)}"
          f" on {dt.date.today().isoformat()}, {pages} pages read")
    by = {}
    for r in ordered:
        by.setdefault(r["framework"], [set(), 0])
        by[r["framework"]][0].add(r["address"]); by[r["framework"]][1] += 1
    for fw, (addrs, n) in sorted(by.items(), key=lambda x: -x[1][1]):
        print(f"  {fw:16} {n:>5} services, {len(addrs):>5} addresses")


if __name__ == "__main__":
    main()
