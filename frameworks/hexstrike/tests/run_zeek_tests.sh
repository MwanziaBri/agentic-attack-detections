#!/usr/bin/env bash
# Run the HexStrike Zeek package against tests/hexstrike-sample.pcap: every notice must fire and the near misses must stay quiet.
# Rebuild the capture with: python3 tests/make_pcap.py
set -euo pipefail
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
(cd "$work" && zeek -C -r "$OLDPWD/tests/hexstrike-sample.pcap" "$OLDPWD/zeek/hexstrike" >/dev/null 2>stderr.txt)
log="$work/notice.log"
fail=0
# expect <notice> <text>: a line of that notice type that holds the text. quiet <what> <text>: no notice line holds the text.
expect() { if ! { grep "HexStrike::$1" "$log" 2>/dev/null || true; } | grep -qF -- "$2"; then echo "MISSING: $1 with $2"; fail=1; fi; }
quiet() { if grep -qF -- "$2" "$log" 2>/dev/null; then echo "UNEXPECTED: $1"; fail=1; fi; }

if [ -s "$work/stderr.txt" ]; then echo "UNEXPECTED: zeek wrote to stderr"; cat "$work/stderr.txt"; fail=1; fi
for n in User_Agent Exploit_User_Agent XSS_Probe Tool_API_Request Server_Exposed; do
    if grep -q "HexStrike::$n" "$log" 2>/dev/null; then echo "notice: $n"; else echo "MISSING: $n"; fail=1; fi
done
expect User_Agent "HexStrike-HTTP-Framework/"
expect User_Agent "HexStrike-BrowserAgent/"
expect Tool_API_Request "/api/command"
expect Tool_API_Request "/api/tools/nmap"
quiet "a browser" 198.51.100.99
quiet "a GET to the tool list" 10.0.0.40
quiet "the API path on another port" 10.0.0.41
quiet "a look-alike API path" 10.0.0.42
quiet "an exploit-like user agent" 203.0.113.30
quiet "a page that mentions HexStrike" 198.51.100.50

if [ "$fail" -eq 0 ]; then echo "PASS"; else echo "FAIL"; exit 1; fi
