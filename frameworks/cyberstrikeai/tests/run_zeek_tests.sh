#!/usr/bin/env bash
# Run the CyberStrikeAI Zeek package against tests/cyberstrikeai-sample.pcap: every notice must fire and the near misses must stay quiet.
# Rebuild the capture with: python3 tests/make_pcap.py
set -euo pipefail
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
(cd "$work" && zeek -C -r "$OLDPWD/tests/cyberstrikeai-sample.pcap" "$OLDPWD/zeek/cyberstrikeai" >/dev/null 2>stderr.txt)
log="$work/notice.log"
fail=0
# expect <notice> <text>: a line of that notice type that holds the text. quiet <what> <text>: no notice line holds the text.
expect() { if ! { grep "CyberStrikeAI::$1" "$log" 2>/dev/null || true; } | grep -qF -- "$2"; then echo "MISSING: $1 with $2"; fail=1; fi; }
quiet() { if grep -qF -- "$2" "$log" 2>/dev/null; then echo "UNEXPECTED: $1"; fail=1; fi; }

if [ -s "$work/stderr.txt" ]; then echo "UNEXPECTED: zeek wrote to stderr"; cat "$work/stderr.txt"; fail=1; fi
for n in Webshell_Manager OS_Probe OS_Probe_Answered Implant_Checkin Implant_User_Agent TCP_Implant Console_User_Agent Console_Certificate; do
    if grep -q "CyberStrikeAI::$n" "$log" 2>/dev/null; then echo "notice: $n"; else echo "MISSING: $n"; fail=1; fi
done
expect OS_Probe 203.0.113.11            # the probe in a query string
expect Implant_Checkin "/check_in"          # check-in with both token headers
expect Implant_Checkin "/tasks?session_id=" # task poll with the session header
quiet "a browser" 198.51.100.99
quiet "a session header without a check-in path" 10.0.0.50
quiet "CSB1 inside a larger segment" 10.0.0.51
quiet "the unrelated CyberStrike user agent" 10.0.0.52
quiet "a certificate with a longer common name" 10.0.0.53
quiet "the generic signature notice" Signatures::

if [ "$fail" -eq 0 ]; then echo "PASS"; else echo "FAIL"; exit 1; fi
