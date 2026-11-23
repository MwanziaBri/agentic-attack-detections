#!/usr/bin/env python3
"""Write tests/hexstrike-sample.pcap: synthetic HexStrike traffic and near misses for the Zeek test.

    pip install scapy && python3 tests/make_pcap.py
"""
from pathlib import Path
from scapy.all import IP, TCP, Ether, Raw, wrpcap

pkts = []
t = [1795200000.0]
E = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
ER = Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")


def stamp(p):
    t[0] += 0.01
    p.time = t[0]
    return p


def http(cli, srv, sport, dport, request, response):
    c, s = 1000, 5000
    pkts.append(stamp(E / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="S", seq=c)))
    pkts.append(stamp(ER / IP(src=srv, dst=cli) / TCP(sport=dport, dport=sport, flags="SA", seq=s, ack=c + 1)))
    c += 1; s += 1
    pkts.append(stamp(E / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="A", seq=c, ack=s)))
    pkts.append(stamp(E / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="PA", seq=c, ack=s) / Raw(request)))
    c += len(request)
    pkts.append(stamp(ER / IP(src=srv, dst=cli) / TCP(sport=dport, dport=sport, flags="PA", seq=s, ack=c) / Raw(response)))
    s += len(response)
    pkts.append(stamp(E / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="FA", seq=c, ack=s)))
    pkts.append(stamp(ER / IP(src=srv, dst=cli) / TCP(sport=dport, dport=sport, flags="FA", seq=s, ack=c + 1)))
    pkts.append(stamp(E / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="A", seq=c + 1, ack=s + 1)))


def req(method, path, ua, body=""):
    b = body.encode()
    extra = f"Content-Type: application/json\r\nContent-Length: {len(b)}\r\n" if body else ""
    return f"{method} {path} HTTP/1.1\r\nHost: target.example.test\r\nUser-Agent: {ua}\r\n{extra}Accept: */*\r\n\r\n".encode() + b


def resp(body, status="200 OK", ctype="application/json"):
    b = body.encode()
    return f"HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {len(b)}\r\n\r\n".encode() + b


WEB, HX = "10.0.0.5", "10.0.0.8"
BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"

# Requests that reach a web server: the HTTP testing module, the headless browser, a generated exploit, the XSS probe
http("203.0.113.20", WEB, 41001, 80, req("GET", "/", "HexStrike-HTTP-Framework/1.0 (Advanced Security Testing)"), resp("<html></html>", ctype="text/html"))
http("203.0.113.21", WEB, 41002, 80, req("GET", "/login", "HexStrike-BrowserAgent/1.0 (Security Testing)"), resp("<html></html>", ctype="text/html"))
http("203.0.113.22", WEB, 41003, 80, req("GET", "/cgi-bin/status", "Mozilla/5.0 (Compatible Exploit)"), resp("", status="404 Not Found"))
http("203.0.113.23", WEB, 41004, 80, req("GET", "/search?q=%3ChexstrikeXSSTest123%3E", BROWSER), resp("<html></html>", ctype="text/html"))

# The HexStrike server: a health check and its answer, a shell command and a tool run over the API
http("10.0.0.30", HX, 41010, 8888, req("GET", "/health", "python-requests/2.32.3"),
     resp('{"status":"healthy","message":"HexStrike AI Tools API Server is operational","version":"6.0.0"}'))
http("10.0.0.30", HX, 41011, 8888, req("POST", "/api/command", "python-requests/2.32.3", '{"command":"id"}'), resp('{"stdout":"uid=0(root)"}'))
http("10.0.0.31", HX, 41012, 8888, req("POST", "/api/tools/nmap", "python-requests/2.32.3", '{"target":"10.0.0.5"}'), resp('{"success":true}'))

# Near misses: a browser, a GET to the tool list, an API path on another port, a look-alike path,
# an exploit-like user agent that is not the exact string, and a page that mentions HexStrike
http("198.51.100.99", WEB, 41100, 80, req("GET", "/", BROWSER), resp("<html></html>", ctype="text/html"))
http("10.0.0.40", HX, 41101, 8888, req("GET", "/api/tools/list", "python-requests/2.32.3"), resp("[]"))
http("10.0.0.41", "10.0.0.9", 41102, 8080, req("POST", "/api/command", "python-requests/2.32.3", '{"command":"build"}'), resp("{}"))
http("10.0.0.42", HX, 41103, 8888, req("POST", "/api/commandeer", "python-requests/2.32.3", "{}"), resp("{}"))
http("203.0.113.30", WEB, 41104, 80, req("GET", "/", "Mozilla/5.0 (Compatible Exploit Scanner)"), resp("<html></html>", ctype="text/html"))
http("10.0.0.43", "198.51.100.50", 41105, 80, req("GET", "/blog/hexstrike", BROWSER),
     resp("<html><body>HexStrike AI is a tools API server</body></html>", ctype="text/html"))

out = Path(__file__).with_name("hexstrike-sample.pcap")
wrpcap(str(out), pkts)
print(f"wrote {out} ({len(pkts)} packets)")
