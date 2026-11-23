#!/usr/bin/env python3
"""Write tests/cyberstrikeai-sample.pcap: synthetic CyberStrikeAI traffic and near misses for the Zeek test.

    pip install scapy && python3 tests/make_pcap.py      (needs openssl for the test certificates)
"""
import struct, subprocess, tempfile
from pathlib import Path
from scapy.all import IP, TCP, Ether, Raw, wrpcap

pkts = []
t = [1795100000.0]
E = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
ER = Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")


def stamp(p):
    t[0] += 0.01
    p.time = t[0]
    return p


def session(cli, srv, sport, dport, client_segments, server_segments):
    """A TCP session: the client's segments, then the server's, each one its own packet."""
    c, s = 1000, 5000
    pkts.append(stamp(E / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="S", seq=c)))
    pkts.append(stamp(ER / IP(src=srv, dst=cli) / TCP(sport=dport, dport=sport, flags="SA", seq=s, ack=c + 1)))
    c += 1; s += 1
    pkts.append(stamp(E / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="A", seq=c, ack=s)))
    for seg in client_segments:
        pkts.append(stamp(E / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="PA", seq=c, ack=s) / Raw(seg)))
        c += len(seg)
    for seg in server_segments:
        pkts.append(stamp(ER / IP(src=srv, dst=cli) / TCP(sport=dport, dport=sport, flags="PA", seq=s, ack=c) / Raw(seg)))
        s += len(seg)
    pkts.append(stamp(E / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="FA", seq=c, ack=s)))
    pkts.append(stamp(ER / IP(src=srv, dst=cli) / TCP(sport=dport, dport=sport, flags="FA", seq=s, ack=c + 1)))
    pkts.append(stamp(E / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="A", seq=c + 1, ack=s + 1)))


def http(cli, srv, sport, dport, request, response):
    session(cli, srv, sport, dport, [request], [response])


def req(method, path, ua, headers="", body=""):
    b = body.encode()
    extra = f"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(b)}\r\n" if body else ""
    return f"{method} {path} HTTP/1.1\r\nHost: target.example.test\r\nUser-Agent: {ua}\r\n{headers}{extra}Accept: */*\r\n\r\n".encode() + b


def resp(body, status="200 OK"):
    b = body.encode()
    return f"HTTP/1.1 {status}\r\nContent-Type: text/html\r\nContent-Length: {len(b)}\r\n\r\n".encode() + b


def cert_der(cn):
    with tempfile.TemporaryDirectory() as d:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                        "-days", "365", "-subj", f"/CN={cn}", "-keyout", f"{d}/k.pem", "-out", f"{d}/c.der", "-outform", "DER"],
                       check=True, capture_output=True)
        return Path(f"{d}/c.der").read_bytes()


def u24(n):
    return struct.pack(">I", n)[1:]


def handshake(kind, body):
    return bytes([kind]) + u24(len(body)) + body


def record(payload):
    return b"\x16\x03\x03" + struct.pack(">H", len(payload)) + payload


def tls_session(cli, srv, sport, dport, cn):
    """A TLS 1.2 handshake up to ServerHelloDone, so the server certificate is in the clear."""
    client_hello = b"\x03\x03" + b"\x11" * 32 + b"\x00" + b"\x00\x02\xc0\x2b" + b"\x01\x00"
    server_hello = b"\x03\x03" + b"\x22" * 32 + b"\x00" + b"\xc0\x2b" + b"\x00"
    der = cert_der(cn)
    certificate = u24(len(der) + 3) + u24(len(der)) + der
    hello = record(handshake(1, client_hello))
    server = record(handshake(2, server_hello) + handshake(11, certificate) + handshake(14, b""))
    session(cli, srv, sport, dport, [hello], [server])


ATT, WEB, HOST, C2 = "203.0.113.10", "10.0.0.5", "10.0.0.20", "198.51.100.44"
BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"

# The webshell manager: its user agent, the OS probe in a POST body, and a Windows server answering it
http(ATT, WEB, 40001, 80, req("POST", "/uploads/s.aspx", "Mozilla/5.0 (compatible; CyberStrikeAI-WebShell/1.0)",
                              body="pass=x&cmd=echo+%3AOSPROBE_%25OS%25%3AEND"), resp(":OSPROBE_Windows_NT:END\r\n"))
# The OS probe in a query string from a client with another user agent
http("203.0.113.11", WEB, 40002, 80, req("GET", "/up/s.php?pass=x&cmd=echo%20:OSPROBE_%25OS%25:END", "curl/8.5.0"), resp(":OSPROBE_Linux:END"))

# HTTP implants: a check-in with both token headers and the truncated Chrome user agent, and a task poll from another host
IMP = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
tok = "X-Implant-Token: 4f1c2a\r\nX-Session-Token: 9b8e7d\r\n"
http(HOST, C2, 40010, 8443, req("POST", "/check_in", IMP, headers=tok, body="x"), resp("{}"))
http("10.0.0.21", C2, 40011, 8443, req("GET", "/tasks?session_id=9b8e7d", IMP, headers="X-Session-Token: 9b8e7d\r\n"), resp("[]"))

# TCP implant: CSB1 on its own, then a length frame
session(HOST, C2, 40012, 4444, [b"CSB1", b"\x00\x00\x00\x10" + b"A" * 16], [b"\x00\x00\x00\x04ABCD"])

# The console's own user agent on a recon API
http("10.0.0.30", "198.51.100.60", 40020, 80, req("GET", "/api/v1/search/all?qbase64=x", "CyberStrikeAI/1.7.4"), resp("{}"))

# The console certificate, TLS 1.2
tls_session("10.0.0.40", "198.51.100.70", 40030, 8080, "CyberStrikeAI")

# Near misses: a real browser, a session token without a check-in path, CSB1 inside a larger segment,
# an unrelated project's user agent, and a certificate with a longer common name
http("198.51.100.99", WEB, 40100, 80, req("GET", "/", BROWSER), resp("<html></html>"))
http("10.0.0.50", "198.51.100.80", 40101, 80, req("GET", "/api/profile", BROWSER, headers="X-Session-Token: abc\r\n"), resp("{}"))
session("10.0.0.51", "198.51.100.81", 40102, 4444, [b"CSB1" + b"\x00\x00\x00\x04ABCD"], [b"ok"])
http("10.0.0.52", "198.51.100.82", 40103, 80, req("GET", "/v1/models", "cyberstrike/2.3.0"), resp("{}"))
tls_session("10.0.0.53", "198.51.100.83", 40104, 443, "CyberStrikeAI-Lab")

out = Path(__file__).with_name("cyberstrikeai-sample.pcap")
wrpcap(str(out), pkts)
print(f"wrote {out} ({len(pkts)} packets)")
