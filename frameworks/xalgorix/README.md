# Xalgorix Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **Xalgorix** ([xalgorix/xalgorix](https://github.com/xalgorix/xalgorix), reviewed at `f5b1a99a`, one commit after v4.6.205), a single Go binary with a web dashboard whose agent works through a penetration test of a web application or API with a shell, a headless browser and an HTTP client, while a second agent re-exploits each finding. No tool call needs human approval. No vendor or CERT report of Xalgorix in a real intrusion was found on November 23, 2026, so this folder is built from the source code alone: it finds Xalgorix testing you, Xalgorix running on a host, and its consoles exposed.

| | |
|---|---|
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, Zeek intel, YARA, STIX 2.1 |
| Docs | [What Xalgorix leaves behind](source-code-signals.md), with a file and line for every signal |
| Status | Experimental. Tested for syntax and conversion, Suricata rules against test flows, YARA against the Xalgorix source and the other agent code bases. Baseline every rule on your own data before alerting |

## What Xalgorix leaves behind

The short version. The full review is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Code |
|---|---|---|
| Verifier paths | `<path>-xalgorix-nonexistent-<id>` (access control check) and `<dir>/xalgorix-missing-<id>` followed by `../` steps to `etc/passwd` (path traversal check) | `internal/agent/verify_authbypass.go`, `verify_path_traversal.go` |
| Verifier bodies | XXE documents with `xalgorix-xxe-start-<32 hex>`, `xalgorix-xxe-control-` and `xalgorix-xxe-end-`, and `file:///xalgorix-xxe-missing-<32 hex>` | `internal/agent/verify_xxe.go` |
| CSRF check | `Origin: https://csrf-attacker.example` with the matching `Referer` | `internal/agent/verify_csrf.go:113-115` |
| Canary | Reflection canary `XALG0R1XTEST`, an example in the system prompt, so the model may vary it | `internal/agent/agent_prompt.go` |
| Callbacks | Its own listener answers every request with `xalgorix-oob-ok:<id>`; by default it uses public interactsh names. Calibration requests carry `User-Agent: xalgorix-origin-calibration/1` and the header `X-Xalgorix-Origin-Calibration` | `internal/oob/server.go` |
| Host | `xalgorix --web`; every agent command is `bash -c` that starts with `export XALGORIX_WORKSPACE=` and defines `__xalgorix_resolve_path`; files `~/.xalgorix.env`, `/etc/xalgorix.env`, `~/.xalgorix/data/`, `/etc/systemd/system/xalgorix.service`; image `xalgord/xalgorix` | `internal/tools/terminal/terminal.go` |
| Console | Plain HTTP on port 9137, title `Xalgorix — Security Scanner`, icon `/logo.png` with Shodan hash `248472114`. A renamed build keeps `localStorage.getItem("xalgorix.theme")` and the cookie `xalgorix_session` | `internal/web/static/index.html` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: Xalgorix on a host, the watchlist sweep, and its markers in web and proxy logs |
| [`sigma/`](sigma) | 3 Sigma rules: verifier markers in web logs, the agent's processes, and its files |
| [`suricata/`](suricata) | Rules for its verifier requests, canary and callbacks, and for an exposed console |
| [`zeek/`](zeek) | Intel framework file generated from the CSV |
| [`yara/`](yara) | A rule for the binary and its source |

Out-of-band lookups, attack tools started by an agent, model traffic from servers and the rest are in [`behaviors/`](../../behaviors). Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `xalgorix`.

## Limits

- The verifier markers are in the code and appear only when a finding is being confirmed. Scanning before that uses ordinary browser user agents and the usual tools.
- The canary, the sign-up addresses and the probe order are examples in the system prompt. The model can change them on any run.
- A match means Xalgorix, not an attacker: it is promoted to bug bounty hunters and security teams. Check who ran it and whether the test was agreed.
