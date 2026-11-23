# RedAmon Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **RedAmon** ([samugit83/redamon](https://github.com/samugit83/redamon), reviewed at `73ca9d38`, version 7.9.0), a self-hosted penetration testing platform: a Docker Compose stack with a web console, a recon pipeline that maps a target's attack surface, and an agent that exploits what the map shows from a Kali container, with Metasploit for the shells. No vendor or CERT report of RedAmon in a real intrusion was found on November 23, 2026, and its agent asks for approval before exploitation by default. This folder is therefore built from the source code alone: it finds RedAmon scanning you, RedAmon running on a host, and its consoles exposed.

| | |
|---|---|
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, Zeek intel, YARA, STIX 2.1 |
| Docs | [What RedAmon leaves behind](source-code-signals.md), with a file and line for every signal |
| Status | Experimental. Tested for syntax and conversion, Suricata rules against test flows, YARA against the RedAmon source and the other agent code bases. Baseline every rule on your own data before alerting |

## What RedAmon leaves behind

The short version. The full review is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Code |
|---|---|---|
| AI endpoint probe | User agent `RedAmon-AISurfaceRecon/1.0`, on by default. It POSTs `{"model": "probe", "messages": [{"role": "user", "content": "ping"}], "max_tokens": 1}` to model API paths and an MCP `initialize` whose `clientInfo` names `RedAmon-AISurfaceRecon` | `recon/main_recon_modules/ai_surface_recon.py` |
| Other user agents | `Mozilla/5.0 (compatible; RedAmon/4.7)`, `RedAmon-JsRecon/1.0`, `RedAmon-CachePoison/1.0` from modules that are off by default, and the truncated `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36` on page and script fetches, which CyberStrikeAI's implant also sends | `recon/main_recon_modules/`, `recon/helpers/resource_enum/` |
| Canaries | XSS canary `rEdAm0n1337XsS` in parameters, `User-Agent`, `Referer` and a cookie; cache poisoning canary `rdmn<10 hex>.redamon-poc.invalid` in `X-Forwarded-Host` and similar headers with a `rdmncb=` cache buster | `agentic/prompts/xss_prompts.py`, `recon/cache_scan/` |
| Callbacks | `interactsh-client -server oast.fun`, reverse shells to TCP 4444 or through `ngrok tcp 4444` or `chisel client <url> R:4444:localhost:4444` | `agentic/prompts/rce_prompts.py`, `mcp/servers/tunnel_manager.py` |
| Host | Containers `redamon-webapp`, `redamon-agent`, `redamon-kali`, `redamon-recon-<id>`, labels `redamon.run_id`, scratch folder `/tmp/redamon`, listeners on 3000, 8090 and 4444 | `docker-compose.yml`, `recon_orchestrator/container_manager.py` |
| Console | Port 3000, title `RedAmon`, favicon hash `964522141` on Shodan. A renamed build keeps `localStorage.getItem('redamon-theme')` in every page and the open route `/api/version/check` | `webapp/src/app/layout.tsx` |
| Agent API | Port 8090 with no credential: `/health`, `/openapi.json` titled `RedAmon Agent API`, `/tunnel-status` | `agentic/api.py` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: RedAmon on a host, the watchlist sweep, and its markers in web, proxy and DNS logs |
| [`sigma/`](sigma) | 3 Sigma rules: scanner markers in web logs, the stack or a reverse shell tunnel on a host, and the ownership lookup |
| [`suricata/`](suricata) | Rules for its user agents, probes and canaries, and for an exposed console or agent API |
| [`zeek/`](zeek) | Intel framework file generated from the CSV |
| [`yara/`](yara) | A rule for its agent prompt and scanner markers |

Out-of-band lookups, attack tools started by an agent, model traffic from servers and the rest are in [`behaviors/`](../../behaviors). Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `redamon`.

## Limits

- Everything here is a default of the published code. An operator who edits the code or the project settings removes it.
- Post-exploitation is stock Metasploit, so a compromised host shows Metasploit, not RedAmon.
- A match means RedAmon, not an attacker: penetration testers and students run it. Check who ran it and whether the test was agreed.
