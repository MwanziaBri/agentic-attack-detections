# Exposed agent consoles

Addresses where Shodan has seen the web console of one of the frameworks in this repository. The list is built from the fingerprints the rules here already use: favicons, page titles, page text that survives a rename, and certificates.

**This is not a detection feed.** Nothing in this folder goes into the Suricata address rules, the WAF lists, the STIX bundle or the plain feeds. Those hold addresses that a named report tied to attacks. An address here means a console was reachable from the internet, and nothing more:

- Researchers, students and security teams run these tools, and some of the listed consoles are decoys.
- Hermes Agent and Agent Zero are general-purpose agents. An exposed dashboard is an exposed agent, not an attack console.
- Hosting addresses are reassigned. `last_seen` is the date Shodan last saw the console, and Shodan's index covers about the last 30 days.

Use it to check whether one of your own addresses is on it, to see where consoles are hosted, or as context when an address already has your attention for another reason.

## Files

| File | Contents |
|---|---|
| [`consoles.csv`](consoles.csv) | One row per address and port: `address`, `port`, `framework`, `matched_on` (the fingerprint that found it), `page_title`, `asn`, `country`, `last_seen` |
| [`shodan-queries.csv`](shodan-queries.csv) | The Shodan searches, in the order they run. A service found by an earlier search is not listed again |

## Snapshot of November 23, 2026

| Framework | Services | Addresses | Most common ports |
|---|---|---|---|
| ARTEX and AntiFox | 3,242 | 2,816 | 8787, 443, 8790 |
| Hermes Agent, port 9119 only | 2,192 | 2,192 | 9119 |
| CyberStrikeAI | 1,408 | 1,188 | 8444, 8080, 443 |
| PentAGI | 510 | 500 | 8443, 8666, 443 |
| Agent Zero | 186 | 175 | 5080, 443, 50080 |
| RedAmon | 34 | 34 | 3000, 443, 80 |
| Cairn | 31 | 30 | 8000, 8001 |
| HexStrike | 30 | 30 | 8888 |
| Strix | 13 | 12 | 8080, 443, 7777 |
| Xalgorix | 13 | 13 | 9137, 1337, 443 |
| Pentest Swarm AI | 0 | 0 | |
| All | 7,659 | 6,715 | |

- A service is one address and port. 4,868 of the 7,659 were seen in the seven days before the snapshot.
- One network, AS398823, holds 423 of the services: 236 pages titled CyberStrikeAI on port 8444 and 186 titled PentAGI on port 8666, on addresses that also serve a write-up of PentAGI's prompts. That looks like one mass deployment or a set of decoys, not that many operators. Leave it out before quoting a count.
- 431 ARTEX services were found by title or page text and not by favicon: builds with another icon or another name that kept the title, its ending or the description.
- Renamed builds show up for the newer frameworks too: a RedAmon console titled `Anvigil` and Xalgorix dashboards titled `VulnHawk — Security Scanner` and `MindSOC - VAPT`, found by icon or by the theme script.
- 57 addresses are also in [`iocs/indicators.csv`](../iocs/indicators.csv), where a named report ties them to attacks.
- Most services are in the United States (2,785), China (1,250), Hong Kong (763), Germany (470) and Singapore (359).

## Rebuild it

```bash
SHODAN_API_KEY=... python3 tools/exposure_snapshot.py --count   # totals only, no query credits
SHODAN_API_KEY=... python3 tools/exposure_snapshot.py           # one query credit per 100 results
```

The searches run against Shodan only. Nothing connects to a listed address.

## What it misses

- Consoles served by host name only, such as the ones behind `sslip.io` names on port 443. Shodan scans addresses, so it does not see them.
- Consoles on ports Shodan has not scanned yet, and consoles that were down when it looked.
- Renamed builds that changed the favicon, the title and the page text.
- Hermes dashboards on ports other than 9119, which are left out on purpose: the stock port keeps the list to default installs.

To add a search, add a row to `shodan-queries.csv` and say in the pull request which fingerprint in the framework's `source-code-signals.md` it comes from.
