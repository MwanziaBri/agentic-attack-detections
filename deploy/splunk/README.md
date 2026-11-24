# Splunk app

One app with the searches for every framework and the shared behaviors, the indicator lookups and the Agentic Attack Activity dashboard. Built by `tools/build_splunk.py`; do not edit by hand.

Download `agentic-attack-detections-splunk.tgz` from the [latest release](https://github.com/ThreatDefence/agentic-attack-detections/releases/latest/download/agentic-attack-detections-splunk.tgz) and install it with **Apps > Manage Apps > Install app from file**, or copy [`TA-agentic-attack-detections/`](TA-agentic-attack-detections) into `$SPLUNK_HOME/etc/apps/`. The app replaces the ARTEX-only app of the same name.

## Set up

1. **Settings > Advanced search > Search macros**: point `aad_indexes` at the indexes that hold your endpoint, web, DNS and cloud logs. It ships as `index=*`.
2. The data source macros find events by CIM tags and sourcetypes, so data from a CIM-compliant add-on needs no change. Edit a macro if your data is tagged differently.
3. Every search ships disabled. Run one over 30 days to baseline it, then enable it.
4. Enabled searches write their results to the `summary` index and to Triggered Alerts. The dashboard reads the summary index.

| Macro | Finds | Default |
| --- | --- | --- |
| `aad_process` | Process starts | `tag=process tag=report` |
| `aad_file` | File creation | `tag=endpoint tag=filesystem` |
| `aad_registry` | Registry writes | `tag=endpoint tag=registry` |
| `aad_dns` | DNS queries | `tag=network tag=resolution tag=dns` |
| `aad_proxy` | Outbound proxy logs | `tag=web tag=proxy` |
| `aad_web` | Your web server, load balancer and WAF logs | `tag=web NOT tag=proxy` |
| `aad_aws_cloudtrail` | AWS CloudTrail | `sourcetype=aws:cloudtrail` |
| `aad_azure_signin`, `aad_azure_audit`, `aad_azure_activity` | Entra ID sign-ins and audit log, Azure activity log | the Microsoft add-on sourcetypes |
| `aad_okta` | Okta system log | `sourcetype=OktaIM2:log` |

## Searches

- Every Sigma rule in the repository, converted to SPL on CIM field names: `process`, `process_path`, `parent_process_path`, `file_path`, `registry_path`, `query`, `url`, `uri_path`, `uri_query` and `http_user_agent`. Cloud rules keep the JSON field names the AWS, Microsoft and Okta add-ons extract.
- The hand-written ARTEX searches.
- Indicator searches for reported addresses, domains (and their subdomains), file hashes and user agents, matched against lookups built from `iocs/indicators.csv`. Indicators past their review date are skipped.

Each search has its ATT&CK techniques in `action.correlationsearch.annotations`, which Splunk Enterprise Security shows. Each one adds `aad_framework` and `aad_entity` (the source address for web, sign-in and cloud events, the machine for endpoint events) to its results.

## Dashboard

**Agentic Attack Activity** has a card for each framework: hosts and addresses with a result in the time range, results per day, how many of them first appeared in the last seven days, the count for all time, and the framework's usual console port. Below the cards is a table of the latest results.
