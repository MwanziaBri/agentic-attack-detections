# Elastic Security import

Built by `tools/build_elastic.py` from the Sigma rules, the hand-written ARTEX rules in `frameworks/artex/elastic/rules/` and `iocs/indicators.csv`. Do not edit these files by hand.

| File | Contents |
|---|---|
| `agentic-attack-detections.ndjson` | Every rule, disabled: Sigma rules as Lucene query rules, Sigma correlations as ES\|QL rules, the hand-written ARTEX rules, and one indicator match rule |
| `agentic-attack-indicators.ndjson` | Medium and high confidence addresses, domains, URLs and file hashes as ECS `threat.indicator` documents, in `_bulk` format. Addresses past their review date are left out |

## Import

1. Rules: Security > Rules > Import, choose `agentic-attack-detections.ndjson`, or

   ```bash
   curl -u elastic -H 'kbn-xsrf: true' -F file=@agentic-attack-detections.ndjson \
     "$KIBANA/api/detection_engine/rules/_import?overwrite=true"
   ```

2. Indicators, for the indicator match rule:

   ```bash
   curl -u elastic -H 'Content-Type: application/x-ndjson' --data-binary @agentic-attack-indicators.ndjson \
     "$ES/logs-ti_agentic_attacks-default/_bulk"
   ```

   Load the file again after each release. `logs-ti_*` is the threat index Elastic Security reads by default.

3. Every rule reads `logs-*`, `filebeat-*`, `winlogbeat-*` and `packetbeat-*`. Change the index patterns to your own data, then enable the rules you have data for. The ES|QL correlations name the fields of Elastic's AWS and Azure integrations and fail to run where no index has those fields, so enable them only where that data is collected.

The indicator match is exact: a reported domain does not match its subdomains here. The Splunk app and the Sentinel watchlist do match subdomains.
