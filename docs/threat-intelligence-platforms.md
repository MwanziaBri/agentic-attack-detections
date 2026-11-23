# Loading the feeds into MISP and OpenCTI

The indicators in [`iocs/indicators.csv`](../iocs/indicators.csv) are published in two shapes that a threat intelligence platform can read. Pick by what you need to keep.

| File | What it holds | What travels with each value |
|---|---|---|
| `feeds/ipv4.txt`, `domains.txt`, `urls.txt`, `sha256.txt`, `md5.txt` | One value per line. Medium and high confidence only. Addresses past their review date are left out | Nothing. The value only |
| `feeds/by-framework/<framework>/` | The same lists, one folder per framework | Nothing, but the folder tells you the framework |
| `feeds/stix2.1-bundle.json` | Every indicator that has a STIX pattern, all confidence levels, expired addresses included, plus the frameworks and named actors | Confidence, source, framework or actor, dates |

Raw addresses for a feed:

```
https://raw.githubusercontent.com/ThreatDefence/agentic-attack-detections/main/feeds/ipv4.txt
https://raw.githubusercontent.com/ThreatDefence/agentic-attack-detections/main/feeds/domains.txt
https://raw.githubusercontent.com/ThreatDefence/agentic-attack-detections/main/feeds/by-framework/artex/ipv4.txt
```

Addresses here come from cloud and VPS providers and get reassigned. Treat them as leads to check, not as a block list.

## MISP

### The plain lists as feeds

Use this for the values that change: addresses and domains.

1. Open **Sync Actions**, then **Feeds**, then **Add Feed**.
2. Fill in the form:

   | Field | Value |
   |---|---|
   | Enabled | On |
   | Name | For example `Agentic attack detections: IPv4` |
   | Provider | `agentic-attack-detections` |
   | Input Source | Network |
   | URL | The raw address of the list |
   | Source Format | Freetext Parsed Feed |
   | Target Event | Fixed Event |
   | Delta Merge | On |
   | Auto Publish | Off until you have looked at the first pull |
   | Default Tag | A tag of your own, so the values can be found later |

3. Save, then choose **Fetch all events** on the feed's row.

Add one feed per list. Each list becomes one event, named after the feed. Delta Merge removes a value from that event when the value leaves the list, which is how an address past its review date drops out.

What arrives:

| In the list | MISP attribute |
|---|---|
| IPv4 address | `ip-dst` |
| Domain with two labels, such as `b8t.shop` | `domain` |
| Name with more labels, such as `cdn.js-static.com` | `hostname` |
| URL | `url` |
| Hash | `sha256` or `md5` |

What does not arrive: confidence, source and framework. To keep the framework, add the lists from `feeds/by-framework/` as separate feeds with a tag each. Attributes arrive with the IDS flag on; tick **Override IDS Flag** on the feed if you want them as context only.

`user_agents.txt` is not for a free-text feed. The parser is built for network values and hashes and has no user agent type. User agents come through the STIX bundle.

### The STIX bundle

Use this when you want the context.

1. Open **Event Actions**, then **List Events**, then **Import from…**, then **STIX 2.x format (lossy)**.
2. Choose `feeds/stix2.1-bundle.json`, or the copy attached to the latest release.
3. Leave **Publish imported events** off. If you see **How to handle Galaxies and Clusters**, keep **As MISP standard format**.
4. Choose **Upload**.

The same import over the API is a `POST` of the file to `/events/upload_stix/2`.

The bundle becomes one event:

| In the bundle | In MISP |
|---|---|
| Address, domain, URL, hash and file name indicators | Attributes: `ip-dst`, `domain`, `url`, `sha256`, `md5`, `filename` |
| User agent indicators | `stix2-pattern` objects that hold the STIX pattern. There is no user agent attribute |
| Folder and account indicators | `directory` and `user-account` objects |
| Confidence 85, 60 or 30 | The tag `misp:confidence-level` with `usually-confident`, `fairly-confident` or `rarely-confident` |
| Framework | A galaxy cluster of the type STIX 2.1 Tool on the attribute |
| Named actor | A galaxy cluster of the type STIX 2.1 Intrusion Set on the attribute |
| Description, which ends with "Reported by" and the source | The attribute comment |
| `valid_from` and `valid_until` (the review date) | `first_seen` and `last_seen` |
| Labels | Dropped |
| The link to the source report | Dropped |
| The link from an actor to the framework it used | Dropped |

Check these before you rely on the event:

- **Every attribute has the IDS flag on, including low confidence rows.** Those rows include legitimate services such as AI model APIs. Filter on `misp:confidence-level="rarely-confident"` and clear the flag, or leave those rows out of exports.
- **Indicators tied to a named actor carry the actor, not the framework.** Search by the actor cluster for those.
- **Wildcard patterns arrive as text.** File name prefixes and URL fragments use `LIKE` in STIX, so MISP gets values such as `artex-probe-%`. MISP compares values literally, so these will not correlate. Treat them as notes or edit them.
- **Expired addresses are in the bundle.** They carry a `last_seen` date and nothing in MISP removes them on that date.
- **Each new version of the bundle becomes a new event.** The event takes the bundle's ID, which changes with its content. Delete the earlier event first, and use the feeds above for the values that change.

## OpenCTI

1. Make sure the `ImportFileStix` connector is running. Your user needs the capability "Upload knowledge files".
2. Open the **Data import and analyst workbenches** panel (the database icon with a small gear, top right).
3. Upload `feeds/stix2.1-bundle.json`. The connector starts on its own and puts the result in a workbench.
4. Review the workbench and validate it. Nothing enters the platform before that.

OpenCTI stores STIX 2.1 as it is, so the bundle's fields map one to one:

| In the bundle | In OpenCTI |
|---|---|
| Indicators with a STIX pattern | Indicators |
| Confidence 85, 60 or 30 | Confidence level, capped at the importing user's maximum |
| Labels: the framework and `high`, `medium` or `low` | Labels |
| `created_by_ref` | Author |
| The source name and link | External reference |
| `valid_from` and `valid_until` | Validity dates. A decay rule that applies to the indicator replaces `valid_until` with its own |
| Frameworks and named actors | Tools and intrusion sets, with `indicates` and `uses` relationships |

The bundle holds indicators, not observables, so OpenCTI creates no observables from it. Indicators past `valid_until` are marked revoked.

## How this page was checked

The MISP steps were run on November 24, 2026 on MISP 2.5.52 (the project's own container images), over its API, with the lists and the bundle of that date (356 indicators):

- All five plain lists, added as freetext feeds from their raw GitHub addresses, arrived in full with the types in the table above. Pointing a feed at a shorter list and fetching it again removed the dropped values.
- The bundle, uploaded to `/events/upload_stix/2`, became one unpublished event with 290 attributes and 66 objects, plus the original file as an attachment, as described above.
- The menu and field names come from the MISP 2.5 source, not from clicking through the interface.

The bundle also passes `stix2-validator` 3.3.2 as valid STIX 2.1. Its warnings are about the IDs, which are name-based on purpose so they stay the same between builds.

The OpenCTI steps follow the OpenCTI documentation and have not been run on a live OpenCTI. If a step differs on yours, open an issue.
