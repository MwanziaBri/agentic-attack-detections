# Deploy to Microsoft Sentinel

One deployment creates the analytics rules, the hunting queries and the `AGENTIC_IOCs` watchlist in a workspace that has Microsoft Sentinel on. Built by `tools/build_sentinel.py`; do not edit by hand.

Deploy into the resource group that holds the workspace and give the workspace name. You need Contributor (or Microsoft Sentinel Contributor plus deployment rights) on that resource group. Analytics rules start disabled unless you set `enableRules` to true: enable each one once its data source is connected and you have baselined it. Every template carries the whole watchlist, so deploying several of them is safe, and deploying again updates what is there instead of adding copies.

Hunts that hold several example queries become one hunting query per example ("part 1", "part 2"), because a hunting query runs as one query. MITRE sub-techniques show as their parent technique: the Microsoft Sentinel API keeps parent techniques only.

| Template | Analytics rules | Hunting queries | Deploy |
| --- | --- | --- | --- |
| [`agentic-attack-detections.json`](agentic-attack-detections.json) Everything | 20 | 84 | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FThreatDefence%2Fagentic-attack-detections%2Fmain%2Fdeploy%2Fsentinel%2Fagentic-attack-detections.json) |
| [`behaviors.json`](behaviors.json) behaviors | 2 | 9 | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FThreatDefence%2Fagentic-attack-detections%2Fmain%2Fdeploy%2Fsentinel%2Fbehaviors.json) |
| [`agent-zero.json`](agent-zero.json) agent-zero | 0 | 2 | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FThreatDefence%2Fagentic-attack-detections%2Fmain%2Fdeploy%2Fsentinel%2Fagent-zero.json) |
| [`artex.json`](artex.json) artex | 7 | 37 | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FThreatDefence%2Fagentic-attack-detections%2Fmain%2Fdeploy%2Fsentinel%2Fartex.json) |
| [`cairn.json`](cairn.json) cairn | 2 | 6 | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FThreatDefence%2Fagentic-attack-detections%2Fmain%2Fdeploy%2Fsentinel%2Fcairn.json) |
| [`cyberstrikeai.json`](cyberstrikeai.json) cyberstrikeai | 2 | 5 | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FThreatDefence%2Fagentic-attack-detections%2Fmain%2Fdeploy%2Fsentinel%2Fcyberstrikeai.json) |
| [`hermes.json`](hermes.json) hermes | 2 | 4 | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FThreatDefence%2Fagentic-attack-detections%2Fmain%2Fdeploy%2Fsentinel%2Fhermes.json) |
| [`hexstrike.json`](hexstrike.json) hexstrike | 2 | 4 | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FThreatDefence%2Fagentic-attack-detections%2Fmain%2Fdeploy%2Fsentinel%2Fhexstrike.json) |
| [`pentagi.json`](pentagi.json) pentagi | 2 | 5 | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FThreatDefence%2Fagentic-attack-detections%2Fmain%2Fdeploy%2Fsentinel%2Fpentagi.json) |
| [`pentestswarm.json`](pentestswarm.json) pentestswarm | 0 | 3 | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FThreatDefence%2Fagentic-attack-detections%2Fmain%2Fdeploy%2Fsentinel%2Fpentestswarm.json) |
| [`redamon.json`](redamon.json) redamon | 0 | 3 | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FThreatDefence%2Fagentic-attack-detections%2Fmain%2Fdeploy%2Fsentinel%2Fredamon.json) |
| [`strix.json`](strix.json) strix | 1 | 3 | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FThreatDefence%2Fagentic-attack-detections%2Fmain%2Fdeploy%2Fsentinel%2Fstrix.json) |
| [`xalgorix.json`](xalgorix.json) xalgorix | 0 | 3 | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FThreatDefence%2Fagentic-attack-detections%2Fmain%2Fdeploy%2Fsentinel%2Fxalgorix.json) |

Command line:

```bash
az deployment group create -g <resource-group> --template-uri https://raw.githubusercontent.com/ThreatDefence/agentic-attack-detections/main/deploy/sentinel/agentic-attack-detections.json \
  --parameters workspace=<workspace-name> enableRules=false
```
