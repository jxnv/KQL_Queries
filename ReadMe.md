# KQL Investigation Queries
This document contains KQL queries for SOC Sentinel investigation purposes. These prompts can be copied and pasted directly into Sentinel, with "KeyArtifact" replaced by the appropriate search term relevant to your investigation.

## List Tables
```KQL
search "*" 
| summarize count() by $table
| sort by count_ desc
```

## Precise List Tables
```KQL
search "*"
| where $table has "KeyArtifact"
| summarize count() by $table
| sort by count_ desc
```

## Phishing Pivot
```KQL
SecurityAlert
| where AlertName has "phishing"
| where TimeGenerated >= ago(7d)
| extend KeyArtifact = parse_json(Entities)[0].KeyArtifact
| where KeyArtifact == "<YourKeyArtifactValue>"
| summarize count() by KeyArtifact
```
