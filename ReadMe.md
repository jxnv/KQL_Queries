# KQL Investigation Queries
This document contains KQL queries for SOC Sentinel investigation purposes. These prompts can be copied and pasted directly into Sentinel, with "KeyArtifact" replaced by the appropriate search term relevant to your investigation. These queries come without tables attached.

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
| where AlertName has "phishing"
| where TimeGenerated >= ago(7d)
| extend KeyArtifact = parse_json(Entities)[0].KeyArtifact
| where KeyArtifact == "<YourKeyArtifactValue>"
| summarize count() by KeyArtifact
```
## Threat IP Pivot
```KQL
| where TimeGenerated >= ago(30d)
| extend KeyArtifact = parse_json(Entities)[0].KeyArtifact
| where KeyArtifact == "<YourKeyArtifactValue>"
| summarize count() by KeyArtifact
```

## Detailed Key Artifact Table
```KQL
| where Entities has "KeyArtifact"
| extend KeyArtifact = parse_json(Entities)[0].KeyArtifact
| extend Timestamp = TimeGenerated
| extend Source = parse_json(Entities)[0].Source
| extend Destination = parse_json(Entities)[0].Destination
| extend Source_IP = parse_json(Entities)[0].Source_IP
| extend Destination_IP = parse_json(Entities)[0].Destination_IP
| extend Application = parse_json(Entities)[0].Application
| project Timestamp, KeyArtifact, Source, Destination, Source_IP, Destination_IP, Application
| sort by Timestamp
```
## Top 25 IPs interacting with the Artifacts
```KQL
| where Entities has "KeyArtifact"
| extend KeyArtifact = parse_json(Entities)[0].KeyArtifact
| extend Source_IP = parse_json(Entities)[0].Source_IP
| summarize count() by Source_IP
| top 25
```

## Admin Activity Tracker
```KQL
| where Entities has "KeyArtifact"
| extend KeyArtifact = parse_json(Entities)[0].KeyArtifact
| extend Timestamp = TimeGenerated
| extend Username = parse_json(Entities)[0].Username
| extend Host = parse_json(Entities)[0].Host
| extend Process = parse_json(Entities)[0].Process
| extend CommandLine = parse_json(Entities)[0].CommandLine
| extend Action = parse_json(Entities)[0].Action
| project Timestamp, Username, Host, Process, CommandLine, Action
| sort by Timestamp desc
```
