# KQL Investigation Queries

This document contains KQL queries for SOC Sentinel investigation purposes. These prompts can be copied and pasted directly into Sentinel, with "KeyArtifact" replaced by the appropriate search term relevant to your investigation. The queries come without attached tables unless specified.

---

## Introduction

Kusto Query Language (KQL) is the language used across Azure Monitor, Azure Data Explorer, and Azure Log Analytics (which Microsoft Sentinel uses under the hood). I have always found the following visualization regarding KQL useful:

> _We use KQL to create accurate and efficient queries to identify threats, detections, patterns, and anomalies within our large datasets._

---

## Anatomy of a KQL Query

![image](https://github.com/user-attachments/assets/7d3ad46a-d0d9-4609-be16-a21fcc9bf070)


Below is an example of a basic KQL query:

```KQL
SigninLogs
| where TimeGenerated > ago(14d)
| where UserPrincipalName == "reprise_99@testdomain.com"
| where ResultType == "0"
| where AppDisplayName == "Microsoft Teams"
| project TimeGenerated, Location, IPAddress, UserAgent
```

### Breakdown:
- **`SigninLogs`**: Specifies the table in which to search (e.g., Azure AD sign-in logs).
- **`where TimeGenerated > ago(14d)`**: Filters events from the last 14 days.
- **`where UserPrincipalName == "reprise_99@testdomain.com"`**: Narrows down to specific user activity.
- **`where ResultType == "0"`**: Limits to successful logins (ResultType "0").
- **`where AppDisplayName == "Microsoft Teams"`**: Focuses on sign-ins specifically to Microsoft Teams.
- **`project TimeGenerated, Location, IPAddress, UserAgent`**: Selects only relevant columns for the results.

Now, let's explore some other useful KQL queries for SOC investigations.

---

## Queries

### List All Tables

This query lists all tables and the number of events in each one.

```KQL
search "*"
| summarize count() by $table
| sort by count_ desc
```

### Precise List of Tables by Keyword

This query returns tables related to a specific keyword (`KeyArtifact`).

```KQL
search "*"
| where $table has "KeyArtifact"
| summarize count() by $table
| sort by count_ desc
```

### Phishing Pivot (Last 7 Days)

This query pivots on phishing alerts, filtering the results for the past 7 days and a specific artifact.

```KQL
| where AlertName has "phishing"
| where TimeGenerated >= ago(7d)
| extend KeyArtifact = parse_json(Entities)[0].KeyArtifact
| where KeyArtifact == "<YourKeyArtifactValue>"
| summarize count() by KeyArtifact
```

### Threat IP Pivot (Last 30 Days)

This query tracks the prevalence of a threat IP in the environment over the past 30 days.

```KQL
| where TimeGenerated >= ago(30d)
| extend KeyArtifact = parse_json(Entities)[0].KeyArtifact
| where KeyArtifact == "<YourKeyArtifactValue>"
| summarize count() by KeyArtifact
```

### Detailed Key Artifact Table

This query retrieves detailed metadata for a given artifact and organizes the results into a readable table.

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

### Top 25 IPs Interacting with the Artifact

This query finds the top 25 source IP addresses interacting with the specified artifact.

```KQL
| where Entities has "KeyArtifact"
| extend KeyArtifact = parse_json(Entities)[0].KeyArtifact
| extend Source_IP = parse_json(Entities)[0].Source_IP
| summarize count() by Source_IP
| top 25
```

### Admin Activity Tracker

This query tracks administrator activity based on key artifacts and provides relevant information in a concise table.

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
### MFA Checker
This query retrieves events related to MFA (success or failure) that contain the "KeyArtifact" field and provides detailed information about the event.
```KQL
| where Entities has "KeyArtifact"
| extend KeyArtifact = parse_json(Entities)[0].KeyArtifact
| extend Timestamp = TimeGenerated
| extend Username = parse_json(Entities)[0].Username
| extend Host = parse_json(Entities)[0].Host
| extend Event = parse_json(Entities)[0].Event
| extend Source = parse_json(Entities)[0].Source
| extend IP = parse_json(Entities)[0].IP
| extend Source_IP = parse_json(Entities)[0].Source_IP
| extend Action = parse_json(Entities)[0].Action
| extend Reason = parse_json(Entities)[0].Reason
| extend Result = parse_json(Entities)[0].Result
| extend Status = case(Result == "Success", "Success", Result == "Failure", "Failure", "Unknown")
| summarize count() by Status, Timestamp, Username, Host, Event, Source, IP, Source_IP, Action, Reason, Result
| sort by Timestamp desc
```
---

This document serves as a reference guide for investigation and analysis purposes within Microsoft Sentinel, streamlining threat detection and pattern recognition using KQL.
