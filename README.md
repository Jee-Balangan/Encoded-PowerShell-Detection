# Encoded-PowerShell-Detection
PowerShell detection lab focused on encoded commands. Sysmon telemetry, Wazuh analysis, and SOC investigation workflow.

## Project Overview

I built and validated a controlled phishing-style PowerShell simulation to confirm that suspicious PowerShell activity could be captured and investigated through endpoint telemetry.

The project focused on:

- Validating Wazuh log ingestion
- Confirming Sysmon process creation telemetry
- Detecting `ExecutionPolicy Bypass`
- Detecting `-EncodedCommand`
- Reviewing full command-line arguments
- Decoding Base64 content
- Evaluating parent-child process relationships
- Mapping activity to MITRE ATT&CK
- Following a SOC-style investigation workflow

## Environment

### Windows 10 Endpoint

Used to generate Windows Security, Sysmon, and PowerShell telemetry.

### Wazuh SIEM

Used to collect and review endpoint telemetry.

### Ubuntu Server 24.04

Hosted the Wazuh Manager and supported centralized log collection.

### Sysmon

Used to capture detailed process creation activity, including command-line arguments and process relationships.

## Attack Scenario

The simulation represented a phishing-style post-click execution scenario.

The attack flow was:

1. User executes an invoice-themed PowerShell script
2. PowerShell launches
3. `ExecutionPolicy Bypass` is used
4. `-EncodedCommand` is supplied
5. Sysmon Event ID `1` is generated
6. Wazuh receives the telemetry
7. The analyst reviews the command-line data
8. The Base64 string is extracted and decoded
9. The decoded command is evaluated for intent

## Logging Validation

Before running the simulation, I validated that the logging pipeline was working correctly.

This included:

- Confirming the Wazuh agent was active
- Verifying port `1514/tcp` was listening
- Generating a manual Windows Application event
- Confirming log ingestion into Wazuh archives
- Validating Sysmon Event ID `1`
- Confirming full command-line visibility

## PowerShell Execution Policy Bypass

The following behavior was tested:

`powershell -ExecutionPolicy Bypass -File .\Invoice_Update.ps1`

The activity was successfully captured in Sysmon telemetry and Wazuh logs.

The recorded event included:

- `powershell.exe`
- Full command-line arguments
- Parent process information
- Process GUID
- User context
- Integrity level

## Encoded PowerShell Simulation

A test command was converted to Base64 and executed using:

`powershell -ExecutionPolicy Bypass -EncodedCommand <Base64String>`

The encoded string remained visible in the `CommandLine` field within the telemetry.

The Base64 content was then decoded to determine the original command.

In this simulation, the decoded command was:

`whoami`

The command itself was benign, but the execution method demonstrated behavior commonly associated with phishing, malware delivery, and post-exploitation activity.

## SOC Investigation Workflow

The investigation followed a structured analyst workflow:

1. Identify suspicious PowerShell process creation
2. Review high-risk parameters such as:
   - `-ExecutionPolicy Bypass`
   - `-EncodedCommand`
3. Extract key telemetry fields
4. Review parent-child process relationships
5. Extract and decode Base64 content
6. Evaluate command intent
7. Determine scope and impact
8. Classify and escalate based on context

## Key Telemetry Fields

Important fields reviewed during analysis included:

- `Image`
- `ParentImage`
- `CommandLine`
- `ParentCommandLine`
- `User`
- `IntegrityLevel`
- `ProcessGuid`
- `Timestamp`

## MITRE ATT&CK Mapping

- `T1566.001` — Phishing: Spearphishing Attachment
- `T1059.001` — Command and Scripting Interpreter: PowerShell
- `T1059` — Command and Scripting Interpreter
- `T1027` — Obfuscated / Compressed Files and Information

## Detection Artifacts

The investigation identified the following useful detection artifacts:

- Sysmon Event ID `1`
- `powershell.exe`
- `-ExecutionPolicy Bypass`
- `-EncodedCommand`
- Base64 content in command-line telemetry
- Parent-child process relationships
- Full PowerShell command-line visibility in Wazuh

## Detection Considerations

Encoded PowerShell activity is suspicious, but it is not automatically malicious.

Legitimate administrators and automation tools may also use encoded PowerShell.

Context should include:

- User role
- Parent process
- Frequency of execution
- Command content
- Endpoint baseline
- Additional child processes
- Related network activity

## Defensive Recommendations

- Enable PowerShell Script Block Logging
- Enable PowerShell Module Logging
- Restrict ExecutionPolicy changes through Group Policy
- Implement Constrained Language Mode where appropriate
- Alert on suspicious PowerShell child processes
- Apply least privilege
- Tune detection logic using user and process context

## Skills Demonstrated

- Wazuh SIEM
- Sysmon analysis
- PowerShell telemetry
- Base64 decoding
- Command-line analysis
- Process lineage analysis
- SOC triage workflow
- MITRE ATT&CK mapping
- Detection engineering concepts
- False-positive analysis

## Key Takeaway

This project showed that visibility into PowerShell execution depends on collecting detailed endpoint telemetry and reviewing more than just the executable name.

Command-line parameters, parent-child relationships, encoded content, and user context are all important when determining whether PowerShell activity is benign or suspicious.
