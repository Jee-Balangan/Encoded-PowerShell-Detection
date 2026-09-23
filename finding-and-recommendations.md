# Encoded PowerShell Findings and Recommendations

This file summarizes the main findings from the Encoded PowerShell Detection project and the defensive improvements recommended based on the telemetry and investigation workflow.

## Key Findings

### 1. Wazuh Successfully Captured the Required Telemetry

The logging pipeline successfully collected Windows, Sysmon, and PowerShell activity.

The environment confirmed visibility into:

- Windows Application logs
- Sysmon Event ID `1`
- PowerShell process creation
- Full command-line arguments
- Parent-child process relationships
- User context
- Integrity level

This showed that the environment had enough telemetry to support investigation of suspicious PowerShell activity.

### 2. ExecutionPolicy Bypass Was Clearly Visible

PowerShell execution using:

`-ExecutionPolicy Bypass`

was captured in Sysmon process creation telemetry.

This confirmed that the SIEM could identify execution behavior commonly associated with phishing payloads and post-exploitation activity.

### 3. Encoded PowerShell Was Detectable

PowerShell execution using:

`-EncodedCommand`

was visible in the collected telemetry.

The Base64 content remained present in the `CommandLine` field, allowing it to be extracted and reviewed.

### 4. Base64 Decoding Was Required to Determine Intent

The encoded command could not be fully evaluated from surface-level telemetry alone.

The Base64 value had to be extracted and decoded before the actual command could be reviewed.

In this simulation, the decoded command was:

`whoami`

The command itself was benign, but the technique demonstrated why encoded content must be inspected during triage.

### 5. Process Context Increased Detection Value

The strongest investigation did not rely only on the presence of `powershell.exe`.

Important context included:

- Parent process
- Command-line arguments
- User context
- Integrity level
- Process GUID
- Related child processes

This information helped determine whether PowerShell activity was expected or suspicious.

### 6. Encoded PowerShell Can Produce False Positives

The presence of `-EncodedCommand` or `-ExecutionPolicy Bypass` does not automatically mean the activity is malicious.

Legitimate administrators, automation tools, and enterprise management software may use similar techniques.

This means detection logic must be tuned using context rather than relying only on keyword matching.

### 7. Combined Indicators Increase Risk

PowerShell activity containing both:

`-ExecutionPolicy Bypass`

and

`-EncodedCommand`

should receive elevated scrutiny.

The combination is more suspicious than either indicator reviewed in isolation.

### 8. Parent-Child Relationships Are Important

PowerShell spawned by another process can provide important context.

PowerShell launched by Office applications, browsers, script hosts, or unknown executables may represent higher-risk activity than interactive use by an administrator.

## Recommendations

### Enable PowerShell Script Block Logging

Enable Script Block Logging to capture PowerShell script content during execution.

This provides deeper visibility into PowerShell behavior and can expose deobfuscated content.

### Enable PowerShell Module Logging

Module Logging should be enabled to improve visibility into cmdlet-level activity.

This can help analysts identify suspicious PowerShell behavior even when commands are encoded or obfuscated.

### Restrict ExecutionPolicy Changes Through Group Policy

Use Group Policy to enforce consistent PowerShell execution settings.

Execution policies are not a security boundary, but centralized policy enforcement can reduce casual bypass activity and improve monitoring consistency.

### Implement Constrained Language Mode

Where appropriate, use Constrained Language Mode to restrict PowerShell functionality for non-administrative users.

This can reduce the ability to abuse advanced PowerShell features.

### Alert on Suspicious PowerShell Child Processes

Monitor for PowerShell spawning processes such as:

- `cmd.exe`
- `wscript.exe`
- Other system utilities

These parent-child relationships can provide useful behavioral indicators.

### Apply Least Privilege

Reduce unnecessary local administrative privileges.

Limiting privilege reduces the potential impact of successful phishing or script execution.

### Tune Detection Rules With Context

Detection logic should account for:

- User role
- Endpoint baseline
- Parent process
- Command content
- Execution frequency
- Maintenance windows
- Related network activity

This helps reduce false positives while preserving useful detection coverage.

### Standardize Base64 Decoding During Triage

When `-EncodedCommand` is identified, analysts should have a consistent process for:

1. Extracting the encoded value
2. Decoding it
3. Reviewing command intent
4. Checking for additional suspicious activity
5. Determining scope and impact

### Correlate Process Relationships

Detection logic should correlate parent and child processes rather than evaluating individual events in isolation.

This can improve detection fidelity and help analysts understand how suspicious PowerShell activity began.

## Overall Security Lesson

The project showed that collecting telemetry is only the first step.

Effective PowerShell detection depends on detailed command-line visibility, process context, encoded-content inspection, and properly tuned detection logic.

The environment captured enough information to support investigation, but analysts still need context and decoding workflows to determine whether suspicious PowerShell activity is actually malicious.
