# Encoded PowerShell Detection Logic

This file documents the detection indicators, telemetry fields, and investigation logic used during the Encoded PowerShell Detection project.

## Primary Detection Source

The primary detection source was Sysmon Event ID `1`, which records process creation activity.

The event provided visibility into:

- Process image
- Parent process
- Command-line arguments
- User context
- Integrity level
- Process GUID
- Execution timestamp

## Detection Indicator 1: ExecutionPolicy Bypass

Suspicious PowerShell execution was identified through the presence of:

```text
-ExecutionPolicy Bypass
```

This parameter can be used to bypass local PowerShell execution policy restrictions.

### Detection Concept

```text
Image = powershell.exe
AND CommandLine contains "-ExecutionPolicy Bypass"
```

### Analyst Review

The presence of this parameter should trigger additional review of:

- User context
- Parent process
- Command-line contents
- Execution source
- Related PowerShell activity

## Detection Indicator 2: EncodedCommand

Encoded PowerShell execution was identified through:

```text
-EncodedCommand
```

### Detection Concept

```text
Image = powershell.exe
AND CommandLine contains "-EncodedCommand"
```

### Why It Matters

The `-EncodedCommand` parameter allows PowerShell commands to be Base64 encoded.

Encoded execution can obscure command intent during initial log review and should be treated as higher-risk activity requiring inspection.

## Combined High-Risk Behavior

The combination of:

```text
-ExecutionPolicy Bypass
```

and:

```text
-EncodedCommand
```

in the same PowerShell execution increases detection priority.

### Detection Concept

```text
Image = powershell.exe
AND CommandLine contains "-ExecutionPolicy Bypass"
AND CommandLine contains "-EncodedCommand"
```

## Parent-Child Process Analysis

PowerShell activity should not be reviewed only by executable name.

The parent process provides important context.

Examples of higher-risk relationships include PowerShell being launched by:

- Microsoft Office applications
- Browser processes
- Script hosts
- Unknown executables

Interactive execution by an administrator may have a different risk level than execution spawned by another application.

## PowerShell Child Process Detection

PowerShell launching other system utilities can provide additional evidence of suspicious activity.

Examples include:

```text
powershell.exe → cmd.exe
```

or PowerShell launching commands such as:

```text
whoami
hostname
```

### Detection Concept

```text
ParentImage = powershell.exe
AND ChildProcess = cmd.exe
```

Additional command-line context should be reviewed before classification.

## Base64 Decoding Workflow

When `-EncodedCommand` is present:

1. Extract the Base64 value from the `CommandLine` field
2. Decode the value
3. Review the resulting command
4. Determine whether the command performs:
   - Reconnaissance
   - Credential access
   - Persistence
   - Lateral movement
   - Network communication
   - Other suspicious behavior

In this simulation, the decoded command was:

```text
whoami
```

The command itself was benign, but the encoded execution method still required investigation.

## Key Telemetry Fields

The following fields were important during analysis:

```text
Image
ParentImage
CommandLine
ParentCommandLine
ProcessGuid
User
IntegrityLevel
Timestamp
```

These fields help establish execution context and reconstruct the process chain.

## False Positive Considerations

Encoded PowerShell activity is not automatically malicious.

Potential legitimate uses may include:

- Administrative scripts
- Enterprise management tools
- Automation frameworks
- Software deployment
- Maintenance activity

Analysts should review:

- User role
- Endpoint baseline
- Maintenance windows
- Parent process
- Frequency of execution
- Decoded command content
- Related network activity
- Additional endpoint events

## Severity Considerations

PowerShell execution containing both:

```text
-ExecutionPolicy Bypass
```

and:

```text
-EncodedCommand
```

should receive elevated scrutiny.

A high-severity alert would be appropriate when the activity is supported by additional suspicious context.

## Example Alert

```text
Alert Name: Suspicious Encoded PowerShell Execution
Severity: High
MITRE Technique: T1059.001
Host: AD01
Process: powershell.exe
CommandLine: Full PowerShell execution string
Decoded Command: whoami
User: Endpoint user context
Process GUID: Unique process identifier
Timestamp: UTC
```

## MITRE ATT&CK Mapping

- `T1566.001` — Phishing: Spearphishing Attachment
- `T1059.001` — Command and Scripting Interpreter: PowerShell
- `T1059` — Command and Scripting Interpreter
- `T1027` — Obfuscated / Compressed Files and Information

## Detection Takeaway

The strongest detection approach is not simply searching for the word `PowerShell`.

Detection should combine:

- Command-line indicators
- Process relationships
- User context
- Encoded content
- Endpoint baseline
- Related activity

This provides better detection fidelity and reduces false positives.
