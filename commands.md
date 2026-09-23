# Encoded PowerShell Detection Commands

This file documents the commands used to validate logging, simulate suspicious PowerShell execution, generate encoded commands, and decode Base64 content during the lab.

## A. Wazuh and Logging Validation

### Verify Wazuh Agent Status

```bash
sudo /var/ossec/bin/agent_control -l
```

### Verify Wazuh Manager Service

```bash
sudo systemctl status wazuh-manager
```

### Verify Log Ingestion Port

```bash
sudo ss -tulnp | grep 1514
```

### Monitor Wazuh Archive Logs

```bash
sudo tail -f /var/ossec/logs/archives/archives.log
```

## B. Generate a Windows Test Event

This command was used to confirm that Windows Application logs were being collected and forwarded to Wazuh.

```powershell
eventcreate /ID 1000 /L APPLICATION /T INFORMATION /SO TestSource /D "Manual test event"
```

## C. Validate Sysmon Process Creation

A simple command was executed to confirm that Sysmon Event ID `1` was capturing process creation activity and full command-line telemetry.

```powershell
whoami
```

## D. Simulated Phishing Payload Execution

The following command was used to simulate suspicious PowerShell execution using `ExecutionPolicy Bypass`.

```powershell
powershell -ExecutionPolicy Bypass -File .\Invoice_Update.ps1
```

## E. Base64 Encoding Process

A benign test command was converted into Base64 to simulate encoded PowerShell execution.

```powershell
$command = 'whoami'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encoded = [Convert]::ToBase64String($bytes)
```

## F. Execute Encoded PowerShell Command

The generated Base64 string was executed using `-EncodedCommand`.

```powershell
powershell -ExecutionPolicy Bypass -EncodedCommand <Base64String>
```

## G. Decode Base64 Content

The encoded value was decoded to confirm the original command.

```powershell
$decoded = [System.Text.Encoding]::Unicode.GetString(
    [Convert]::FromBase64String($encoded)
)
```

## Command Workflow Summary

The command sequence supported the following workflow:

1. Verify Wazuh connectivity
2. Confirm log ingestion
3. Validate Sysmon process creation telemetry
4. Execute suspicious PowerShell behavior
5. Encode a benign command in Base64
6. Execute the encoded command
7. Confirm the encoded string appears in telemetry
8. Decode the Base64 content
9. Review the resulting command for intent
