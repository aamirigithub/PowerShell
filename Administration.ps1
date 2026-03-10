# System Information and Server Management
| Command                                 | Description                          | Example                                 |
| --------------------------------------- | ------------------------------------ | --------------------------------------- |
| `Get-ComputerInfo`                      | Displays detailed system information | `Get-ComputerInfo`                      |
| `Get-CimInstance Win32_OperatingSystem` | OS information using CIM             | `Get-CimInstance Win32_OperatingSystem` |
| `hostname`                              | Displays server hostname             | `hostname`                              |
| `Get-HotFix`                            | Lists installed patches              | `Get-HotFix`                            |
| `Get-Uptime`                            | Shows system uptime (PS 6+)          | `Get-Uptime`                            |

Below is a **structured reference of essential PowerShell commands for Windows Server Administrators**, organized by administrative domain. This format is useful for system engineers managing **Active Directory, networking, storage, services, security, and automation**.

---
## 1. System Information and Server Management

| Command                                 | Description                          | Example                                 |
| --------------------------------------- | ------------------------------------ | --------------------------------------- |
| `Get-ComputerInfo`                      | Displays detailed system information | `Get-ComputerInfo`                      |
| `Get-CimInstance Win32_OperatingSystem` | OS information using CIM             | `Get-CimInstance Win32_OperatingSystem` |
| `hostname`                              | Displays server hostname             | `hostname`                              |
| `Get-HotFix`                            | Lists installed patches              | `Get-HotFix`                            |
| `Get-Uptime`                            | Shows system uptime (PS 6+)          | `Get-Uptime`                            |

Example:

```powershell
Get-ComputerInfo | Select WindowsProductName, WindowsVersion, OsHardwareAbstractionLayer
```

---

# 2. Process Management

| Command         | Description             |
| --------------- | ----------------------- |
| `Get-Process`   | List running processes  |
| `Stop-Process`  | Terminate process       |
| `Start-Process` | Start a new process     |
| `Wait-Process`  | Wait until process ends |

Examples

```powershell
Get-Process

Stop-Process -Name notepad

Start-Process notepad.exe
```

---

# 3. Windows Service Management

| Command           | Description         |
| ----------------- | ------------------- |
| `Get-Service`     | List services       |
| `Start-Service`   | Start service       |
| `Stop-Service`    | Stop service        |
| `Restart-Service` | Restart service     |
| `Set-Service`     | Change startup type |

Examples

```powershell
Get-Service

Start-Service -Name w32time

Stop-Service -Name spooler

Set-Service -Name spooler -StartupType Automatic
```

---

# 4. Event Log Management

| Command          | Description              |
| ---------------- | ------------------------ |
| `Get-EventLog`   | Read classic event logs  |
| `Get-WinEvent`   | Modern event log command |
| `Clear-EventLog` | Clear event logs         |

Example

```powershell
Get-WinEvent -LogName System -MaxEvents 20
```

---

# 5. Disk and Storage Management

| Command         | Description      |
| --------------- | ---------------- |
| `Get-Disk`      | List disks       |
| `Get-Volume`    | Show volumes     |
| `Get-Partition` | List partitions  |
| `New-Partition` | Create partition |
| `Format-Volume` | Format disk      |

Examples

```powershell
Get-Disk

Get-Volume

Format-Volume -DriveLetter E -FileSystem NTFS
```

---

# 6. File and Directory Management

| Command         | Description        |
| --------------- | ------------------ |
| `Get-ChildItem` | List files         |
| `Copy-Item`     | Copy files         |
| `Move-Item`     | Move files         |
| `Remove-Item`   | Delete files       |
| `New-Item`      | Create file/folder |

Examples

```powershell
Get-ChildItem C:\Logs

Copy-Item file.txt D:\Backup

Remove-Item oldfile.txt
```

---

# 7. Network Management

| Command              | Description               |
| -------------------- | ------------------------- |
| `Get-NetIPAddress`   | View IP addresses         |
| `Get-NetAdapter`     | Network adapter details   |
| `Restart-NetAdapter` | Restart NIC               |
| `Test-NetConnection` | Test network connectivity |
| `Get-NetRoute`       | Show routing table        |

Examples

```powershell
Get-NetIPAddress

Test-NetConnection google.com

Restart-NetAdapter -Name Ethernet
```

---

# 8. Firewall Management

| Command                   | Description          |
| ------------------------- | -------------------- |
| `Get-NetFirewallRule`     | View firewall rules  |
| `New-NetFirewallRule`     | Create firewall rule |
| `Enable-NetFirewallRule`  | Enable rule          |
| `Disable-NetFirewallRule` | Disable rule         |

Example

```powershell
New-NetFirewallRule -DisplayName "Allow HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow
```

---

# 9. User and Group Management (Local)

| Command                | Description       |
| ---------------------- | ----------------- |
| `Get-LocalUser`        | List local users  |
| `New-LocalUser`        | Create user       |
| `Add-LocalGroupMember` | Add user to group |
| `Get-LocalGroup`       | List groups       |

Examples

```powershell
Get-LocalUser

New-LocalUser "backupadmin" -Password (Read-Host -AsSecureString)

Add-LocalGroupMember -Group Administrators -Member backupadmin
```

---

# 10. Active Directory Administration

(Requires **ActiveDirectory module**)

| Command             | Description      |
| ------------------- | ---------------- |
| `Get-ADUser`        | Retrieve AD user |
| `New-ADUser`        | Create user      |
| `Set-ADUser`        | Modify user      |
| `Remove-ADUser`     | Delete user      |
| `Get-ADGroup`       | Get groups       |
| `Add-ADGroupMember` | Add member       |

Examples

```powershell
Import-Module ActiveDirectory

Get-ADUser -Filter *

New-ADUser -Name "John Smith" -SamAccountName jsmith -Enabled $true
```

---

# 11. Windows Updates

| Command                 | Description                              |
| ----------------------- | ---------------------------------------- |
| `Get-WindowsUpdateLog`  | Generate update log                      |
| `Install-WindowsUpdate` | Install updates (PSWindowsUpdate module) |
| `Get-WindowsUpdate`     | Check updates                            |

Example

```powershell
Install-Module PSWindowsUpdate

Get-WindowsUpdate

Install-WindowsUpdate -AcceptAll -AutoReboot
```

---

# 12. Remote Server Management

| Command           | Description                |
| ----------------- | -------------------------- |
| `Enter-PSSession` | Remote interactive session |
| `Invoke-Command`  | Run command remotely       |
| `New-PSSession`   | Create persistent session  |

Examples

```powershell
Enter-PSSession -ComputerName Server01

Invoke-Command -ComputerName Server01 -ScriptBlock {Get-Service}
```

---

# 13. Scheduled Tasks

| Command                  | Description |
| ------------------------ | ----------- |
| `Get-ScheduledTask`      | List tasks  |
| `Register-ScheduledTask` | Create task |
| `Start-ScheduledTask`    | Run task    |

Example

```powershell
Get-ScheduledTask
```

---

# 14. Security and Permissions

| Command               | Description        |
| --------------------- | ------------------ |
| `Get-Acl`             | View permissions   |
| `Set-Acl`             | Modify ACL         |
| `Get-ExecutionPolicy` | View script policy |
| `Set-ExecutionPolicy` | Change policy      |

Examples

```powershell
Get-Acl C:\Data

Set-ExecutionPolicy RemoteSigned
```

---

# 15. Useful Administrative Utilities

| Command         | Description             |
| --------------- | ----------------------- |
| `Get-Command`   | List available commands |
| `Get-Help`      | Get command help        |
| `Get-Module`    | Show installed modules  |
| `Import-Module` | Load module             |

Examples

```powershell
Get-Command

Get-Help Get-Service -Full
```

---

# 16. Server Role and Feature Management

| Command                  | Description       |
| ------------------------ | ----------------- |
| `Get-WindowsFeature`     | List server roles |
| `Install-WindowsFeature` | Install role      |
| `Remove-WindowsFeature`  | Remove role       |

Example

```powershell
Get-WindowsFeature

Install-WindowsFeature Web-Server
```

---

# 17. Registry Management

| Command            | Description       |
| ------------------ | ----------------- |
| `Get-ItemProperty` | Read registry key |
| `Set-ItemProperty` | Modify key        |
| `New-Item`         | Create key        |

Example

```powershell
Get-ItemProperty HKLM:\Software\Microsoft
```

---

# 18. Performance Monitoring

| Command           | Description            |
| ----------------- | ---------------------- |
| `Get-Counter`     | Performance counters   |
| `Measure-Command` | Measure execution time |

Example

```powershell
Get-Counter "\Processor(_Total)\% Processor Time"
```

---

# Recommended Core Commands Every Server Admin Should Know

```
Get-Process
Get-Service
Get-EventLog
Get-NetIPAddress
Test-NetConnection
Get-Volume
Get-WindowsFeature
Get-ADUser
Invoke-Command
Get-ScheduledTask
```

---


1. **Top 150 PowerShell commands every Windows System Engineer must know**

Below is a **curated list of 150 important PowerShell commands (cmdlets) that every Windows System Engineer or Windows Server Administrator should know**. The list is grouped by **administrative domain** to make it easier for learning, operations, and inclusion in technical documentation or books.

---

# Top 150 PowerShell Commands Every Windows System Engineer Must Know

# 1. PowerShell Core & Discovery Commands

These commands help you explore PowerShell capabilities.

| Command          | Purpose                  |
| ---------------- | ------------------------ |
| `Get-Command`    | List available commands  |
| `Get-Help`       | Display help for cmdlets |
| `Update-Help`    | Update help files        |
| `Get-Alias`      | Show command aliases     |
| `Get-Module`     | View loaded modules      |
| `Import-Module`  | Load module              |
| `Remove-Module`  | Remove module            |
| `Install-Module` | Install module           |
| `Find-Module`    | Search module repository |
| `Get-PSDrive`    | View PowerShell drives   |

---

# 2. System Information Commands

| Command            | Purpose                      |
| ------------------ | ---------------------------- |
| `Get-ComputerInfo` | System information           |
| `Get-CimInstance`  | Retrieve system info via CIM |
| `Get-WmiObject`    | Query WMI objects            |
| `Get-HotFix`       | Installed patches            |
| `Get-TimeZone`     | Display system timezone      |
| `Set-TimeZone`     | Set timezone                 |
| `Get-Date`         | Current date/time            |
| `Get-Uptime`       | System uptime                |
| `Get-Host`         | PowerShell host info         |
| `Get-Culture`      | System culture settings      |

---

# 3. File and Folder Management

| Command         | Purpose              |
| --------------- | -------------------- |
| `Get-ChildItem` | List files/folders   |
| `New-Item`      | Create file/folder   |
| `Copy-Item`     | Copy files           |
| `Move-Item`     | Move files           |
| `Remove-Item`   | Delete files         |
| `Rename-Item`   | Rename item          |
| `Set-Location`  | Change directory     |
| `Get-Location`  | Current directory    |
| `Clear-Content` | Remove file contents |
| `Add-Content`   | Append to file       |
| `Set-Content`   | Write to file        |
| `Get-Content`   | Read file            |
| `Out-File`      | Output to file       |
| `Test-Path`     | Check path existence |
| `Split-Path`    | Parse file path      |

---

# 4. Process Management

| Command                 | Purpose                      |
| ----------------------- | ---------------------------- |
| `Get-Process`           | List processes               |
| `Start-Process`         | Start application            |
| `Stop-Process`          | Kill process                 |
| `Wait-Process`          | Wait for process             |
| `Debug-Process`         | Debug process                |
| `Get-ProcessMitigation` | Security mitigation settings |

---

# 5. Windows Service Management

| Command           | Purpose               |
| ----------------- | --------------------- |
| `Get-Service`     | List services         |
| `Start-Service`   | Start service         |
| `Stop-Service`    | Stop service          |
| `Restart-Service` | Restart service       |
| `Suspend-Service` | Pause service         |
| `Resume-Service`  | Resume service        |
| `Set-Service`     | Change service config |
| `New-Service`     | Create service        |

---

# 6. Event Logs & Monitoring

| Command           | Purpose             |
| ----------------- | ------------------- |
| `Get-EventLog`    | Read event logs     |
| `Get-WinEvent`    | Advanced event logs |
| `Clear-EventLog`  | Clear logs          |
| `Limit-EventLog`  | Change log size     |
| `New-EventLog`    | Create log          |
| `Remove-EventLog` | Delete log          |
| `Write-EventLog`  | Write log entry     |

---

# 7. Disk and Storage Management

| Command            | Purpose                |
| ------------------ | ---------------------- |
| `Get-Disk`         | Show disks             |
| `Initialize-Disk`  | Initialize disk        |
| `Get-Partition`    | Show partitions        |
| `New-Partition`    | Create partition       |
| `Remove-Partition` | Delete partition       |
| `Resize-Partition` | Resize partition       |
| `Get-Volume`       | List volumes           |
| `Format-Volume`    | Format disk            |
| `Set-Volume`       | Modify volume settings |
| `Get-PhysicalDisk` | Physical disk info     |

---

# 8. Networking Commands

| Command                      | Purpose               |
| ---------------------------- | --------------------- |
| `Get-NetIPAddress`           | View IP configuration |
| `New-NetIPAddress`           | Assign IP             |
| `Remove-NetIPAddress`        | Remove IP             |
| `Get-NetAdapter`             | Network adapters      |
| `Enable-NetAdapter`          | Enable NIC            |
| `Disable-NetAdapter`         | Disable NIC           |
| `Restart-NetAdapter`         | Restart NIC           |
| `Get-NetRoute`               | Routing table         |
| `Get-NetNeighbor`            | ARP table             |
| `Test-NetConnection`         | Test connectivity     |
| `Resolve-DnsName`            | DNS lookup            |
| `Get-DnsClientServerAddress` | DNS servers           |
| `Set-DnsClientServerAddress` | Change DNS            |

---

# 9. Firewall Management

| Command                   | Purpose             |
| ------------------------- | ------------------- |
| `Get-NetFirewallRule`     | List firewall rules |
| `New-NetFirewallRule`     | Create rule         |
| `Remove-NetFirewallRule`  | Delete rule         |
| `Enable-NetFirewallRule`  | Enable rule         |
| `Disable-NetFirewallRule` | Disable rule        |
| `Set-NetFirewallRule`     | Modify rule         |

---

# 10. User and Group Management (Local)

| Command                   | Purpose          |
| ------------------------- | ---------------- |
| `Get-LocalUser`           | List local users |
| `New-LocalUser`           | Create user      |
| `Set-LocalUser`           | Modify user      |
| `Remove-LocalUser`        | Delete user      |
| `Get-LocalGroup`          | List groups      |
| `Add-LocalGroupMember`    | Add member       |
| `Remove-LocalGroupMember` | Remove member    |

---

# 11. Active Directory Administration

(Requires ActiveDirectory module)

| Command                    | Purpose             |
| -------------------------- | ------------------- |
| `Get-ADUser`               | Retrieve AD user    |
| `New-ADUser`               | Create AD user      |
| `Set-ADUser`               | Modify user         |
| `Remove-ADUser`            | Delete user         |
| `Get-ADGroup`              | View groups         |
| `New-ADGroup`              | Create group        |
| `Add-ADGroupMember`        | Add group member    |
| `Remove-ADGroupMember`     | Remove group member |
| `Get-ADComputer`           | List computers      |
| `New-ADComputer`           | Create computer     |
| `Remove-ADComputer`        | Delete computer     |
| `Get-ADOrganizationalUnit` | List OU             |
| `New-ADOrganizationalUnit` | Create OU           |
| `Move-ADObject`            | Move AD object      |
| `Get-ADDomain`             | Domain information  |

---

# 12. Windows Update Management

| Command                 | Purpose            |
| ----------------------- | ------------------ |
| `Get-WindowsUpdateLog`  | Windows update log |
| `Get-WUList`            | Available updates  |
| `Install-WindowsUpdate` | Install updates    |
| `Hide-WindowsUpdate`    | Hide updates       |

---

# 13. Remote Server Management

| Command            | Purpose                    |
| ------------------ | -------------------------- |
| `Enter-PSSession`  | Interactive remote session |
| `Exit-PSSession`   | Exit session               |
| `Invoke-Command`   | Execute remote command     |
| `New-PSSession`    | Create session             |
| `Get-PSSession`    | View sessions              |
| `Remove-PSSession` | Remove session             |

---

# 14. Scheduled Tasks

| Command                    | Purpose     |
| -------------------------- | ----------- |
| `Get-ScheduledTask`        | List tasks  |
| `Register-ScheduledTask`   | Create task |
| `Start-ScheduledTask`      | Run task    |
| `Stop-ScheduledTask`       | Stop task   |
| `Unregister-ScheduledTask` | Delete task |

---

# 15. Windows Roles and Features

| Command                    | Purpose      |
| -------------------------- | ------------ |
| `Get-WindowsFeature`       | List roles   |
| `Install-WindowsFeature`   | Install role |
| `Uninstall-WindowsFeature` | Remove role  |

---

# 16. Security & Permissions

| Command               | Purpose                |
| --------------------- | ---------------------- |
| `Get-Acl`             | View permissions       |
| `Set-Acl`             | Change permissions     |
| `Get-ExecutionPolicy` | Script policy          |
| `Set-ExecutionPolicy` | Modify policy          |
| `Unblock-File`        | Allow script execution |

---

# 17. Registry Management

| Command            | Purpose               |
| ------------------ | --------------------- |
| `Get-Item`         | Get registry key      |
| `Get-ItemProperty` | Read registry value   |
| `Set-ItemProperty` | Modify registry value |
| `New-Item`         | Create key            |
| `Remove-Item`      | Delete key            |

---

# 18. Performance Monitoring

| Command            | Purpose                |
| ------------------ | ---------------------- |
| `Get-Counter`      | Performance counters   |
| `Measure-Command`  | Measure execution time |
| `Start-Transcript` | Record session         |
| `Stop-Transcript`  | Stop recording         |

---

# 19. PowerShell Automation & Pipeline

| Command          | Purpose              |
| ---------------- | -------------------- |
| `ForEach-Object` | Loop through objects |
| `Where-Object`   | Filter objects       |
| `Sort-Object`    | Sort output          |
| `Select-Object`  | Select properties    |
| `Group-Object`   | Group output         |
| `Measure-Object` | Count objects        |

---

# 20. Data Export & Reporting

| Command            | Purpose         |
| ------------------ | --------------- |
| `Export-CSV`       | Export data     |
| `Import-CSV`       | Import CSV      |
| `ConvertTo-JSON`   | Convert to JSON |
| `ConvertFrom-JSON` | Parse JSON      |
| `Out-GridView`     | GUI data view   |

---

# 10 Most Used PowerShell Commands in Daily Server Administration

```powershell
Get-Process
Get-Service
Get-EventLog
Get-ChildItem
Test-NetConnection
Get-NetIPAddress
Get-Volume
Get-ADUser
Invoke-Command
Get-WindowsFeature
```

---


1. **Top 50 PowerShell scripts every System Engineer should know**
2. **PowerShell troubleshooting commands for Windows Server**
3. **100 real-world PowerShell administration scenarios**


2. **PowerShell automation scripts for daily server administration**
3. **PowerShell commands cheat sheet for your book (very useful appendix)**
4. **50 real-world PowerShell scenarios for Windows Server administrators**


