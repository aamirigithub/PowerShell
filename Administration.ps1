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
2. **PowerShell automation scripts for daily server administration**
3. **PowerShell commands cheat sheet for your book (very useful appendix)**
4. **50 real-world PowerShell scenarios for Windows Server administrators**


