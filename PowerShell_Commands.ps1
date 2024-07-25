# .SYNOPSIS
# Comprehensive Power Shell commands for Systems Engineers
 
# .DESCRIPTION
# This is a handy Power Shell Cheat Sheet for systems engineers.
 
# .DATE
# July 15, 2015
 
# .NOTES
# Author: Aamir Mukhtar
# Web: https://sites.google.com/view/aamirmukhtar/

{ ${Online References }
https://www.powershellgallery.com/

# Writing PowerShell module in C#
https://msdn.microsoft.com/en-us/library/dd878294(v=vs.85).aspx

# How to Write a PowerShell Binary Module
https://msdn.microsoft.com/en-us/library/dd878342(v=vs.85).aspx
https://msdn.microsoft.com/en-us/library/dd878297(v=vs.85).aspx # How to Write a Module Manifest
https://msdn.microsoft.com/en-us/powershell/wmf/5.0/releasenotes  # Windows Management Framework (WMF) 5.0 RTM Release Notes Overview

# Windows 2012 server
https://docs.microsoft.com/en-us/powershell/module/grouppolicy/?view=winserver2012r2-ps

# Windows 10 and Windows 2016
https://docs.microsoft.com/en-us/powershell/module/wsus/?view=win10-ps

# Basic Cookbooks 
https://msdn.microsoft.com/en-us/powershell/scripting/getting-started/basic-cookbooks

# Windows Server 2016 and Windows 10
https://technet.microsoft.com/en-us/library/mt156917.aspx

# MCP MAG for powershell
https://mcpmag.com/pages/topic-pages/powershell.aspx

# Shell TIPS
https://technet.microsoft.com/en-us/library/ee692794.aspx

# Powershell Admin
http://www.powershelladmin.com/

# Powershell org
http://www.powershell.org

}


{ ${Linux on Windows / Windows Subsystem for Linux - WSL}
https://docs.microsoft.com/en-us/windows/wsl/install-win10
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux	# Open PowerShell as Administrator and enable WSL
# Go to Windows store and search for WSL. Install Whatever Linux flavor is needed 

}


{ ${PowerShell Information}

# Getting powershell information, version, Build etc
hostname                                   # get the nost name
Get-Host                                   # get details of hosts
(Get-host).Version
$PSversionTable
$PSVersionTable.PSVersion
$env:HOMEPATH
$env:ALLUSERSPROFILE
$env:COMPUTERNAME

${Make custom powershell commands permanent}

 <#
If you like an approach to open PowerShell ISE. 
Copy the function into your ISE session. 
Create a folder in C:\Program Files\Windows PowerShell\Modulesand save the code as psm1 file. 
Make sure that your file name and folder name match. Close PowerShell. 
Open PowerShell again. The command is now available for use.
 #>
eg.
1. Make dir in C:\Program Files\Windows PowerShell\Modules\Test-OpenPort
2. Copy function on notepad and save in above folder as Test-OpenPort.psm1
3. Open PowerShell ISE
4. Execute the command

${Powershell TIPS / TRICKS }

verb-noun --> get-Items
[TAB]								# complete the command
get-alias							# PS command line alias list
gal									# get-alias commands alias
gal cl + [TAB]						# to complete specific command
gal *c*								# wild card usage
get-alias -definitoin <alias>		# search for specific alias definition
update-help -force
get-help <commandlet>
Get-Command
Get-Command *ping*					# Using wild card
man <commandlet>
get-help *service* [option] <mandatory>
get-verb
get-help <commandlet> -detailed or -examples or -full or -online or -show or -showWindow or -displayName
gsv <displayName>
help about_*
cls; help about_*
get-help <command>
get-help -catagory Provider
get-help get-eventlog
Start-Sleep 10						# Sleep for 10 seconds

get-history

ps> get-help *AD*

}


{ ${Help on string, command, examples}

# Displays help about Windows PowerShell cmdlets and concepts.
get-help <cmdlet>
get-help <cmdlet> -Detailed
Get-Help <cmdlet> -Examples
Get-Help <cmdlet> -Full

update-help
Save-Help
get-help services
get-help Get-Command -Detailed
Get-Help Get-ChildItem -Full
get-help Where-Object -full
Get-Help Sort-Object -Full
Get-Help Get-Acl -Examples   # to get example of Get-Acl



# Get help on command on CLI
help set-content
help set-content -showWindow


<# Mother of all cmdLets commands (add, clear. compare, convert, copy, export, format, get, group, import, measure, 
# move, new, out, read, remove, rename, resolve, restart, resume, select, set,sort, split, sstart, stop, suspend, 
tee, test, trace, update, write #>

Get-Command -Verb get
Get-Command -Verb set
Get-Command *help*
Get-Command *help* -CommandType Cmdlet
Get-Command -Noun object
Get-Command -ListImported
Get-Command -CommandType Cmdlet
Get-Command -Module Microsoft.PowerShell.Security
Get-Command Get-AppLockerPolicy
Get-Command Notepad -All
Get-command **-Dns*
Get-command *-dhcp*
Get-command *network*

# List of installed providers
Get-PSProvider

# List avilaable server modules
import-module servermanager

# Get properties and methods of an object
Get-Service | Get-Member

# Aliases
$alias:Dir
Get-Alias -name dir

Get-Alias | Where-Object {$_.Definition -eq "Get-ChildItem"}Dir alias: | Group-Object definition
# Filters
# PowerShell Where-Object filter and its alias ? and $_. means take thing from the current input
Get-ChildItem "C:\Program Files" -recurse | Where-Object {$_.extension -eq ".exe"}
Get-ChildItem "C:\Program Files" -recurse | ? {$_.extension -eq ".exe"}
Get-WmiObject -List | Where-Object {$_.name -Match "Network"}
Gwmi -List | Where {$_.name -Match "Network"}

# Sort
Get-Service | Sort-Object Status
Get-Service | Sort-Object -Descending
Get-service | Get-Member
Get-Service | Sort-Object Status, DisplayName | Format-Table DisplayName, CanStop, Status -groupBy status -auto 

Get-ChildItem -path "C:\windows\" | Sort-Object length -descending
Get-Location    # pwd
Get-ChildItem   # ls or dir

# Get a list of defined variables
Get-Variable

# get history of commands
Get-History | Select-Object -Property  Id, CommandLine,  @{L='ExecutionTime';E={($_.EndExecutionTime-$_.StartExecutionTime)}}

}

# ----------------------- Active Directory ------------------------------
{
# View the cmdlets now available            
Get-Command -Module ActiveDirectory 

# Get AD information
Search-ADAccount -PasswordNeverExpires -UsersOnly
Search-ADAccount -AccountExpired
Search-ADAccount -LockedOut

# Query Active directory Group object
Get-ADGroup -Filter {(cn -eq "serviceaccount")}
Get-ADGroupMember
Get-ADGroup -filter {GroupCategory -eq "Security" -and GroupScope -eq "Global"}
Get-ADGroup -Identity accAdmins -Properties *| Get-Member

# Query Active directory forest
Get-ADForest
Get-ADForest company.com
Get-ADForest -Current LocalComputer
Get-ADForest -Current LoggedOnUser            
Get-ADForest | Get-Member

# Query active directory User Object
Get-ADUser -Filter *
Get-ADUser -Filter {EmailAddress -like "aamir.mukhtar@company.com"}
Get-ADUser -filter {(EmailAddress -like "*") -and (Surname -eq "svcaccaddm")}
Get-ADUser -filter {(cn -eq "svcaccaddm")}
Get-ADUser -filter {(mail -eq "*") -and (sn -eq "Smith")}
Get-ADUser -Identity svcaccaddm -Properties *
Get-ADUser -Identity svcaccaddm -Properties MemberOf

# Query active directory Computer Object
Get-ADComputer -Filter *

Get-ADObject -Filter {(mail -like "*") -and (ObjectClass -eq "user")}

# Query active directory Domain 
Get-ADDomain
get-adDomain <domainName>  

# Verify the ADWS service is running a second hop DC.            
Get-Service ADWS -ComputerName DC1.tailspintoys.local 

# It will show the rules of servers domain wide
ps> Netdom Query FSMO					
ps> Get-WindowsFeature –ComputerName Server01 | Where Installed

# Get list of computers in AD list
Get-ADComputer -LDAPFilter '(objectClass=Computer)' | Select -ExpandProperty Name
Get-ADComputer -Filter 'SamAccountName -like "*2008*"' | Select -Exp Name
Get-ADComputer -Filter * | Where { $_.Name -imatch '2008' } | Select -Exp Name

ps> get-adDomain <domainName>
ps> get-adForest

${Get all hosts/computers in local domain} 
Get-ADComputer -Filter *
Get-ADComputer -Filter * | select Name

${User Account}

Import-module ActiveDirectory							            # To get active directory module installed
Get-ADUser am028787 -Properties *
Get-ADUser am028787 -Properties * | Select-Object LockedOut			# check user lockout status
Search-ADAccount -Locked | Select Name, LockedOut, LastLogonDate	# check user lockout status

# Set a password for a user account using a distinguished name
Set-ADAccountPassword –Identity “CN=JohnThomas,OU=Production Users,DC=TechGenix,DC=Com” –Reset –NewPassword (ConvertTo-SecureString -AsPlainText "ThisPassword001" -Force)

Set-ADAccountPassword –Identity JohnThomas –Reset –NewPassword (ConvertTo-SecureString -AsPlainText "ThisPassword001" -Force)

# Change a specified users password
Set-ADAccountPassword -Identity elisada -OldPassword (ConvertTo-SecureString -AsPlainText "p@ssw0rd" -Force) -NewPassword (ConvertTo-SecureString -AsPlainText "qwert@12345" -Force)

# Prompt a specified user to change their password
Set-ADAccountPassword -Identity EvanNa

Get-ADUser username -properties *
Get-ADUser username -properties *  > get-aduser am0100 -properties *

Invoke-Command {net localgroup administrators} -comp addmprd02 	# get the members of administrators group on remote machine

Get-ADUser "am0100" -Server "company.com"							# check user account on another domain

whoami /groups															# To check which groups I belongs to

Get-ADGroupMember <accAdmins>

# Account Lockout Status Tool

}

# ----------------------- Active Directory ------------------------
{
# install RSAT tools on Powershell before using active directory 

#  Active Directory Trust 

Test-ComputerSecureChannel                                              # Test a channel between the local computer and its domain
Test-ComputerSecureChannel -Server "company.com"                        # Test a channel between the local computer and a domain controller

# Active Directory gMSA Service Account
add-ADSRootKey -EffectiveTime ((get-date).AddHours(-10))                # Generate key for gMSA account

}


# ----------------------- WMI -------------------------------------------
{# Reading WMI Objects
# Win32_OperatingSystem, Win32_LogicalDisk, WIn32_Volume
Get-WmiObject -List
Get-WmiObject -List | Where {$_.name -Match "cim*"}
Get-WmiObject Win32_OperatingSystem
Get-WmiObject Win32_OperatingSystem | Select-Object "Version"
Get-WMIObject Win32_OperatingSystem | findStr "BuildNumber"
Get-WMIObject Win32_OperatingSystem | Select-String "BuildNumber"
Get-WMIObject Win32_OperatingSystem | Select-Xml "BuildNumber"
Get-WmiObject Win32_DiskQuota
Get-WmiObject CheckCheck
Get-WmiObject win32_volume
Get-WmiObject win32_volume | Select-Object FileSystem, Name
Get-WmiObject -Class Win32_UserAccount -Filter  "LocalAccount='True'" | Select PSComputername, Name, Status, Disabled, AccountType, Lockout, PasswordRequired, PasswordChangeable, PasswordExpires, Domain, PasswordLastSet, PasswordAge, PasswordExpiryDate, SID, Description 
Get-WmiObject Win32_Bios | Select-Object *
Get-WmiObject Win32_Bios | Select-Object serialNumber
Get-WmiObject Win32_Bios | Get-Member
Get-WmiObject -query ‘select * from SoftwareLicensingService'
Get-WmiObject -query ‘select * from SoftwareLicensingService' | Select-Object OA3xOriginalProductKey
Get-WmiObject -query 'select * from Win32_Procesor'

# Retrieving Network Adapter Properties
Get-WmiObject -Class Win32_NetworkAdapter -ComputerName .

Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE -ComputerName . | Format-Table -Property IPAddress
Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE -ComputerName .
Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE -ComputerName . | Select-Object -Property [a-z]* -ExcludeProperty IPX*,WINS*
Get-WmiObject -Class Win32_PingStatus -Filter "Address='127.0.0.1'" -ComputerName .
Get-WmiObject -Class Win32_PingStatus -Filter "Address='127.0.0.1'" -ComputerName . | Format-Table -Property Address,ResponseTime,StatusCode -Autosize

Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "DHCPEnabled=true" -ComputerName . | Format-Table -Property DHCP*
# Releasing and Renewing DHCP Leases on All Adapters
Get-WmiObject -List | Where-Object -FilterScript {$_.Name -eq "Win32_NetworkAdapterConfiguration"}

Get-WmiObject -Class win32_Bios
Get-WmiObject -Class win32_Bios -ComputerName server01.company.com
Get-WmiObject -Class win32_Processor -ComputerName server02.company.com | Out-File c:\scripts\test.txt

}

# ---------------------------- Windows Objects -------------------------------
{
# find out installed features
get-module
get-module -ListAvailable			# List available module Packages
Get-WindowsFeature -ComputerName Server1 -Credential contoso.com\user1		# lists features available and installed on the target computer 
get-windowsFeature Web*				# show the available and installed rules of server
Add-WindowsFeature Telnet-Client	# add Telnet-Client feature on the server

# Get list of installed hotfixes
get-hotfix
}

# ----------------------- Windows Registry ------------------------------
{
New-Item:     # Create akey
Remove-Item:  # Delete a key
Test-path:    # Verify whether a key exists

Get-PSDrive
CD HKLM:      # use pwd and dir to check more

Get-ItemProperty:    # Read an entry value
Get-GPRegistryValue: 
Get-ItemPropertyValue
New-ItemProperty:    # Create an entry (key/value pair)
Set-ItemProperty:    # Modify an entry value
Rename-ItemProperty: # Change the key in an entry
Remove-ItemProperty: # Delete an entry

Get-Acl -Path HKLM:\System\CurrentControlSet\Control | Format-List

# Listing Registry Entries
Get-Item -Path HKLM:\System\CurrentControlSet\Control
Get-Item -Path HKLM:\System\CurrentControlSet\Control | Select-Object -ExpandProperty Property
Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion

# Getting a Single Registry Entry
Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion -Name DevicePath

Set-Location -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion
Set-Location -Path hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion

# Creating New Registry Entries
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion -Name PowerShellPath -PropertyType String -Value $PSHome

# Renaming Registry Entries
Rename-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion -Name PowerShellPath -NewName PSHome
Rename-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion -Name PowerShellPath -NewName PSHome -passthru

# Deleting Registry Entries
Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion -Name PSHome
Remove-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion -Name PowerShellPath

#Listening Registry Entries (Cmdlets used: New-Item, Get-Item , New-ItemProperty, Set-ItemProperty, Get-ItemProperty)
Get-Item -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters | Select-Object -ExpandProperty Property

#Get Item Properties
Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters

# Get single registry entry
Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -Name enablesecuritysignature

# Modify value
Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -Name enablesecuritysignature -Value 1

# Listening Registry Entries (Cmdlets used: New-Item, Get-Item , New-ItemProperty, Set-ItemProperty, Get-ItemProperty)
ps> Get-Item -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters | Select-Object -ExpandProperty Property

# Get Item Properties
ps> Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters

# Get single registry entry
ps> Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -Name enablesecuritysignature

# Modify value
ps> Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters -Name enablesecuritysignature -Value 1

}

# ----------------------- System ----------------------------------------
{Measure-Command {$(1..1000)}
Measure-Command {$(1..1000) | Out-Null}
Measure-Command {$(1..1000) > $null}

Measure-Command {[Void]$(1..1000)}
Measure-Command {$null = $(1..1000)}

Get-HotFix
Get-Process
Get-Service
Get-EventLog
Show-EventLog
New-Guid

# USB infr
Get-WmiObject Win32_USBControllerDevice
Get-WmiObject Win32_USBControllerDevice | Foreach-Object { [Wmi]$_.Dependent }
gwmi Win32_USBControllerDevice |%{[wmi]($_.Dependent)} | Sort Manufacturer,Description,DeviceID | Ft -GroupBy Manufacturer Description,Service,DeviceID
GET-WMIOBJECT win32_diskdrive | Where { $_.InterfaceType –eq ‘USB’ }
GET-WMIOBJECT –query “SELECT * from win32_diskdrive where InterfaceType = ‘USB’”

get-service -name bits | get-member
						| select
						| sort

}

${Event Logs}
{
Get-EventLog System -Source Microsoft-Windows-WinLogon -After (Get-Date).AddDays(-5) -ComputerName computername	(logon and logoff history)
Get-EventLog System -Source Microsoft-Windows-WinLogon -Before (Get-Date).AddDays(-5) -ComputerName computername

Get-Eventlog System					# shows system logs for local computer
Get-EventLog -LogName System -Newest 5 -EntryType Error | Format-Table Time,EntryType,Message -AutoSize -Wrap

# Eventlogs
Get-EventLog System -Source Microsoft-Windows-WinLogon -After (Get-Date).AddDays(-5) -ComputerName computername	(logon and logoff history)
Get-EventLog System -Source Microsoft-Windows-WinLogon -Before (Get-Date).AddDays(-5) -ComputerName computername

}

# ----------------------- Out / Input / File / Folder / Directory / Disk -----
{
# Reading input from keyboard
Read-Host -Prompt "Enter your choice "
Read-Host -AsSecureString "Enter your password"
Read-Host -WarningAction Continue

Get-Acl -Path HKLM:\System\CurrentControlSet\Control | Format-List
Export-Csv
Export-Certificate
ConvertTo-Csv
ConvertTo-Html
ConvertTo-Html
ConvertTo-Json
ConvertTo-Xml
Out-File
Out-Printer
Out-Null

Write-Output Here I am ... 
Write-Output 'Here I am ...' | Out-Null
Write-Output "Here I am ..."
Write-Host Here I am ...
Write-Host 'Here I am ...' | Out-Null
Out-Default
Out-File
Out-GridView
Out-Host
Out-Printer
Out-String

Get-Clipboard | Out-Host
Set-Clipboard

# get a list of share folders
Get-WmiObject -Class win32_share
Get-WmiObject -Class win32_Share -ComputerName abcComputer

# Copying Files and Folders
Copy-Item -Path c:\boot.ini -Destination c:\boot.bak
Copy-Item -Path c:\boot.ini -Destination c:\boot.bak -Force
Copy-Item C:\temp\test1 -Recurse c:\temp\DeleteMe
Copy-Item -Filter *.txt -Path c:\data -Recurse -Destination c:\temp\text

# Creating Files and Folders
New-Item -Path 'C:\temp\New Folder' -ItemType "directory"
New-Item -Path 'C:\temp\New Folder\file.txt' -ItemType "file"

# Removing All Files and Folders Within a Folder
Remove-Item C:\temp\DeleteMe
Remove-Item C:\temp\DeleteMe -Recurse

# Mapping a Local Folder as a Windows Accessible Drive
subst p: $env:programfiles

# Reading a Text File into an Array
Get-Content -Path C:\boot.ini
(Get-Content -Path C:\boot.ini).Length

# Getting Disk information
Get-Disk # run as administrator
Get-Disk | Where-Object –FilterScript {$_.Bustype -Eq "USB"}
Get-Disk | Where-Object –FilterScript {$_.BusType -Eq "iSCSI"} | Get-IscsiSession | Format-Table
# getting the disk volume informatoin
Get-Volume
# getting disk partition information
Get-Partition

}

# ----------------------- ZIP Files/Folder ------------------------------
{
Get-ChildItem .\ToZip  | Compress-Archive  -DestinationPath "$PWD\ToZip.zip"  -Verbose 
Get-ChildItem -Filter  *.txt |  Compress-Archive -DestinationPath  .\ToZip.zip -Update  -Verbose 

# Expanding Zip Files using Expand-Archive
New-Item -Name ZipFiles -ItemType  Directory
Expand-Archive -Path .\ToZip.zip -DestinationPath  .\ZipFiles -Verbose 
Get-ChildItem .\ZipFiles

}

# ----------------------- Networking ------------------------------------
{# https://msdn.microsoft.com/en-us/powershell/wmf/5.0/networkswitch_overview
Get-Command *-NetworkSwitch*
Get-NetRoute
Get-NetworkSwitchFeature
Find-NetRoute
Get-NetRoute
Get-BgpRouter

# Gets information about IP address configuration
Get-NetIPAddress
# Gets information about the IP interface properties
Get-NetIPInterface

# Gets information about the IPv4 Protocol configuration.
Get-NetIPv4Protocol

# Gets information about the neighbor cache for IPv4 and IPv6.
Get-NetNeighbor
Get-NetNeighbor –AddressFamily IPv4
Get-NetNeighbor | Format-List –Property *
Get-NetNeighbor –State Reachable | Get-NetAdapter

# gets the global TCP/IP offload settings. These settings include Receive Side Scaling, Receive Segment Coalescing, task offload, and NetworkDirect.
Get-NetOffloadGlobalSetting

#  A computer uses a prefix policy to select source and destination addresses. A prefix policy establishes selection criteria based on the precedence of destination addresses and on labels that are attached to source addresses.
Get-NetPrefixPolicy

# Gets the IP routing table.
Get-NetRoute | Format-List –Property *
Get-NetRoute –InterfaceIndex 12
Get-NetRoute –DestinationPrefix "0.0.0.0/0" | Select-Object –ExpandProperty "NextHop"

# Gets information about current TCP connection statistics.
Get-NetTCPConnection
Get-NetTCPConnection –State Established
Get-NetTCPConnection –AppliedSetting Internet
Get-NetTCPConnection -RemotePort 22
Get-NetTCPConnection -RemoteAddress <String[]> -RemotePort <UInt16[]>

# Gets information about TCP settings and configuration.
Get-NetTCPSetting
Get-NetTCPSetting –Setting Internet
Get-NetTcpSetting | Format-Table

# Gets information about transport filters.
Get-NetTransportFilter

# Gets information about current UDP connection statistics.
Get-NetUDPEndpoint
Get-NetUDPEndpoint –LocalAddress 127.0.0.1

# Get all dynamic port ranges for UDP
Get-NetUDPSetting

# an array to ping multiple computers with a single command
"127.0.0.1","localhost","research.microsoft.com" | ForEach-Object -Process {Get-WmiObject -Class Win32_PingStatus -Filter ("Address='" + $_ + "'") -ComputerName .} | Select-Object -Property Address,ResponseTime,StatusCode

#  ping all of the computers on a subnet
1..254| ForEach-Object -Process {Get-WmiObject -Class Win32_PingStatus -Filter ("Address='192.168.1." + $_ + "'") -ComputerName .} | Select-Object -Property Address,ResponseTime,StatusCode

# Creating a Network Share
(Get-WmiObject -List -ComputerName . | Where-Object -FilterScript {$_.Name -eq "Win32_Share"}).Create("C:\temp","TempShare",0,25,"test share of the temp folder")

# Removing a Network Share
(Get-WmiObject -Class Win32_Share -ComputerName . -Filter "Name='TempShare'").Delete()

# Connecting a Windows Accessible Network Drive
(New-Object -ComObject WScript.Network).MapNetworkDrive("B:", "\\FPS01\users")

# IPCONFIG equivalent
Get-NetIPConfiguration
Get-NetIPAddress | Sort InterfaceIndex | FT InterfaceIndex, InterfaceAlias, AddressFamily, IPAddress, PrefixLength –Autosize
Get-NetIPAddress | ? AddressFamily -eq IPv4 | FT –AutoSize
Get-NetAdapter Wi-Fi | Get-NetIPAddress | FT -AutoSize

# PING equivalent
Test-NetConnection						# This will check a Microsoft edge server and if your internet is working or not
Test-NetConnection www.microsoft.com
Test-NetConnection -ComputerName www.microsoft.com -InformationLevel Detailed
Test-NetConnection -ComputerName www.microsoft.com | Select -ExpandProperty PingReplyDetails | FT Address, Status, RoundTripTime -Autosize

Test-NetConnection <ip address> or <hotname> or <fqdn>		# ping remote host
Test-NetConnection thomasmaurer.ch -CommonTCPPort RDP		# check RDP port
Test-NetConnection thomasmaurer.ch -TraceRoute				# trace route

1..10 | % { Test-NetConnection -ComputerName www.microsoft.com -RemotePort 80 } | FT -AutoSize

# NSLOOKKUP equivalent
Resolve-DnsName www.microsoft.com
Resolve-DnsName microsoft.com -type SOA
Resolve-DnsName microsoft.com -Server 8.8.8.8 –Type A

# ROUTE
Get-NetRoute -Protocol Local -DestinationPrefix 192.168*
Get-NetAdapter Wi-Fi | Get-NetRoute

# TRACERT
Test-NetConnection www.microsoft.com –TraceRoute
Test-NetConnection outlook.com -TraceRoute | Select -ExpandProperty TraceRoute | % { Resolve-DnsName $_ -type PTR -ErrorAction SilentlyContinue }

# NETSTAT
Get-NetTCPConnection | Group State, RemotePort | Sort Count | FT Count, Name -Autosize
Get-NetTCPConnection | ? State -eq Established | FT -Autosize
Get-NetTCPConnection | ? State -eq Established | ? RemoteAddress -notlike 127* | % { $_; Resolve-DnsName $_.RemoteAddress -type PTR -ErrorAction SilentlyContinue }

Get-NetTCPConnection | ? {$_.State -eq “Listen” }			# Locally listening ports

}
${ Port Ping }
{

Test-NetConnection

Test-NetConnection -Port 902 192.168.1.100 -InformationLevel Detailed
Test-NetConnection -Port 80 -ComputerName www.google.com 
Test-NetConnection -ComputerName google.com -TraceRoute

Test-Connection -quiet -computer (Get-Content names.txt) | ForEach (# do something) 
Test-Connection -count 1 -computer (Get-Content names.txt) | ForEach ( # do something with $_.Address )
test-connection addmcrt01 -Count 1 | Select Address,IPv4Address,ResponseTime,BufferSize

$computers = "addmcrt01","addmcrt09","addmprd01"
test-connection $computers -Count 1 | Select Address,IPv4Address,ResponseTime,BufferSize

foreach ($ip in 1..20) {Test-NetConnection -Port 80 -InformationLevel "Detailed" 192.168.1.$ip}		# Test port 80 from IP 1 to 20 in lost

Test-NetConnection addmcrt01 -CommonTCPPort HTTP
test-netconnection addmcrt01 -CommonTCPPort RDP
test-netconnection addmcrt01 -CommonTCPPort SMB -InformationLevel Quiet

# Multi-ports ping
Test-OpenPort -Port 22 addmprd01            # Ping port 22 on target computer 
Test-OpenPorts <host> -Port <port(s)>
Test-OpenPort addmABC10 -Port 80,443,22,135
Test-OpenPort yahoo.com,google.com -Port 80,443
Test-OpenPort 192.168.0.1,google.com -Port 80,443,53 | Sort-Object Status

# For someone who wants to test a port on multiple server and server list is in a txt file
$server = Get-Content -path “C:\ServerList.txt”
Test-OpenPort -Target $server -Port 443 | Sort-Object Status | Out-GridView

-- OR --

$servernames = Read-Host -Prompt “Enter Server Names or IPs separated by commas – no spaces (Then press ENTER)”
$ports = Read-Host -Prompt “Enter Port Numbers Separated by Commas – no spaces (Then press ENTER)”

Test-OpenPort -Target $servernames -Port $ports

param($addmcrt01,$22)
New-Object System.Net.Sockets.TCPClient -ArgumentList $ip, $port


}
${ Internet Connectivity}
{

while ($true) {Test-NetConnection -InformationLevel Quiet}	# Test Microsoft edge becon on internet

}

# ----------------------- DNS Client -----------------------------------

# Adds a rule to the Name Resolution Policy Table (NRPT).
Add-DnsClientNrptRule 	

# Adds a rule to the Name Resolution Policy Table (NRPT).
Clear-DnsClientCache 	

# Clears the contents of the DNS client cache.
Get-DnsClient 	

# Retrieves details of the network interfaces configured on a specified computer.
Get-DnsClientCache 	

# Retrieves the contents of the DNS client cache.
Get-DnsClientGlobalSetting 	

# Retrieves global DNS client settings like the suffix search list.
Get-DnsClientNrptGlobal 	

# Retrieves the Name Resolution Policy Table (NRPT) global settings.
Get-DnsClientNrptPolicy 	

# Retrieves the Name Resolution Policy Table (NRPT) configured on the computer.
Get-DnsClientNrptRule 	

# Retrieves the DNS client Name Resolution Policy Table (NRPT) rules.
Get-DnsClientServerAddress 	

# Gets DNS server IP addresses from the TCP/IP properties on an interface.
Register-DnsClient 	

# Registers all of the IP addresses on the computer onto the configured DNS server.
Remove-DnsClientNrptRule 	

# Removes the specified DNS client Name Resolution Policy Table (NRPT) rule.
Resolve-DnsName 	

# Performs a DNS name query resolution for the specified name.
Set-DnsClient 	

# Sets the interface specific DNS client configurations on the computer.
Set-DnsClientGlobalSetting 	

# Sets the DNS client global, non-interface specific, settings.
Set-DnsClientNrptGlobal 	

# Modifies the global Name Resolution Policy Table (NRPT) settings.
Set-DnsClientNrptRule 	

# Modifies a DNS client Name Resolution Policy Table (NRPT) rule for the specified namespace.
Set-DnsClientServerAddress 	

Sets DNS server addresses associated with the TCP/IP properties on an interface.


# ----------------------- Install / Uninstall ---------------------------
{
# Listing Windows Installer Applications
Get-WmiObject -Class Win32_Product -ComputerName .
Get-WmiObject -Class Win32_Product -ComputerName .  | Format-Wide -Column 1

Get-WmiObject -Class Win32_Product -ComputerName . | Where-Object -FilterScript {$_.Name -eq "Microsoft .NET Framework 2.0"} | Format-List -Property *
Get-WmiObject -Class Win32_Product -ComputerName . -Filter "Name='Microsoft .NET Framework 2.0'"| Format-List -Property *
Get-WmiObject -Class Win32_Product -ComputerName . -Filter Name`=`'Microsoft` .NET` Framework` 2.0`' | Format-List -Property *

# Listing All Uninstallable Applications
Uninstall=HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall
(Get-ChildItem -Path Uninstall:).Count
Get-ChildItem -Path $Uninstall | ForEach-Object -Process { $_.GetValue("DisplayName") }

# Installing Applications
(Get-WMIObject -ComputerName PC01 -List | Where-Object -FilterScript {$_.Name -eq "Win32_Product"}).Install(\\AppSrv\dsp\NewPackage.msi)

# Removing Applications
(Get-WmiObject -Class Win32_Product -Filter "Name='ILMerge'" -ComputerName . ).Uninstall()
Get-ChildItem -Path Uninstall: | ForEach-Object -Process { $_.GetValue("UninstallString") }
Get-ChildItem -Path Uninstall: | Where-Object -FilterScript { $_.GetValue("DisplayName") -like "Win*"} | ForEach-Object -Process { $_.GetValue("UninstallString") }

# Upgrading Windows Installer Applications
(Get-WmiObject -Class Win32_Product -ComputerName . -Filter "Name='OldAppName'").Upgrade(\\AppSrv\dsp\OldAppUpgrade.msi)

Get-Module							# To list the installed modules
Import-Module ActiveDirectory		# importing ActiveDirectory module

Get-HotFix                          # Get hotfix information only
}


# ----------------------- SQL QUERY -------------------------------------
{
Get-Command -Module SQLPS 
Invoke-Sqlcmd -ServerInstance localhost\sql112 -Database master -Query "Select dabase_ID, name FROM sys.database"
Invoke-Sqlcmd -ServerInstance localhost\sql112 -Database master -Query "Select dabase_ID, name FROM sys.database" | Get-Member
Invoke-Sqlcmd -Query "SELECT GETDATE() AS TimeOfQuery;" -ServerInstance "MyComputer\MyInstance" 
Invoke-Sqlcmd -Query "SELECT @@VERSION;" -QueryTimeout 3 

}


# ----------------------- JSON ------------------------------------------
{


}


# ----------------------- Web API --------------------------------------- 
{
Invoke-WebRequest -Uri http://www.google.com | findstr "<head>"
Invoke-WebRequest -Uri http://www.google.com | Select-Object "content"
Invoke-WebRequest -Uri http://www.google.com | Select-Object "content" | Format-List

$R = Invoke-WebRequest -URI http://www.bing.com?q=how+many+feet+in+a+mile
$R.AllElements | where {$_.innerhtml -like "*=*"} | Sort { $_.InnerHtml.Length } | Select InnerText -First 5

# pass the parameters using the method POST
$postParams = @{username='name';moredata='password'}
Invoke-WebRequest -Uri http://addmdev01/ui -Method POST -Body $postParams

# Getting web page status code
(invoke-webrequest  -method head -uri http://www.google.com).statuscode

$page= Invoke-WebRequest https://wiki.company.com/inbox
$page.StatusCode
$page.StatusDescription
$page.links[0]
$page.links | where title -match "Wiki" | Select @{Name="Article";Expression={$_.InnerText}},@{Name="Link";Expression={$_.href}} | format-list

$url = "https://mcpmag.com/rss-feeds/news.aspx" 
$data = invoke-restmethod $url
$data | Select PubDate,Link,Title | out-gridview -title "News"
$data | Select @{Name="Published";Expression={$_.PubDate -as [datetime]}},Title,Link | where Published -gt "08/01/2016" | Sort Published | format-list

# ---------------------------- HTML Reporting --------------------------
Get-Service | ConvertTo-HTML | Out-File Services.html 
Invoke-Item Services.html

Get-Service | Select Name, DisplayName, Status, @{L='RequiredServices';E={$_.RequiredServices  -join '; '}}| ConvertTo-Html | Out-File Services.html
Invoke-Item Services.html


Get-Service | Select Name, DisplayName, Status, @{L='RequiredServices';E={$_.RequiredServices  -join '; '}}|ConvertTo-Html -As List | Out-File Services.html
Invoke-Item Services.html 


}


# ----------------------- Windows Firewall -------------------------------
{
# to get the rules in firewall
Show-NetFirewallRule –PolicyStore ActiveStore
# retrieve a list of inbound rules that apply to all profiles or just the public profile by doing
Get-NetFirewallRule | where {$_.Direction -eq "Inbound" -and (($_.Profile -contains "Any") -or ($_.Profile -contains "Public"))}
Get-NetFirewallRule | where {$_.Direction -eq "Outbound" -and (($_.Profile -contains "Any") -or ($_.Profile -contains "Public"))}

# Adding an Inbound rule
# an application that needs a port exposed you will need to add an inbound exception for this port. Using the Public profile as an example you could do:
New-NetFirewallRule -Name "Custom App Rule (in)" -Description "Our Custom App Rule" -DisplayName "Custom App Rule" -Enabled:True -Profile Public -Direction Inbound -Action Allow -Protocol TCP -LocalPort 4000

# Removing an Inbound rule
Get-NetFirewallRule -Name "Custom App Rule (in)" | Disable-NetFirewallRule

# Updating an existing rule
Get-NetFirewallRule -Name "Custom App Rule (in)" | Set-NetFirewallRule -Action Block

# Firewall logs
%systemroot%\system32\LogFiles\Firewall\pfirewall.log
}


# ----------------------- Download Methods -------------------------------
{
# Download using BITS
Start-BitsTransfer –Source  'https://raw.githubusercontent.com/adbertram/Random-PowerShell-Work/master/IIS/New-IISWebBinding.ps1'  -Destination 'C:\New-IISWebBinding.ps1'

# Download using .Net Webclient
$webClient = New-Object –TypeName System.Net.WebClient
$webClient.DownloadFile('https://raw.githubusercontent.com/adbertram/Random-PowerShell-Work/master/IIS/New-IISWebBinding.ps1','C:\New-IISWebBinding.ps1')

# PS Package Manager
Get-PackageProvider
Get-Package
Get-Package -Name 'Adobe Air' | Install-Package
}

# ----------------------- Encryption ------------------------------------
{
ConvertTo-SecureString -AsPlainText "Here is a string..." -Force | Set-Content -Path C:\Users\AM028787\Documents\Wiki\powerShellSecure.txt
Get-Content -Path C:\Users\AM028787\Documents\Wiki\powerShellSecure.txt | ConvertTo-SecureString
Read-Host -AsSecureString 

$secureIt= ConvertTo-SecureString "hello..." -AsPlainText -Force
$Key = (3,4,2,3,56,34,254,222,1,1,2,23,42,54,33,233,1,34,2,7,6,5,35,43)
$DecryptIt= ConvertFrom-SecureString $secureIt -Key $key
$secureIt

$myString= Read-Host -AsSecureString
$myString 
$Encrypt= ConvertFrom-SecureString -SecureString $myString
$Encrypt
$Decrypt= ConvertTo-SecureString -String $Encrypt
$Decrypt
}


# ----------------------- Package Management ----------------------------
{# Find Package
Find-Package -Provider PowerShellGet -Source PSGallery
Find-Package -Name jquery –Provider NuGet -Source http://www.nuget.org/api/v2/
Find-Package -Name jquery –Provider NuGet –RequiredVersion 2.1.4 -Source nuget.org

# FInd Package provider
Find-PackageProvider #Find all available package providers
Find-PackageProvider -Name "Nuget" -AllVersions  #Find all versions of a provider
Find-PackageProvider -Name "Gistprovider" -Source "PSGallery"  #Find a provider from a specified source

# Get all the packages installed by Programs provider
Get-Package –Provider Programs
# Get all the packages installed by NuGet provider at c:\test using the dynamic
Get-Package –Provider NuGet -Destination c:\test

# Get all currently loaded package providers
Get-PackageProvider
# The following cmdlet will show all the package providers available on the machine (including those that are not loaded):
Get-PackageProvider -ListAvailable

# Get all package sources
Get-PackageSource
# Get all package sources for a specific provider
Get-PackageSource –ProviderName PowerShellGet

# Import a package provider from the local machine
Import-PackageProvider –Name MyProvider

Find-PackageProvider
Install-PackageProvider –Name MyProvider
Find-PackageProvider –Name "Nuget" -AllVersions
Install-PackageProvider -Name "Nuget" -RequiredVersion "2.8.5.201" -Force
Get-PackageProvider –ListAvailable
Import-PackageProvider –Name "Nuget" -RequiredVersion "2.8.5.201" -Verbose
Import-PackageProvider –Name MyProvider –RequiredVersion xxxx -force

# Install Packages
Install-Package -Name jquery -Source nuget.org -Destination c:\test
# Install a package by piping.
Find-Package -Name jquery –Provider NuGet | Install-Package -Destination c:\test
# Install a package provider from the PowerShell Gallery
Install-PackageProvider –Name "Gistprovider" -Verbose
# Install a specified version of a package provider
Find-PackageProvider –Name "Nuget" -AllVersions
Install-PackageProvider -Name "Nuget" -RequiredVersion "2.8.5.201" -Force

# Find a provider and install it
Find-PackageProvider –Name "Gistprovider" | Install-PackageProvider -Verbose

# Install a provider to the current user’s module folder
Install-PackageProvider –Name Gistprovider –Verbose –Scope CurrentUser

# Register Package Source
Register-PackageSource -Name "NugetSource" -Location "http://www.nuget.org/api/v2" –ProviderName nuget

# Saves jquery package to c:\test using NuGetProvider
# Notes that the -Path parameter must point to an existing location
Save-Package -Name jquery –Provider NuGet -Path c:\test

# Save a package by piping.
Find-Package -Name jquery -Source http://www.nuget.org/api/v2/ | Save-Package -Path c:\test
Find-Package -source c:\test

#Set-PackageSource changes the values for a source that has already been registered by running the Register-PackageSource cmdlet. By #running Set-PackageSource, you can change the source name and location.
Set-PackageSource  -Name nuget.org -Location  http://www.nuget.org/api/v2 -NewName nuget2 -NewLocation https://www.nuget.org/api/v2

# Uninstall jquery using nuget
Uninstall-Package -Name jquery –Provider NuGet -Destination c:\test

# Uninstall a package with by piping with Get-Package
Get-Package -Name jquery –Provider NuGet -Destination c:\test | Uninstall-Package

# Unregister a package source for the NuGet provider. You can use command Unregister-PackageSource, to disconnect with a repository, and Get-PackageSource, to discover what the repositories are associated with that provider.
Unregister-PackageSource  -Name "NugetSource"
}

# ----------------------- Modules ---------------------------------------
{# Get built-in modules or stored modules
Get-Module -ListAvailable

Get-Module ActiveDirectory | Format-List  

# View the cmdlets now available            
Get-Command -Module ActiveDirectory  

# Find all modules with tags Azure or DSC
Find-Module -Tag Azure, DSC

# Find modules with a specific DscResource
Find-Module -DscResource xFirewall

#Find modules with specific commands
Find-Module -Command Get-ScriptAnalyzerRule, Invoke-ScriptAnalyzer

# Find all modules with Dsc resources
Find-Module -Includes DscResource

# Find all modules with cmdlets
Find-Module -Includes Cmdlet

# Find all modules with functions
Find-Module -Includes Function

# Find all DSC resources
Find-DscResource

# Find all DSC resources contained within a specific module
Find-DscResource -ModuleName xNetworking

# Find all DSC resources in modules with DSCResourceKit or DesiredStateConfiguration
Find-DscResource -Tag DesiredStateConfiguration, DSCResourceKit

# Find modules using -Filter parameter
# Specified filter value is searched in Name and Description properties
Find-Module -Filter Cookbook -Repository PSGallery
Find-Module -Filter RBAC -Repository PSGallery

#Register a default repository
Register-PSRepository –Name DemoRepo –SourceLocation “https://www.myget.org/F/powershellgetdemo/api/v2” –PublishLocation “<https://www.myget.org/F/powershellgetdemo/api/v2>/package” –InstallationPolicy –Trusted

#Get all of the registered repositories
Get-PSRepository

#Search only the new repository for modules
Find-Module -Repository DemoRepo

#By default, PowerShellGet operates against all registered repositories when none is specified. In this example, the “SomeModule” module is installed from the DemoRepo.
Install-Module SomeModule

#Removing a repository
Unregister-PSRepository DemoRepo

# There is now side-by-side (SxS) module version support in Install-Module, Update-Module, and Publish-Module cmdlets that run in Windows PowerShell 5.0 or newer.
Get-Module -ListAvailable -Name PSScriptAnalyzer | Format-List Name,Version,ModuleBase
Install-Module -Name PSScriptAnalyzer -RequiredVersion 1.1.1 -Repository PSGallery
Get-InstalledModule -Name PSScriptAnalyzer -AllVersions

Install-Module -Name ContosoServer -RequiredVersion 1.0 -Repository MSPSGallery
Get-Module -ListAvailable -Name ContosoServer | Format-List Name,Version,ModuleBase
Install-Module -Name ContosoServer -RequiredVersion 2.0 -Repository MSPSGallery
Get-Module -ListAvailable -Name ContosoServer | Format-List Name,Version,ModuleBase

Get-InstalledModule
Find-Module -Repository GalleryINT -Name ModuleWithDependencies2 -IncludeDependencies

Install-Module -Repository GalleryINT -Name ModuleWithDependencies2 -Scope CurrentUser
Get-Module -Name ModuleWithDependencies2 -ListAvailable

Update-Module -Name ContosoServer -RequiredVersion 1.5
Get-Module -ListAvailable -Name ContosoServer | Format-List Name,Version,ModuleBase

Get-Module -Name ContosoServer -ListAvailable

Publish-Module -Name ContosoServer -RequiredVersion 1.0 -Repository LocalRepo -NuGetApiKey Local-Repo-NuGet-ApiKey
Publish-Module -Path "C:\\Program Files\\WindowsPowerShell\\Modules\\ContosoServer\\2.0" -Repository LocalRepo -NuGetApiKey Local-Repo-NuGet-ApiKey

# Ensure that module dependencies are available on the repository
Find-Module -Repository LocalRepo -Name RequiredModule1,RequiredModule2,RequiredModule3,NestedRequiredModule1,NestedRequiredModule2,NestedRequiredModule3 | Sort-Object -Property Name

# Find the TestDepWithNestedRequiredModules1 module with its dependencies by specifying -IncludeDependencies
Find-Module -Name TestDepWithNestedRequiredModules1 -Repository LocalRepo –IncludeDependencies -MaximumVersion "1.0"

# Use Find-Module metadata to find the module dependencies.
Find-Module -Repository MSPSGallery -Name ModuleWithDependencies2

# Install the TestDepWithNestedRequiredModules1 module with dependencies
Install-Module -Name TestDepWithNestedRequiredModules1 -Repository LocalRepo -RequiredVersion "1.0" Get-InstalledModule

# Update the TestDepWithNestedRequiredModules1 module with dependencies
Find-Module -Name TestDepWithNestedRequiredModules1 -Repository LocalRepo -AllVersions
Update-Module -Name TestDepWithNestedRequiredModules1 -RequiredVersion 2.0

# Run the Uninstall-Module cmdlet to uninstall a module that you installed by using PowerShellGet
Get-InstalledModule -Name RequiredModule1 | Uninstall-Module

# Save-Module cmdlet
Save-Module -Repository MSPSGallery -Name ModuleWithDependencies2 -Path C:\MySavedModuleLocation dir C:\MySavedModuleLocation

# Update-ModuleManifest cmdlet
Get-Content -Path "C:\Temp\PSGTEST-TestPackageMetadata\2.5\PSGTEST-TestPackageMetadata.psd1"
Update-ModuleManifest -Path "C:\Temp\PSGTEST-TestPackageMetadata\2.5\PSGTEST-TestPackageMetadata.psd1"
Get-Content -Path "C:\Temp\PSGTEST-TestPackageMetadata\2.5\PSGTEST-TestPackageMetadata.psd1"
}

# ----------------------- AppLocker -------------------------------------
{

}

# ----------------------- PowerCLI --------------------------------------
{ # http://www.tomsitpro.com/articles/vmware-powercli-cmdlets,2-795.html
# To start using PowerCLI, you have to download it from VMware's site and install it into a Windows operating system.Download the latest PowerCLI version from vmware.com

}

# ----------------------- Manage Remotely -------------------------------
{
# Windows remote management `
https://sid-500.com/2018/08/16/enabling-winrm-for-windows-client-operating-systems-windows-10-windows-8-windows-7/
WinRM						# Windows Remote Management (WinRM) is the Microsoft implementation of the WS-Management protocol which provides a secure way to communicate with local and remote computers using web services.

Get-Service WinRM
Test-WSMan <remoteHost>

# Test connection to remote computer `
Enter-PSSession <hostname>

# Run PowerShell Commands On Remote Computer `
https://sysadminguides.org/2017/04/18/powershell-running-commands-on-remote-computer/
https://sysadminguides.org/2017/05/02/how-to-pass-credentials-in-powershell/
https://www.metisit.com/blog/securely-storing-credentials-with-powershell/

# Get remote computer hardware information `
systeminfo							# it will give system info of local computer
Get-ADComputer -Filter *			# get computers in local domain 
(Get-ADComputer -Filter *).Name | Foreach-Object {Invoke-Command -ComputerName $_ {systeminfo /FO CSV}} | ConvertFrom-Csv | Out-GridView
(Get-ADComputer -Filter *).Name | Foreach-Object {Invoke-Command -ComputerName $_ {systeminfo /FO CSV} -ErrorAction SilentlyContinue} | ConvertFrom-Csv | Out-GridView
(Get-ADComputer -Filter *).Name | Foreach-Object {Invoke-Command -ComputerName $_ {systeminfo /FO CSV} -ErrorAction SilentlyContinue | Select-Object -Skip 1} | ConvertFrom-Csv -Header "Host Name","OS","Version","Manufacturer","Configuration","Build Type","Registered Owner","Registered Organization","Product ID","Install Date","Boot Time","System Manufacturer","Model","Type","Processor","Bios","Windows Directory","System Directory","Boot Device","Language","Keyboard","Time Zone","Total Physical Memory","Available Physical Memory","Virtual Memory","Virtual Memory Available","Virtual Memory in Use","Page File","Domain","Logon Server","Hotfix","Network Card","Hyper-V" | Out-GridView

# Get remote computer software  information `
Get-WmiObject win32_product
Get-CimInstance win32_product
Get-WmiObject Win32_BaseBoard
Get-CimInstance win32_CTRL+SPACE 		# To get all available classes
Get-CimInstance Win32_Product | Get-Member -MemberType Properties
Get-CimInstance win32_product | Select-Object Name, PackageName, InstallDate | Out-GridView

https://sid-500.com/2018/04/02/powershell-how-to-get-a-list-of-all-installed-software-on-remote-computers/
(Get-ADComputer -Filter * -Searchbase "OU=serverName,DC=company,DC=com").Name
(Get-ADComputer -Filter * -Searchbase "OU=Test,DC=sid-500,DC=com").Name | Out-File C:\Temp\Computer.txt | notepad C:\Temp\Computer.txt
Get-CimInstance -ComputerName (Get-Content C:\Temp\Computer.txt) -ClassName win32_product -ErrorAction SilentlyContinue| Select-Object PSComputerName, Name, PackageName, InstallDate | Out-GridView
}

# ----------------------------------- Updates / Patch / Hotfix Management ---------------------------
{
# Get list of installed hotfixes
get-hotfix

# Get the Dotnet version
(Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").Release
(Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").Version

(Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Client").Version

[System.Reflection.Assembly]::GetExecutingAssembly().ImageRuntimeVersion

# WHich version PowerShell using
$psversiontable
[Environment]::Version

# WSUS
https://mcpmag.com/articles/2017/08/10/automate-wsus-using-the-powershell-updateservices.aspx
https://www.powershellmagazine.com/2012/11/07/client-and-patch-management-using-the-updateservices-module/

Get-Module -ListAvailable
Import-Module -Name UpdateServices 
Get-Command -Module  UpdateServices 

# Windows Update
Get-WindowsUpdateLog


}