https://www.starwindsoftware.com/blog/getting-started-with-powershell-and-vmware-vsphere
# *****************************************************************************
# Log in to a vCenter Server or ESX host:              Connect-VIServer       *
# To find out what commands are available, type:       Get-VICommand          *
# To show searchable help for all PowerCLI commands:   Get-PowerCLIHelp       *
# Once youve connected, display all virtual machines:  Get-VM                 *
# If you need more help, visit the PowerCLI community: Get-PowerCLICommunity  *
# *****************************************************************************

# VMware has published the PowerCLI in the PowerShell gallery. In this way, you don’t have to install an application anymore to use PowerCli.
Install-Module -Name VMware.PowerCLI

'OR'

Install-Module -Name VMware.PowerCLI -AllowClobber (worked for me)

# If you have installed the PowerCLI from executable, you need to remove it and install PowerCLI with the above command.
Update-Module -Name VMware.PowerCLI

# When PowerCLI is installed you can run the below command. You can see that 620 cmdlet exists for VMware vSphere.
GET-Command -module *VMware* | measure

# Connect to VMware vCenter
Connect-VIServer -Server <vCenter FQDN> -Credential <Credential variable>

$credential = Get-Credential AM028787
Connect-VIServer -Server cernvirkc1mvc1 -Credential $credential



Get-VM
Get-VM -Name "Win XP SP2"
Get-Help About_OBN
Add-PassthroughDevice
Add-VMHost
Add-VmHostNtpServer
Apply-DrsRecommendation
Apply-VMHostProfile
Connect-VIServer
Copy-DatastoreItem
Copy-HardDisk
Copy-VMGuestFile
Disconnect-VIServer
Dismount-Tools
Export-VApp
Export-VMHostProfile
Get-Annotation
Get-CDDrive
Get-Cluster
Get-CustomAttribute
Get-Datacenter
Get-Datastore
Get-DrsRecommendation
Get-DrsRule
Get-FloppyDrive
Get-Folder
Get-HardDisk
Get-Inventory
Get-IScsiHbaTarget
Get-Log
Get-LogType
Get-NetworkAdapter
Get-NicTeamingPolicy
Get-OSCustomizationNicMapping
Get-OSCustomizationSpec
Get-PassthroughDevice
Get-PowerCLIConfiguration
Get-PowerCLIVersion
Get-ResourcePool
Get-ScsiLun
Get-ScsiLunPath
Get-Snapshot
Get-Stat
Get-StatInterval
Get-StatType
Get-Task
Get-Template
Get-UsbDevice
Get-VApp
Get-VICredentialStoreItem
Get-VIEvent
Get-View
Get-VIObjectByVIView
Get-VIPermission
Get-VIPrivilege
Get-VIRole
Get-VirtualPortGroup
Get-VirtualSwitch
Get-VM
Get-VMGuest
Get-VMGuestNetworkInterface
Get-VMGuestRoute
Get-VMHost
Get-VMHostAccount
Get-VMHostAdvancedConfiguration
Get-VMHostAvailableTimeZone
Get-VMHostDiagnosticPartition
Get-VMHostFirewallDefaultPolicy
Get-VMHostFirewallException
Get-VMHostFirmware
Get-VMHostHba
Get-VMHostModule
Get-VMHostNetwork
Get-VMHostNetworkAdapter
Get-VMHostNtpServer
Get-VMHostProfile
Get-VMHostService
Get-VMHostSnmp
Get-VMHostStartPolicy
Get-VMHostStorage
Get-VMHostSysLogServer
Get-VMQuestion
Get-VMResourceConfiguration
Get-VMStartPolicy
Import-VApp
Import-VMHostProfile
Install-VMHostPatch
Invoke-VMScript
Mount-Tools
Move-Cluster
Move-Datacenter
Move-Folder
Move-Inventory
Move-ResourcePool
Move-Template
Move-VM
Move-VMHost
New-CDDrive
New-Cluster
New-CustomAttribute
New-CustomField
New-Datacenter
New-Datastore
New-DrsRule
New-FloppyDrive
New-Folder
New-HardDisk
New-IScsiHbaTarget
New-NetworkAdapter
New-OSCustomizationNicMapping
New-OSCustomizationSpec
New-ResourcePool
New-Snapshot
New-StatInterval
New-Template
New-VApp
New-VICredentialStoreItem
New-VIPermission
New-VIRole
New-VirtualPortGroup
New-VirtualSwitch
New-VM
New-VMGuestRoute
New-VMHostAccount
New-VMHostNetworkAdapter
New-VMHostProfile
Remove-CDDrive
Remove-Cluster
Remove-CustomAttribute
Remove-CustomField
Remove-Datacenter
Remove-Datastore
Remove-DrsRule
Remove-FloppyDrive
Remove-Folder
Remove-HardDisk
Remove-Inventory
Remove-IScsiHbaTarget
Remove-NetworkAdapter
Remove-OSCustomizationNicMapping
Remove-OSCustomizationSpec
Remove-PassthroughDevice
Remove-ResourcePool
Remove-Snapshot
Remove-StatInterval
Remove-Template
Remove-UsbDevice
Remove-VApp
Remove-VICredentialStoreItem
Remove-VIPermission
Remove-VIRole
Remove-VirtualPortGroup
Remove-VirtualSwitch
Remove-VM
Remove-VMGuestRoute
Remove-VMHost
Remove-VMHostAccount
Remove-VMHostNetworkAdapter
Remove-VMHostNtpServer
Remove-VMHostProfile
Restart-VM
Restart-VMGuest
Restart-VMHost
Restart-VMHostService
Set-Annotation
Set-CDDrive
Set-Cluster
Set-CustomAttribute
Set-CustomField
Set-Datacenter
Set-Datastore
Set-DrsRule
Set-FloppyDrive
Set-Folder
Set-HardDisk
Set-IScsiHbaTarget
Set-NetworkAdapter
Set-NicTeamingPolicy
Set-OSCustomizationNicMapping
Set-OSCustomizationSpec
Set-PowerCLIConfiguration
Set-ResourcePool
Set-ScsiLun
Set-ScsiLunPath
Set-Snapshot
Set-StatInterval
Set-Template
Set-VApp
Set-VIPermission
Set-VIRole
Set-VirtualPortGroup
Set-VirtualSwitch
Set-VM
Set-VMGuestNetworkInterface
Set-VMGuestRoute
Set-VMHost
Set-VMHostAccount
Set-VMHostAdvancedConfiguration
Set-VMHostDiagnosticPartition
Set-VMHostFirewallDefaultPolicy
Set-VMHostFirewallException
Set-VMHostFirmware
Set-VMHostHba
Set-VMHostModule
Set-VMHostNetwork
Set-VMHostNetworkAdapter
Set-VMHostProfile
Set-VMHostService
Set-VMHostSnmp
Set-VMHostStartPolicy
Set-VMHostStorage
Set-VMHostSysLogServer
Set-VMQuestion
Set-VMResourceConfiguration
Set-VMStartPolicy
Shutdown-VMGuest
Start-VApp
Start-VM
Start-VMHost
Start-VMHostService
Stop-Task
Stop-VApp
Stop-VM
Stop-VMHost
Stop-VMHostService
Suspend-VM
Suspend-VMGuest
Suspend-VMHost
Test-VMHostProfileCompliance
Test-VMHostSnmp
Update-Tools
Wait-Task


# vCenter Privileges` The permission assigned to a user will be checked out
Administration >> Access Control >> Roles + Privileges

Role: v-FEUser  (Front End Client Team)
Virtual machine >> Interation
					- Configure CD media
					- Configure floppy media
					- Console Interation
					- Device connection
					- Power Off
					- Power ON
					- VMWare Tools install

Virtual machine >> Configuration >> Upgrade virtual machine compatibility