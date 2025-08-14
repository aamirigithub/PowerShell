# .SYNOPSIS
# Comprehensive Power Shell commands for Systems Engineers
 
# .DESCRIPTION
# This is a handy Power Shell Cheat Sheet for systems engineers.
 
# .DATE
# June 10, 2013
 
# .NOTES
# Author: Aamir Mukhtar
# Web: https://sites.google.com/view/aamirmukhtar/

${Net}
{

net user /domain am0100
net group /domain                                       # Get list of all groups in current domain
net user                                                # returns the list of all user accounts on the local computer
net user /domain										# Get list of all users in current domain
net group /doamin										# Get list of all groups in current domain

net user /domain am0100								# Check user account on local domain
Get-ADUser "am0100" -Server "company.com"			# check user account on another domain

net group /doamin										# Get all groups in domain
net group /domain “Schema Admins”						# Get "Schema Admins" details

net localgroup <your_groupname> /domain

net share												# to check the local shared folders
net start												# to check the services running locally
Net user /add newuseLoginid  newuserPassword /domain	# Add a domain user account
Net user /add newuserLoginid  newuserPassword			# Add new user on local computer:
Net user loginid  /ACTIVE:NO /domain					# Disable/Lock a domain user account:
Net user loginid /ACTIVE:YES  /domain					# To enable/unlock a domain user account:
Net user loginid /Passwordchg:No						# Prevent users from changing their account password:
Net user loginid /Passwordchg:Yes						# To allow users to change their password:
Net user username										# To retrieve the settings of a user:

net localgroup administrators							# get the members of administrators group on local machine

}

${NetSH}
{
# Check Wireless Network

..             - Goes up one context level.
?              - Displays a list of commands.
abort          - Discards changes made while in offline mode.
add            - Adds a configuration entry to a list of entries.
advfirewall    - Changes to the `netsh advfirewall' context.
alias          - Adds an alias.
branchcache    - Changes to the `netsh branchcache' context.
bridge         - Changes to the `netsh bridge' context.
bye            - Exits the program.
commit         - Commits changes made while in offline mode.
delete         - Deletes a configuration entry from a list of entries.
dhcp           - Changes to the `netsh dhcp' context.
dhcpclient     - Changes to the `netsh dhcpclient' context.
dnsclient      - Changes to the `netsh dnsclient' context.
dump           - Displays a configuration script.
exec           - Runs a script file
exit           - Exits the program
firewall       - Changes to the `netsh firewall' context.
help           - Displays a list of commands.
http           - Changes to the `netsh http' context.
interface      - Changes to the `netsh interface' context.
ipsec          - Changes to the `netsh ipsec' context.
lan            - Changes to the `netsh lan' context.
mbn            - Changes to the `netsh mbn' context.
namespace      - Changes to the `netsh namespace' context.
netio          - Changes to the `netsh netio' context.
offline        - Sets the current mode to offline.
online         - Sets the current mode to online.
p2p            - Changes to the `netsh p2p' context.
popd           - Pops a context from the stack.
pushd          - Pushes current context on stack.
quit           - Exits the program.
ras            - Changes to the `netsh ras' context.
routing        - Changes to the `netsh routing' context.
rpc            - Changes to the `netsh rpc' context.
set            - Updates configuration settings.
show           - Displays information.
trace          - Changes to the `netsh trace' context.
unalias        - Deletes an alias.
wcn            - Changes to the `netsh wcn context.
wfp            - Changes to the `netsh wfp context.
winhttp        - Changes to the `netsh winhttp context.
winsock        - Changes to the `netsh winsock context.
wlan           - Changes to the `netsh wlan' context.

netsh wlan show networks
netsh> firewall or Get-Command -Module NetSecurity


}

${WMIC}
{

# The following global switches are available:

/NAMESPACE           Path for the namespace the alias operate against.
/ROLE                Path for the role containing the alias definitions.
/NODE                Servers the alias will operate against.
/IMPLEVEL            Client impersonation level.
/AUTHLEVEL           Client authentication level.
/LOCALE              Language id the client should use.
/PRIVILEGES          Enable or disable all privileges.
/TRACE               Outputs debugging information to stderr.
/RECORD              Logs all input commands and output.
/INTERACTIVE         Sets or resets the interactive mode.
/FAILFAST            Sets or resets the FailFast mode.
/USER                User to be used during the session.
/PASSWORD            Password to be used for session login.
/OUTPUT              Specifies the mode for output redirection.
/APPEND              Specifies the mode for output redirection.
/AGGREGATE           Sets or resets aggregate mode.
/AUTHORITY           Specifies the <authority type> for the connection.
/?[:<BRIEF|FULL>]    Usage information.

# For more information on a specific global switch, type: switch-name /?

The following alias/es are available in the current role:
ALIAS                    - Access to the aliases available on the local system
BASEBOARD                - Base board (also known as a motherboard or system board) management.
BIOS                     - Basic input/output services (BIOS) management.
BOOTCONFIG               - Boot configuration management.
CDROM                    - CD-ROM management.
COMPUTERSYSTEM           - Computer system management.
CPU                      - CPU management.
CSPRODUCT                - Computer system product information from SMBIOS.
DATAFILE                 - DataFile Management.
DCOMAPP                  - DCOM Application management.
DESKTOP                  - User's Desktop management.
DESKTOPMONITOR           - Desktop Monitor management.
DEVICEMEMORYADDRESS      - Device memory addresses management.
DISKDRIVE                - Physical disk drive management.
DISKQUOTA                - Disk space usage for NTFS volumes.
DMACHANNEL               - Direct memory access (DMA) channel management.
ENVIRONMENT              - System environment settings management.
FSDIR                    - Filesystem directory entry management.
GROUP                    - Group account management.
IDECONTROLLER            - IDE Controller management.
IRQ                      - Interrupt request line (IRQ) management.
JOB                      - Provides  access to the jobs scheduled using the schedule service.
LOADORDER                - Management of system services that define execution dependencies.
LOGICALDISK              - Local storage device management.
LOGON                    - LOGON Sessions.
MEMCACHE                 - Cache memory management.
MEMORYCHIP               - Memory chip information.
MEMPHYSICAL              - Computer system's physical memory management.
NETCLIENT                - Network Client management.
NETLOGIN                 - Network login information (of a particular user) management.
NETPROTOCOL              - Protocols (and their network characteristics) management.
NETUSE                   - Active network connection management.
NIC                      - Network Interface Controller (NIC) management.
NICCONFIG                - Network adapter management.
NTDOMAIN                 - NT Domain management.
NTEVENT                  - Entries in the NT Event Log.
NTEVENTLOG               - NT eventlog file management.
ONBOARDDEVICE            - Management of common adapter devices built into the motherboard (system board).
OS                       - Installed Operating System/s management.
PAGEFILE                 - Virtual memory file swapping management.
PAGEFILESET              - Page file settings management.
PARTITION                - Management of partitioned areas of a physical disk.
PORT                     - I/O port management.
PORTCONNECTOR            - Physical connection ports management.
PRINTER                  - Printer device management.
PRINTERCONFIG            - Printer device configuration management.
PRINTJOB                 - Print job management.
PROCESS                  - Process management.
PRODUCT                  - Installation package task management.
QFE                      - Quick Fix Engineering.
QUOTASETTING             - Setting information for disk quotas on a volume.
RDACCOUNT                - Remote Desktop connection permission management.
RDNIC                    - Remote Desktop connection management on a specific network adapter.
RDPERMISSIONS            - Permissions to a specific Remote Desktop connection.
RDTOGGLE                 - Turning Remote Desktop listener on or off remotely.
RECOVEROS                - Information that will be gathered from memory when the operating system fails.
REGISTRY                 - Computer system registry management.
SCSICONTROLLER           - SCSI Controller management.
SERVER                   - Server information management.
SERVICE                  - Service application management.
SHADOWCOPY               - Shadow copy management.
SHADOWSTORAGE            - Shadow copy storage area management.
SHARE                    - Shared resource management.
SOFTWAREELEMENT          - Management of the  elements of a software product installed on a system.
SOFTWAREFEATURE          - Management of software product subsets of SoftwareElement.
SOUNDDEV                 - Sound Device management.
STARTUP                  - Management of commands that run automatically when users log onto the computer system.
SYSACCOUNT               - System account management.
SYSDRIVER                - Management of the system driver for a base service.
SYSTEMENCLOSURE          - Physical system enclosure management.
SYSTEMSLOT               - Management of physical connection points including ports,  slots and peripherals, and proprietary connections points.
TAPEDRIVE                - Tape drive management.
TEMPERATURE              - Data management of a temperature sensor (electronic thermometer).
TIMEZONE                 - Time zone data management.
UPS                      - Uninterruptible power supply (UPS) management.
USERACCOUNT              - User account management.
VOLTAGE                  - Voltage sensor (electronic voltmeter) data management.
VOLUME                   - Local storage volume management.
VOLUMEQUOTASETTING       - Associates the disk quota setting with a specific disk volume.
VOLUMEUSERQUOTA          - Per user storage volume quota management.
WMISET                   - WMI service operational parameters management.

# For more information on a specific alias, type: alias /?

CLASS     - Escapes to full WMI schema.
PATH      - Escapes to full WMI object paths.
CONTEXT   - Displays the state of all the global switches.
QUIT/EXIT - Exits the program.

# For more information on CLASS/PATH/CONTEXT, type: (CLASS | PATH | CONTEXT) /?

}


${gwmi}
{
Get-WmiObject is gwmi        # Alias of Get-WMIObject
gwmi win32_bios
gwmi win32_Bios | fl SerialNumber

get-wmiObject -Class win32_Bios



}

${wmic}
{
wmic bios
wmic bios get serialnumber       # get the serial number of system
wmic /node:<computerName> bios get serialnumber


REMQUERY WMIC BIOS GET SERIALNUMBER
root\CIMV2	SELECT SerialNumber FROM Win32_BIOS
}

${DSquery}
{
To install the DSQUERY command-line tool on the Microsoft Windows operating system, the system must have RSAT (Remote Server Administration Tools) installed.
Windows 2012 -> Server Manager -> Add Roles and Features -> Role based or features based installation -> Remote Access -> Remote server Administration Tools -> 
Role Administration Tools -> AD DS and AD LDS Tools -> Active Directory module for Windows PowerShell

To install RSAT, follow the given below steps

    Go to Apps and Features
    Click Manage optional features
    Click Add a Feature
    Install RSAT
    Go to the Windows Features control panel
    Turn on “Remote Server Administration Tools, Role Administration Tools, and AD DS and AD LDS Tools”


gpudate /force				# Updates multiple Group Policy settings
AuditPol /get /category:*	# audit policy tool, open through command prompt

dsquery 
dsquery computer /? 		# help for finding computers in the directory.
dsquery contact /? 			# help for finding contacts in the directory.
dsquery subnet /? 			# help for finding subnets in the directory.
dsquery group /? 			# help for finding groups in the directory.
dsquery ou /? 				# help for finding organizational units in the directory.
dsquery site /? 			# help for finding sites in the directory.
dsquery server /? 			# help for finding AD DCs/LDS instances in the directory.
dsquery user /? 			# help for finding users in the directory.
dsquery quota /? 			# help for finding quotas in the directory.
dsquery partition /? 		# help for finding partitions in the directory.
dsquery * /? 				# help for finding any object in the directory by using a generic LDAP query.

dsadd /? 					# help for adding objects.
dsget /? 					# help for displaying objects.
dsmod /? 					# help for modifying objects.
dsmove /? 					# help for moving objects.
dsquery /? 					# help for finding objects matching search criteria.
dsrm /? 					# help for deleting objects.

# To find all users with names
dsquery user -name *
dsquery ou -name *

# To find all users with names starting with "mukhtar"
dsquery user -name mukhtar*

# To find all users with names starting with "John" and display his office number:
dsquery user -name John* | dsget user -office

# To find all computers that have been inactive for the last four weeks and remove them from the directory:
dsquery computer -inactive 4 | dsrm

# To read all attributes of the object whose DN is ou=Test,dc=microsoft,dc=com:
dsquery * ou=Test,dc=microsoft,dc=com -scope base -attr *

# DSQuery to list all your Domain Controllers
dsquery server
dsquery server domainroot
dsquery server dc=company,dc=com

# DSQuery to list all the OUs in your domain
dsquery OU dc=company, dc=net
dsquery ou domainroot

# To find all users in the default Users folder with DSQuery
dsquery USER cn=users,dc=company,dc=net

# To query the FSMO roles of your Domain Controllers
dsquery server -hasfsmo schema

# Display all subnets in the London site:
dsquery subnet –site London

# Display a list of computers in the domain whose names begin from AM:
dsquery computer -name AM*

# How to find all members for a particular group.
dsget group ADDMadmins -members

# How to find all groups for a particular member (including nested groups)
dsget user "<DN of the user>" -memberof -expand
dsquery user -samid "username" | dsget user -memberof -expand

# Get the Groups name form Users container
dsquery group -o rdn cn=users,dc=contoso,dc=com
  
# Get the members from a Group
dsquery group -samid "CS_CLUB_ACCOUNTS" | dsget group -members -expand  | dsget user -samid  

# How to find memberof , lastlogontimestamp , homemta(Mail server) , Samaccountname & so on(Repadmin /showattr <DCname> <"DN">)
dsquery * "<DN>" -scope base -attr lastlogontimestamp memberoff 
 
# How to modify user last name.
 dsmod user <dn> -ln "<last name>"

# Find Subnet with associated site.
  dsquery subnet -name <CIDR> | dsget subnet 

# How to find disabled users
  dsquery user "dc=ssig,dc=com" -disabled 

  dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))"

# How to find OS? 
 dsquery * <"DN"> -scope base -attr operatingSystem

# How to find site ?
dsquery site -name * -limit 0
dsquery server -s <server> | dsget server -site 

# How to get tombstonelifetime ?
dsquery * "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=yourdomain,DC=com" -scope base -attr tombstonelifetime 

# How to find mail box? 
dsquery * -filter "samaccountname=biswajit" -attr homemdb  

# How to find the GCs?
DsQuery Server -domain contoso.com -isgc

# How to find all the active users?
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=2))"

# How to find users logon name by their mail address for bulk users?
For Single user
 dsquery * domainroot -filter "(&(objectCategory=Person)(objectClass=User)(mail=e-mailaddress))" -attr name
For bulk users
 for /f %%x in (%1) do dsquery * domainroot -filter "(&(objectcategory=person)(objectclass=user)(mail=%%x))" -attr name


# How to find Schema version?
dsquery * cn=schema,cn=configuration,dc=domainname,dc=local -scope base -attr objectVersion
or
schupgr


Shortest command for finding the schema version


# How to find Site name by server name ?
dsquery server -name test1 | dsget server -site
dsquery server -name (provide the server name for DN) | dsget server -site

# How to find all groups of a user is memberof without the DN's?
dsquery user -samid anthony | dsget user -memberof | dsget group -samid
dsquery user -samid (provide the samaccount name of the user) | dsget user -memberof | dsget group -samid

# How to find all groups if a computer account without giving the DN's ?
dsquery computer -name test1 | dsget computer -memberof | dsget group -samid

# How to find PDC role holder for the existing domain ?
dsquery server -hasfsmo PDC

# How to find Infrastructure Master role holder existing domain ?
dsquery server -hasfsmo INFR

# How to find RID master role holder for existing domain ?
dsquery server -hasfsmo RID

# How to find Schema master role holder in a Forest ?
dsquery server -forest -hasfsmo Schema

# How to find Domain Naming Master in a Forest ?
dsquery server -forest -hasfsmo Name

# How to find if the Domain Controller is a Global Catalog (GC) or not ?
dsquery server -name test1 | dsget server -isgc
 
# How to find subnet with associated site.
dsquery subnet -name 10.222.88.0/25 | dsget subnet

# How to find SID of a user?
dsquery user -samid <bbiswas> | dsget user -sid
dsquery * -filter (samaccountname=santhosh) – attr sid 

# How to find sIDHisotry of a user?
Dsquery * -filter (samaccoutname=santhosh) – attr siDhistory 

# How to find enabled computer accounts in an OU?
dsquery computer OU=Test,DC=sivarajan,DC=com -limit 5000 | dsget computer -dn -disabled | find /i " no"

# How to count enabled computer accounts in an OU?
dsquery computer OU=Test,DC=sivarajan,DC=com -limit 5000 | dsget computer -dn -disabled | find /c /i " no"

# How to find all members for a OU.
dsquery user ou=targetOU,dc=domain,dc=com

# How to find all groups for a OU.
dsquery group ou=targetOU,dc=domain,dc=com

# To get the members status from the active directory group Jump  
dsquery group -samid “Group Pre-Win2k Name” | dsget group -members | dsget user -disabled -display

# Command to find all the subnets for the given site 
dsquery subnet -o rdn -site <site name> 

# Command to find all DCs in the given site
dsquery server -o rdn -site <site name> 

# Command to find all DCs in the Forest
dsquery server -o rdn -forest

# To find all contacts in the organizational unit (OU)
dsquery contact OU=Sales,DC=Contoso,DC=Com

# To list the relative distinguished names of all sites that are defined in the directory
dsquery site -limit 0

# List of all users with primary group "Domain Users"
dsquery * -filter "(primaryGroupID=513)" -limit 0

(You can change the "primaryGroupID" as per your requirement)

513:Domain Users
514:Domain Guests
515:Domain Computers
516:Domain Controllers

# How to find all attributes for all users?
Dsquery * -limit 0 -filter "&(objectClass=User)(objectCategory=Person)" -attr * >>output123.txt

43. Show How Many Times wrong Password has been entered on a specified domain controller.

dsquery * -filter "(sAMAccountName=jsmith)" -s MyServer -attr givenName sn badPwdCount

The badPwdCount attribute is not replicated, so a different value is saved for each user on each domain controller.

44.Expire use account.
dsquery * "dc=contoso,dc=com" -filter "(&(objectCategory=Person)(objectClass=User)(!accountExpires=0)(!accountExpires=9223372036854775807)) " -attr sAMAccountname displayName

Fine Granted Password Policy
45. How to find the 'PSO Applies to'
Jump i)dsget user <user DN> -effectivepso

Example: 

C:\>dsget user "CN=bshwjt,OU=pso,DC=contoso,DC=com" -effectivepso
effectivepso
"CN=test,CN=Password Settings Container,CN=System,DC=contoso,DC=com"
dsget succeeded
("bshwjt" is the user and test is the "PSO" also see the below snap)



ii) How to find the PSO settings
 C:\>dsquery * "<CN=your pso name>,CN=Password Settings Container,CN=System,DC=contoso,DC=com" -scope base -attr *

46. Find out Account Expiry date  

dsquery user -name * -limit 0 | dsget user -samid -acctexpires

47.This example displays all attributes of the contoso.com domain object
dsquery * -filter (dc=contoso) -attr *


48.This complex example displays the names of all attributes (150) that Windows Server 2003 replicates to Global Catalog servers. 
(If the command displays no attributes, ensure that you typed TRUE in capital letters
>dsquery * cn=Schema,cn=Configuration,dc=contoso,dc=com -filter "(&(objectCategory=attributeSchema)(isMemberOfPartialAttributeSet=TRUE))" -limit 0 -attr name


49. How to get all samaacount name ?
dsquery user -o rdn -limit 0

50.The command displays the DNS host name, the site name, and whether the server is Global Catalog (GC) server for each domain controller
dsquery server | dsget server -dnsname -site -isgc

Get all the servers in the forest

dsquery server -forest -limit 0 | dsget server -dnsname -site -isgc
51.The dsget command displays properties of users or other objects. In this example, it displays the 6 groups that explicitly list the Administrator as member

Note: The -memberof -expand combination recursively expands the list of groups of which the user is a member. In this example, the Users group is added to 
the list because Domain Users is a member of the Users group.
dsget user cn=Administrator,cn=Users,dc=contoso,dc=com -memberof 

52.The output of the dsquery command can be used as input for the dsget command by using a pipe ( | ). In this example, the SAM account name and the 
security ID (SID) of each user is displayed.
dsquery user | dsget user -samid -sid -limit 0 >> c:\Allusers-samid-sid.txt

53. # How to find RODC ?
dsquery server -isreadonly

Dsqury for exchange server

54. #How to find the Schema Version for Exchange Servers.

dsquery * CN=ms-Exch-Schema-Version-Pt,cn=schema,cn=configuration,dc=domain,dc=local -scope base -attr rangeUpper

55. #How to find lastLogonTimestamp for all users for a domain

dsquery * -filter "&(objectClass=person)(objectCategory=user)" -attr cn lastLogonTimestamp -limit 0

56. # Inactive users are go to disable state

dsquery * <ou> -filter "(&(objectCategory=Person)(objectClass=User)(!accountExpires=0)(!accountExpires=9223372036854775807))" | dsmod user -disabled yes  

57. # ADDS existing connection point objects 
 

dsquery * forestroot -filter (objectclass=serviceconnectionpoint)


 
58. # Find all Hyper-V hosts in your forest

C:\>dsquery * forestroot -filter "&(cn=Microsoft Hyper-V)(objectCategory=serviceconnectionpoint)" -attr servicebindinginformation >> c:\hyper-v.txt

59. # Find all windows virtual machine in your forest

C:\>dsquery * forestroot -filter "&(cn=windows virtual machine)(objectCategory=serviceconnectionpoint)" -limit 0 -attr * >> c:\allvirtualPCs.txt

 

60.Extract the all groups from an OU with Group Scope & Group Type. Find the below snap for your reference.
C:\>dsquery group "ou=test,dc=gs,dc=com" -limit 0 | dsget group -samid -scope -secgrp
 

 
61.The below example displays a list of users from the OU "Customer Support", 
can then be forwarded to dsget that can provide detailed information about objects.
In the example, the requested user list is headed by the pipe symbol after dsget that 
-outputs then the sAMAccountName for all users and email address. 
If we wanted to carry out modifications to the information returned by DSQuery user list, 
we could send the result to dsmod, which for us is making changes to all users. 
In below snap shows the change in the command ensures that all users of DSQuery 
-user list must change their passwords at next logon.

 

Another way to get the user attributes from an OU. Find the below snap & dsquery for that.
C:\>dsquery * "ou=test,DC=contoso,DC=com" -filter "(&(objectcategory=person)(objectclass=user))" -limit 0 
-attr samaccountname description department title
 

66. # Find the object for DES-Only-Encryption



dsquery * -filter "(UserAccountControl:1.2.840.113556.1.4.803:=2097152)"


67. # Find the DNS servers from all the DNS partitions.



dsquery * "CN=Configuration,DC=contoso,DC=com" -filter "(&(objectClass=crossRef)(objectCategory=crossRef)(systemFlags=5))" -attr NcName msDS-NC-Replica-Locations


Using LDAP Filter.      

68. # How to find particular user attribute using LDAP Filter?


C:\>dsquery * -filter (samaccountname=biz) -attr name whenchanged

  name    whenchanged

  biz     01/03/2014 07:02:14   

69. How to find all disabled users.

}

${Systeminfo}
{
systeminfo.exe                          # Find everything about local system
systeminfo | find /i "Boot Time"		# Find system boot time
net statistics workstation
shutdown -s -f
shutdown -r -f
klist									# List all available login tickets
}

${GPO/policy}
{
# You can use this tool to see what policy is in effect and to troubleshoot policy problems.
GPRESULT
GPresult /R
}

${ DOS }
{
ASSOC          # Displays or modifies file extension associations.
ATTRIB         # Displays or changes file attributes.
BREAK          # Sets or clears extended CTRL+C checking.
BCDEDIT        # Sets properties in boot database to control boot loading.
CACLS          # Displays or modifies access control lists (ACLs) of files.
CALL           # Calls one batch program from another.
CD             # Displays the name of or changes the current directory.
CHCP           # Displays or sets the active code page number.
CHDIR          # Displays the name of or changes the current directory.
CHKDSK         # Checks a disk and displays a status report.
CHKNTFS        # Displays or modifies the checking of disk at boot time.
CLS            # Clears the screen.
CMD            # Starts a new instance of the Windows command interpreter.
COLOR          # Sets the default console foreground and background colors.
COMP           # Compares the contents of two files or sets of files.
COMPACT        # Displays or alters the compression of files on NTFS partitions.
CONVERT        # Converts FAT volumes to NTFS.  You cannot convert the current drive.
COPY           # Copies one or more files to another location.
DATE           # Displays or sets the date.
DEL            # Deletes one or more files.
DIR            # Displays a list of files and subdirectories in a directory.
DISKPART       # Displays or configures Disk Partition properties.
DOSKEY         # Edits command lines, recalls Windows commands, and creates macros.
DRIVERQUERY    # Displays current device driver status and properties.
ECHO           # Displays messages, or turns command echoing on or off.
ENDLOCAL       # Ends localization of environment changes in a batch file.
ERASE          # Deletes one or more files.
EXIT           # Quits the CMD.EXE program (command interpreter).
FC             # Compares two files or sets of files, and displays the differences between them.
FIND           # Searches for a text string in a file or files.
FINDSTR        # Searches for strings in files.
FOR            # Runs a specified command for each file in a set of files.
FORMAT         # Formats a disk for use with Windows.
FSUTIL         # Displays or configures the file system properties.
FTYPE          # Displays or modifies file types used in file extension associations.
GOTO           # Directs the Windows command interpreter to a labeled line in a batch program.
GPRESULT       # Displays Group Policy information for machine or user.
GRAFTABL       # Enables Windows to display an extended character set in graphics mode.
HELP           # Provides Help information for Windows commands.
ICACLS         # Display, modify, backup, or restore ACLs for files and directories.
IF             # Performs conditional processing in batch programs.
LABEL          # Creates, changes, or deletes the volume label of a disk.
MD             # Creates a directory.
MKDIR          # Creates a directory.
MKLINK         # Creates Symbolic Links and Hard Links
MODE           # Configures a system device.
MORE           # Displays output one screen at a time.
MOVE           # Moves one or more files from one directory to another directory.
OPENFILES      # Displays files opened by remote users for a file share.
PATH           # Displays or sets a search path for executable files.
PAUSE          # Suspends processing of a batch file and displays a message.
POPD           # Restores the previous value of the current directory saved by PUSHD.
PRINT          # Prints a text file.
PROMPT         # Changes the Windows command prompt.
PUSHD          #Saves the current directory then changes it.
RD             # Removes a directory.
RECOVER        # Recovers readable information from a bad or defective disk.
REM            # Records comments (remarks) in batch files or CONFIG.SYS.
REN            # Renames a file or files.
RENAME         # Renames a file or files.
REPLACE        # Replaces files.
RMDIR          # Removes a directory.
ROBOCOPY       # Advanced utility to copy files and directory trees
SET            # Displays, sets, or removes Windows environment variables.
SETLOCAL       # Begins localization of environment changes in a batch file.
SC             # Displays or configures services (background processes).
SCHTASKS       # Schedules commands and programs to run on a computer.
SHIFT          # Shifts the position of replaceable parameters in batch files.
SHUTDOWN       # Allows proper local or remote shutdown of machine.
SORT           # Sorts input.
START          # Starts a separate window to run a specified program or command.
SUBST          # Associates a path with a drive letter.
SYSTEMINFO     # Displays machine specific properties and configuration.
TASKLIST       # Displays all currently running tasks including services.
TASKKILL       # Kill or stop a running process or application.
TIME           # Displays or sets the system time.
TITLE          # Sets the window title for a CMD.EXE session.
TREE           # Graphically displays the directory structure of a drive or path.
TYPE           # Displays the contents of a text file.
VER            # Displays the Windows version.
VERIFY         # Tells Windows whether to verify that your files are written correctly to a disk.
VOL            # Displays a disk volume label and serial number.
XCOPY          # Copies files and directory trees.
WMIC           # Displays WMI information inside interactive command shell.	
}

quser

Install-Module -Name VMware.PowerCLI
