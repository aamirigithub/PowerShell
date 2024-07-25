# Powershell multiple lines commenting
<#
 Author: Aamir Mukhtar
 Date: March 25th, 2014
 Release: v1.0.5
#>

#----------------------------------------------
# Common Shellscripts commands and Snippits
#----------------------------------------------
# Coloring background and foreground
Write-Host -ForegroundColor Yellow "Here is a text..."
Write-Host -BackgroundColor Cyan "Here is a text...."
Write-Host -ForegroundColor DarkYellow -BackgroundColor Cyan "Here is a text....."

$host.PrivateData                 # get a list of color settings
[enum]::GetNames([consolecolor])

$a = (Get-Host).PrivateData
$a.WarningBackgroundColor = "red"
Write-Warning "This is a warning!"

$host.PrivateData.WarningForegroundColor = "Yellow"
Write-Warning "This is a warning!"


$host.UI.RawUI
[console]::ForegroundColor = "grey"    # changes powershell console colors

# PS Console Fonts
$psise.Options.FontSize = 11

# Mathmatics on command prompt
2+2
(12+5) * 3 / 4.5
4GB / 720MB
1MB
0xAF
0xAFFE
10%100
"Hello" + " there"

# Running external commands
ping
Winver
notepad
cmd /c help
"C:\programs\Windows NT\accessories\wordpad.exe"
& "C:\programs\Windows NT\accessories\wordpad.exe"
# Check environment Paths
$env:Path   
$env:Path += ";C:\programs\Windows NT\accessories"   # To add the path in environment
$alias:Dir
$alias:ls

# ------------------------------------------------------
# Running scripts
.\anyScript
.\scritpName.bat
.\scritpName.vbs
.\scritpName.ps1

# Multiline comments
<#
    This is multiline comments
#>

# Defining a String
"This is a string in powershell"

# Defining a variable in different way
$varNum = 10
"$(varNum + 1)"
$variable = "defining a string variable"
"This is a variable too $variable"
'This is a variable too $variable'
"This is a variable too `$variable"
'This is a variable too `$variable'

# Escape characters
# `n: new line, `r: carriage return, `t Tabular, `a: alarm, `b: backspace, `': single qutation mark
# `": double quotation mark, `0: null, ``: backtick character

# Text on several lines
$text = @" 
Here-Strings can easily stretch over several lines and may also include "quotation marks". 
Nevertheless, here, too, variables are replaced with their values: C:\Windows, and 
subexpressions like 4 are likewise replaced with their result. The text will be concluded 
only if you terminate the here-string with the termination symbol "@.
"@
$text

# PowerShell recognizes the following character classes:

\w matches any word character, meaning letters and numbers.
\s matches any white space character, such as tabs, spaces, and so forth.
\d matches any digit character.

 # Defining the Date
 $myDate = [dateTime] "06-22-2016"
 $myDate
 $myNow = (now)
 $myNow

 # Empty the variable
 $myVar = $null

 $result = ping localhost
 $result

 $result = 1MB
 $result

# Continutity of a multiple lines using carret and at sign
"Here is a start '
and it goes to this line"

@"
starts from here
and ends on this line
"@



# Block of executable code, which executes with dot and amperson
{
 Here is a code to execute 
}
. { 2 + 1 }
& { 2 + 1 }

# Block of a code
$variable = [scriptBlock]::Create(1+1) # type variable on prompt and enter, answer will be 2
&$variable # to get variable value

# Cast variables
([int] "2").GetType()
([int] "2").GetType().ToString().GetType()

# Array 
("Item1", "Item2")
("Item1", "Item2")[0]  # to get item 1 in an array
("Item1", "Item2").GetType()
@("Item1", "Item2")
@("Item1", "Item2").GetType()

# Table
@{ Line1 = "Item1"
   Line2 = "Item2"
}
$myVariable = @{ Line1 = "Item1"
   Line2 = "Item2"
}
$myVariable
$myVariable["Line1"]

# Splatting
$mySplat = @{
                Path = "C:\temp\test.txt"
                value = "Hello"
            }
Set-Content @mySplat
Get-Content C:\temp\test.txt

# PS Object
$myObj = @{
           Line1 = "Start of line ..."
           Line2 = "....End of line"
 }
 $myObj
 $myObj.Line1

 <#
 ___________________________________
 Comparision
 =  -eq, -ceq, -ieq
 <> -ne, -cne, ine 
 >  -gt, cgt, igt 
 >= -ge, -cge, -ige
 <  -lt, -clt, -ilt 
 <= -le, -cle, -ile
 -contains, -notContains:  it checks each item between the commas,  requires exact equality, cannot use Wildcards
 -Match/ -notMatch: The 'match' can be anywhere within the string, it can be at begning or end or anywhere, can use wildcards
 -Like/ -notLike: both sides of the expression have to be the same, wildcards * and ? can be used
 Assignment-> = -= +=
 Logical-> -and, -or, -xor, -not
 Redirectional: > >>
 Split and Join-> -split
 Type-> -Is, -Isnot
 Unary $i++
 __________________________________
 #>


 4 -eq 10
 "secret" -eq "SECRET"
 123 -lt 123.5
 -not ($a -gt 5)  !($a -gt 5)
 (($age -ge 18) -and ($sex -eq "m"))
 1,2,3,4,5 -eq 3 # to verify 3 is the member of array
 1,2,3,4,5 -ne 3 # to verify members other than 3

 # Conditions
 If (condition) { code... }
 If (condition) { code .. } Else { code... }
 If (condition) { code... } ElseIf (condition) { Code... } Else { Code... }

 $input = 4
 If ($input -eq 4) { Write-Output "It is a number" } else { Write-Output "It is not a number" }

 $input = "4"
 If ($input -eq 4) { Write-Output "It is a number" } else { Write-Output "It is not a number" }

 $input = "4"
 If ($input -eq "5") { Write-Output "It is a number" } else { Write-Output "It is not a number" }

 $input = "Hello there"
 If ($input -match "Null") { Write-Output "It is a number" } else { Write-Output "It is not a number" }

 [int]$input = "4"
 If ($input -eq 4) { Write-Output "It is a number" } else { Write-Output "It is not a number" }

# Powershell -Match,
$Person ="Guy Thomas 1949"
$Person -Match "Th"

$Person ="Guy Thomas 1949"
$Person -Match "Guido"

$Person ="Guy Thomas 1949"
$Person -Match "1939"

$Person ="Guy Thomas 1949"
$Person -Match "19?9"

# \w is the equivalent of using -Match [a-zA-Z_0-9]
$Person ="Guy Thomas 1949"
$Person -Match "\w"

 # PowerShell -Contains, it checks each item between the commas,  requires exact equality
$Name = "Guy Thomas", "Alicia Moss", "Jennifer Jones" 
$Name -Contains "Alicia Moss"

$Name = "Guy Thomas", "Alicia Moss", "Jennifer Jones" 
$Name -Contains "Jones"

$Name = "Guy Thomas", "Alicia Moss", "Jennifer Jones" 
$Name -Contains "*Jones"

# Having only part of the string is no good for -Like, start of the string not enough, Wildcard * is useful
$Person ="Guy Thomas 1949"
$Person -Like "Th"

$Person ="Guy Thomas 1949"
$Person -Like "Guy"

$Person ="Guy Thomas 1949"
$Person -Like "Guy*"

$Person ="Guy Thomas 1949"
$Person -Like "Gzkuy*"

$Person ="Guy Thomas 1949"
$Person -Like "*Th*"

 # Error Handling
try {
    &myPing $env:localhost -n 1
} 
catch {
    $thisError $_

    "Here is an error $($thisError Exception Message)"
}

try{
    Copy-Item test.txt C:\temp
} catch {
    "You will not catch me.."
}

$myError = "Stop"
try{
    Copy-Item C:\temp\test.txt C:\temp\wmi
} catch {
    "You will not catch me.."
}

 # Switch, Switch -case, Switch -wildcard, Switch -regex
 $value = 1
Switch ($value)
{
 1 { "Number 1" }
 2 { "Number 2" }
 3 { "Number 3" }
}$action = "sAVe"
Switch ($action)
{
 "save" { "I save..." }
 "open" { "I open..." } "print" { "I print..." }
 Default { "Unknown command" }
}$action = "sAVe"
Switch -case ($action)
{
 "save" { "I save..." }
 "open" { "I open..." }
 "print" { "I print..." }
 Default { "Unknown command" }
}$text = "IP address: 10.10.10.10"
Switch -wildcard ($text)
{
 "IP*" { "The text begins with IP: $_" }
 "*.*.*.*" { "The text contains an IP " +
 "address string pattern: $_" }
 "*dress*" { "The text contains the string " +
 "'dress' in arbitrary locations: $_" }
}$text = "IP address: 10.10.10.10"
Switch -regex ($text)
{
 "^IP" { "The text begins with IP: " +
 "$($matches[0])" }
 "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" {
 "The text contains an IP address " +
 "string pattern: $($matches[0])" }
 "\b.*?dress.*?\b" { " The text " +
 "contains the string 'dress' in " +
 "arbitrary locations: $($matches[0])" }
}
$array = 1..5Switch ($array)
{
 {$_ % 2} { "$_ is odd."}
 Default { "$_ is even."}
}
# Loop -> For, ForEach
$random = New-Object system.random
For ($i=0; $i -lt 7; $i++) {
 $random.next(1,49)
}

$array = 1,2,"Hello",'C'
foreach ($element in $array) { "current element: $element" }

# Do While
Do {
 $input = Read-Host "Your homepage"
} While (!($input -like "end"))# Open a file for reading:
$file = [system.io.file]::OpenText("C:\autoexec.bat")
While (!($file.EndOfStream)) {
 $file.ReadLine()
}
$file.close# Simple while loop$i = 0
While ($i -lt 5) {
 $i++
 $i
} While ($true)
{
 $password = Read-Host "Enter password"
 If ($password -eq "secret") {break}
}

 # -------------------------------------------------------
 # Usage of Pipes
 1 | Select-Object
 1 | Select-Object -Last 1
 1, 2 | Measure-Object
 1,2,3,4,5 | Measure-Object -Average -Sum -Maximum -Minimum
 1,2 | %{
    "My Numbers: "
 }
 1,2 | Where-Object { $_ -eq 1 }  # equal
 1,2 | Where-Object { $_ -gt 1 }  # greater than
 1,2 | Where-Object { $_ -lt 2 }  # Less than
 
 # Show Environment variables set for powershell
 dir env:
 $env:windir
 $env:homepath


ping localhost -n 1
ping $env:localhost -n 1

$myPing = "ping"
&myPing $env:localhost

# ------------- Array --------------------------------
{
 $x = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
 $x.Count[0]
 $x.Length
 $x.GetValue(0)

 $a = "one", "two", "three"
 $a.GetValue(0)
}

# ---------- Reading Input/Output -----------------------

$myInput = Read-Host "prompt for input > "
$myInput

Write-Host $myInput
Write-Output $myInput

$myInput | clip   # Clips the variable to clipboard
&notepad          # pop up a notepad, past the clip item

# Write output to text file
Get-Service | Sort-Object Status | Out-File -FilePath C:\temp\PStest.txt
&notepad C:\temp\PStest.txt

# Reading a Text File into an Array
Get-Content -Path C:\boot.ini
(Get-Content -Path C:\boot.ini).Length
$Computers = Get-Content -Path C:\temp\DomainMembers.txt

# Write output to deault printer
Get-Service | Out-Printer -FilePath C:\temp\PStest.txt

# Write output to others
Get-Service | Out-Host -Paging
Get-Service | Out-Null

# Writing block of output to a file
$(
    Write-Output "Here is my message..."
    Get-Service
) *>&1 > C:\temp\PStest.txt

$(
    Write-Output "Here is my message..."
    Get-Service
) 2>&1 > C:\temp\PStest.txt

$(
    Write-Output "Here is my message..."
    Get-Service
) | Tee-Object -FilePath C:\temp\PStest.txt

$(
    Write-Output "Here is my message..."
    Get-Service
) *>&1 | Tee-Object -FilePath C:\temp\PStest.txt

$(
    Write-Output "Here is my message..."
    Get-Service
) | Out-File -FilePath C:\temp\PStest.txt


# writing output to CSV file
$myCSV = Get-ChildItem C:\temp
$myCSV | Measure-Object
$myCSV | ConvertTo-Csv | Set-Content c:\temp\csvFile.csv
&notepad C:\temp\csvFile.csv

# Arrange with required columns only
$myCSV = Get-Content C:\temp\csvFile.csv | ConvertFrom-Csv
$myCSV | Select-Object -Property name, attributes | ConvertTo-Csv | Set-Content C:\temp\csvFile.csv
&notepad C:\temp\csvFile.csv

# Fully serialized .NET object stored to a file. there is Import-CliXML
$myXML = Get-ChildItem c:\temp
$myXML | Select-Object -Property Name, Attributes | Export-Clixml c:\temp\xmlFile.xml
&notepad c:\temp\xmlFile.xml

# Converting to XML
$myXML | Select-Object -Property Name, Attributes | 
         ConvertTo-Xml | 
         Select-Object -ExpandProperty OuterXML | 
         Set-Content c:\temp\newXMLfile.xml


# --------------------- Function ---------------------------
function myFun { ping -n 1 -w 100 $args }
myFun localhost

function add ($num1, $num2){
    return $num1 + $num2
}
add 2 2

function add ([int]$num1, [int]$num2){
    return $num1 + $num2
}
add 2 2
$result = add 2 2

function Weekday ([datetime]$date=$(Get-Date))
{
 $date.DayOfWeek
}weekday 06.17.1200
Function Prompt { "Vulnerability Check > " }



# Objects
$myName = New-Object object

<# Useable modules 

First rename the .ps1 file to MyFunctions.psm1.  For Import-Module to see the module 
it has to be in the default path of the modules folder is 
$home\Documents\WindowsPowerShell\Modules.
Directory: C:\Program Files (x86)\Microsoft SQL Server\110\Tools\PowerShell\Modules
Directory: C:\windows\system32\WindowsPowerShell\v1.0\Modules
Directory: C:\Users\AM028787\Documents\WindowsPowerShell\Modules

#>
Get-Module -listavailable
Import-Module myFunctions
Get-Command -module myFunctions

# working with registry
Test-Path "HKLM:\Software"
Test-Path C:\temp

# Function to check path in Registry
function RegistryKeyExists([string] $keyPath)
{
    return Test-Path "$keyPath";
}
RegistryKeyExists "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"

# Function to check key in Registry
function Test-RegistryEntry ([string]$key, [string]$val)
{

    Get-ItemPropertyValue -Path "$key" -Name "$val" -ErrorAction SilentlyContinue | Out-Null;
    return $?;
    
}
Test-RegistryEntry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoRun"

# Function to check the value of Key
function Test-RegistryValue ([string] $key, [string] $name)
{
    Get-ItemProperty -Path $key -Name $name -ErrorAction SilentlyContinue | Out-Null;
    return $?;
}
Test-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoRun"

# Function to check value
function Read-RegistryEntry ([string] $ikey, [string] $iname)
{   
    if ( Test-RegistryEntry $ikey $iname )
    {         
        return (Get-ItemProperty -Path $ikey -Name $iname).$iname;       
    }
    else
    {
        return '';
    }
}
Read-RegistryEntry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoRun"

# Function to create a path
function CreateRegistryKey([string] $keyPath)
{   
    if ( -not (Test-Path $keyPath) )
    {
        New-Item -Path "$keyPath";
        Write-Output "The Key [$keyPath] is created.";
    }
    else
    {
        Write-Output "The Key [$keyPath] already exists.";
    }
}

# Function to add a value
function Set-RegistryEntry ([string] $key, [string] $name, [string] $value, [string] $type)
{
    if ( -not (Test-RegistryEntry $key $name) )
    {
        if ( ($type -eq 'DWORD') -or ( $type -eq 'String' ) )
        {
            New-ItemProperty -Path $key -Name $name -PropertyType $type -Value $value;
        }   
    }
}

# ------------------- Classes ----------------------------------------
class myClass { code_here.....}
enum myEnum { Enum1=[color]::Blue}

class newClass
{
    DoSomething($x)
    {
        $this._doSomething($x) # method syntax
    }
    private _doSomething($a) {}
}
$b = [MyClass]::new()
$b.DoSomething(42)

# Define a class
class TypeName
{
   # Property with validate set
   [ValidateSet("val1", "Val2")]
   [string] $P1

   # Static property
   static [hashtable] $P2

   # Hidden property does not show as result of Get-Member
   hidden [int] $P3

   # Constructor
   TypeName ([string] $s)
   {
       $this.P1 = $s       
   }

   # Static method
   static [void] MemberMethod1([hashtable] $h)
   {
       [TypeName]::P2 = $h
   }

   # Instance method
   [int] MemberMethod2([int] $i)
   {
       $this.P3 = $i
       return $this.P3
   }
}

<# ------------------- Read/Write XML file ----------------------------
    http://www.powershellmagazine.com/2013/08/19/mastering-everyday-xml-tasks-in-powershell/
    Path of XML sample file was saved:
#>

$Path = "C:\Users\AM0100\Documents\Wiki\STIG_TEST.ckl"
 
# load it into an XML object:
$xml = New-Object -TypeName XML
$xml.Load($Path)
# always make sure your node names do not contain spaces
 
# simply traverse the nodes and select the information you want:
# $Xml.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA | Select-Object -Property SID_NAME, SID_DATA

$STATUS = $Xml.CHECKLIST.STIGS.iSTIG.VULN | Select-Object -Property STATUS
$NEWVAL = $Xml.CHECKLIST.STIGS.iSTIG.VULN.STIG_DATA | Select-Object -Property VULN_ATTRIBUTE, ATTRIBUTE_DATA
if (-not ($STATUS -eq "")){

Write-Output $NEWVAL
Write-Output "STATUS: $STATUS"
#$Xml.CHECKLIST.STIGS.iSTIG.VULN.STIG_DATA | Select-Object -Property VULN_ATTRIBUTE, ATTRIBUTE_DATA
}

#$Xml.CHECKLIST.STIGS.iSTIG.VULN.STIG_DATA | Select-Object -Property VULN_ATTRIBUTE, ATTRIBUTE_DATA

#$Xml.CHECKLIST.STIGS.iSTIG.VULN.STIG_DATA | Select-Object -Property VULN_ATTRIBUTE, ATTRIBUTE_DATA

# $Xml.CHECKLIST.STIGS.iSTIG.VULN.STIG_DATA | Select-Object -Property VULN_ATTRIBUTE, ATTRIBUTE_DATA

#$Xml.CHECKLIST.STIGS.iSTIG.VULN.STIG_DATA | Select-Object -Property VULN_ATTRIBUTE, ATTRIBUTE_DATA | findStr "Vuln_Num"
#$Xml.CHECKLIST.STIGS.iSTIG.VULN | Select-Object -Property STATUS, FINDING_DETAILS, COMMENTS, SEVERITY_OVERRIDE, SEVERITY_JUSTIFICATION


# ------------ Reading XML file ----------------
[xml]$userfile = Get-Content C:\Users\AM0100\Documents\Wiki\STIG_TEST.ckl
$myDIG= $userfile.CHECKLIST.STIGS.iSTIG.VULN
Write-Output $myDIG.STIG_DATA.Item(0)

$INFO= $userfile.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA
$ITM= $INFO.SID_DATA.Item(7)
Write-Output $ITM
$counter=0
foreach( $STIG in $userfile.CHECKLIST.STIGS.iSTIG.VULN.STIG_DATA ) 
{ 

    $VULNUM= $STIG.VULN_ATTRIBUTE
    $VULID= $STIG.ATTRIBUTE_DATA

    if ($VULNUM -eq "Vuln_Num"){
    $STATUS=$myDIG.STATUS.Item($counter)
    
    Write-Output "$counter-> $VULNUM : $VULID : $STATUS "  
    $counter++

    }
    
}


# -------------------- Example 2 -----------------
[xml]$userfile = Get-Content C:\Users\AM0100\Documents\Wiki\STIG_TEST.ckl
$myDIG= $userfile.CHECKLIST.STIGS.iSTIG.VULN
Write-Output $myDIG.STIG_DATA.Item(0)

$INFO= $userfile.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA
$ITM= $INFO.SID_DATA.Item(7)
Write-Output $ITM
$counter=1
foreach( $STIG in $userfile.CHECKLIST.STIGS.iSTIG.VULN ) 
{ 
    Write-Output $counter
    Write-Output $STIG.STIG_DATA.Item(0), $STIG.STIG_DATA.Item(1), $STIG.STATUS
    Write-Output '     '
    $counter++

}

# -------------------- Example 3 -----------------
[xml]$userfile = Get-Content C:\Users\AM0100\Documents\Wiki\STIG_TEST.ckl
# $myDIG= $userfile.CHECKLIST.STIGS.iSTIG.VULN   # Testing
# Write-Output $myDIG.STIG_DATA.Item(0)          # Testing

$INFO= $userfile.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA
$ITEM= $INFO.SID_DATA.Item(7)
Write-Output $ITEM
$counter=1
$STATUS_COUNT_Open=0
$STATUS_COUNT_Not_Reviewed=0
$STATUS_COUNT_NotAFinding=0
foreach( $STIG in $userfile.CHECKLIST.STIGS.iSTIG.VULN ) 
{ 
    $(

    Write-Output $counter 
    Write-Output $STIG.STIG_DATA.Item(0), $STIG.STIG_DATA.Item(1), $STIG.STATUS 
    Write-Output '     '
    if ($STIG.STATUS -eq "Open"){ $STATUS_COUNT_Open++} elseIf ($STIG.STATUS -eq "Not_Reviewed"){$STATUS_COUNT_Not_Reviewed++} elseIf ($STIG.STATUS -eq "NotAFinding"){$STATUS_COUNT_NotAFinding++}
    $counter++

    ) *>&1 | Tee-Object -Append -FilePath  C:\Users\AM0100\Documents\Wiki\STIG_TEST.txt
}  
Write-Output "Total Open         : $STATUS_COUNT"
Write-Output "Total Not Reviewed : $STATUS_COUNT_Not_Reviewed"
Write-Output "Total Not A Finding: $STATUS_COUNT_NotAFinding"
 &notepad C:\Users\AM0100\Documents\Wiki\STIG_TEST.txt


# ---------------------------- HTML Reporting --------------------
Get-Service | ConvertTo-HTML | Out-File Services.html 
Invoke-Item Services.html

Get-Service | Select Name, DisplayName, Status, @{L='RequiredServices';E={$_.RequiredServices  -join '; '}}| ConvertTo-Html | Out-File Services.html
Invoke-Item Services.html


Get-Service | Select Name, DisplayName, Status, @{L='RequiredServices';E={$_.RequiredServices  -join '; '}}|ConvertTo-Html -As List | Out-File Services.html
Invoke-Item Services.html 

# Display with header
$Services = Get-Service | Select Name, DisplayName, Status, @{L='RequiredServices';E={$_.RequiredServices  -join '; '}}  | Select -first 10
$Report = 'ServicesReport.html'
$pre = @"

<div style='margin:  2px auto; BACKGROUND-COLOR:Red;Color:Black;font-weight:bold;FONT-SIZE:  16pt;TEXT-ALIGN: center;'>
$Env:Computername  Services Report
</div>    

"@ 
$post = "<BR><i>Report generated on $((Get-Date).ToString()) from $($Env:Computername)</i>"

$Services | ConvertTo-HTML -PreContent  $pre -PostContent  $post |  Out-file $Report
Invoke-Item $Report

# ------------------------------ Example 1 ---------------------------
# Display with header and alternate colored lines
$head=@"

  <style> 

  h1 {

  text-align:center;

  border-bottom:1px solid #666666;

  color:blue;

  }

  TABLE {

  TABLE-LAYOUT:  fixed; 

  FONT-SIZE:  100%; 

  WIDTH:  100%;

  BORDER: 1px  solid black;

  border-collapse: collapse;

  }

  * {

  margin:0

}
              .pageholder {

  margin:  0px auto;

  }

  

  td {

  VERTICAL-ALIGN:  TOP; 

  FONT-FAMILY:  Tahoma;

  WORD-WRAP:  break-word; 

  BORDER: 1px  solid black;          

  }

  

  th {

  VERTICAL-ALIGN:  TOP; 

  COLOR:  #018AC0; 

  TEXT-ALIGN:  left;

  background-color:LightSteelBlue;

  color:Black;

  BORDER: 1px  solid black;

  }

  body {

  text-align:left;

  font-smoothing:always;

  width:100%;

  }        

  tr:nth-child(even)  {

  background-color: #dddddd

  }   

  tr:nth-child(odd)  {

  background-color: #ffffff

  }          

  </style>

"@ 

$pre = @"

  <H1>$Env:Computername  Services Report </H1>   

"@ 

  $body = $Services | ConvertTo-Html -Fragment  | Out-String

  $HTML = $pre, $body

  $post = "<BR><i>Report generated on $((Get-Date).ToString()) from $($Env:Computername)</i>"

  ConvertTo-HTML -Head $head -PostContent  $post -Body  $HTML |  Out-String |  Out-File $Report

Invoke-Item $Report

#region Data gathering 

  $Services = Get-Service | Select Name, DisplayName, Status, @{L='RequiredServices';E={$_.RequiredServices  -join '; '}}

  $Report = 'ServicesReport.html'


# ------------------------- Example 2 ---------------------------
# endregion Data gathering, region Highlighting systems with stopped services 

  Add-Type -AssemblyName  System.Xml.Linq

  $head=@"

  <style> 

  h1 {

  text-align:center;

  border-bottom:1px solid #666666;

  color:blue;

  }

  TABLE {

  TABLE-LAYOUT:  fixed; 

  FONT-SIZE:  100%; 

  WIDTH:  100%;

  BORDER: 1px  solid black;

  border-collapse: collapse;

  }

  * {

  margin:0

}


              .pageholder {

  margin:  0px auto;

  }

  

  td {

  VERTICAL-ALIGN:  TOP; 

  FONT-FAMILY:  Tahoma;

  WORD-WRAP:  break-word; 

  BORDER: 1px  solid black;          

  }

  

  th {

  VERTICAL-ALIGN:  TOP; 

  COLOR:  #018AC0; 

  TEXT-ALIGN:  left;

  background-color:LightSteelBlue;

  color:Black;

  BORDER: 1px  solid black;

  }

  body {

  text-align:left;

  font-smoothing:always;

  width:100%;

  }      

  .even {  background-color: #dddddd; }

  .odd {  background-color: #ffffff; }                            

  </style>

"@ 

$pre = @"

  <H1>$Env:Computername  Services Report </H1>   

"@ 

  $body = $Services | ConvertTo-Html -Fragment  | Out-String


#region Linq parsing 

  $xml = [System.Xml.Linq.XDocument]::Parse( $body)

  if($Namespace  = $xml.Root.Attribute("xmlns").Value)  {

  $Namespace  = "{{{0}}}"  -f $Namespace

  }

  # Find the index of the column you want to format: 

  $Index = [Array]::IndexOf( $xml.Descendants("${Namespace}th").Value, "Status")

  $i=0 

  foreach($row  in $xml.Descendants("${Namespace}tr")){

  If ($i % 2){

  Write-Verbose  'Set even' -Verbose

  $row.SetAttributeValue("class", "even") 

  } Else{

  Write-Verbose  'Set odd' -Verbose

  $row.SetAttributeValue("class", "odd") 

  }

  switch(@($row.Descendants("${Namespace}td"))[$Index]) {

  {'Stopped'  -eq $_.Value } { 

  Write-Verbose  'Set red' -Verbose

  $_.SetAttributeValue( "style", "background:  red;")

  continue 

  } 

  }

  $i++

  }

  $Body = $xml.Document.ToString()

  #endregion Linq parsing 


$HTML = $pre, $body

  $post = "<BR><i>Report generated on $((Get-Date).ToString()) from $($Env:Computername)</i>"

  ConvertTo-HTML -Head $head -PostContent  $post -Body  $HTML |  Out-String |  Out-File $Report

  Invoke-Item $Report

  #endregion Highlighting systems with stopped services

****************************************************
*                  Multiple Pings - Example-1      *
****************************************************
[

    $ServerName = "company.com","comp.net","abc.com","192.168.1.204"    
    foreach ($Server in $ServerName) { 
            if (test-Connection -ComputerName $Server -Count 2 -Quiet ) {  
                write-Host "$Server is alive and Pinging " -ForegroundColor Green 
                    } else 
                    { Write-Warning "$Server seems dead not pinging" 
                    }     
    } 

    output:- 

    company.com is alive and Pinging 
    comp.net is alive and Pinging 
    abc.com is alive and Pinging 
  
]

****************************************************
*                  Multiple Pings - Example-2      *
****************************************************
[

    $ServerName = Get-Content "c:\Computers.txt"   
    foreach ($Server in $ServerName) {  
            if (test-Connection -ComputerName $Server -Count 2 -Quiet ) {   
                "$Server is Pinging "  
                        } else  
                        {"$Server not pinging"  
                        }      
    } 

]

****************************************************
*                  Multiple Pings - Example-3      *
****************************************************
[

    $ServerName = "company.com","comp.net","abc.com","192.168.1.204"    
    foreach ($Server in $ServerName) { 
            if (ping -a $Server -Count 2 ) {  
                write-Host "$Server is alive and Pinging " -ForegroundColor Green 
                        } else 
                        { Write-Warning "$Server seems dead not pinging" 
                        }     
    }

]

*****************************************************
*                  Multiple Pings - Example-4 (Best)*
*****************************************************
[

    # Ping and resolves the name. Uncomment first line for a TXT input file

    #$listofIPs = Get-Content c:\IPList.txt
    $listofIPs = "7.40.1.204","7.40.1.205","7.40.1.206"
    #Lets create a blank array for the resolved names

    $ResultList = @()
    # Lets resolve each of these addresses

    foreach ($ip in $listofIPs)
    {
         $result = $null
         $currentEAP = $ErrorActionPreference
         $ErrorActionPreference = "silentlycontinue"
         $result = [System.Net.Dns]::gethostentry($ip)
         $ErrorActionPreference = $currentEAP
         If ($Result)
         {
              $Resultlist += $IP + " - " + [string]$Result.HostName
         }
         Else
         {
              $Resultlist += "$IP - No HostNameFound"
         }
    }
    $ResultList

    # If we wanted to output the results to a text file we could do this, for this demo I have this line commented and another line here to echo the results to the screen

    #$resultlist | Out-File c:\output.txt

]

**********************************************************
* Multiple Pings + NSlookup for Names or IPs (The Best)  *
**********************************************************
[
    
    <#
     This script performs nslookup and ping on all DNS names or IP addresses 
     you list in the text file referenced in $InputFile (either Names or IPs) 
     Outputs to the screen - Copy the screen into Excel to work with results.
     Also display progress bar at the top
    #>

    $InputFile = 'C:\Users\am028787\Downloads\Hosts_ADOU_1.txt'
    $addresses = get-content $InputFile
    $reader = New-Object IO.StreamReader $InputFile
        while($reader.ReadLine() -ne $null){ $TotalIPs++ }
    write-host    ""    
    write-Host -ForegroundColor DarkYellow "Performing nslookup on each address..."    
            foreach($address in $addresses) {
                ## Progress bar
                $i++
                $percentdone = (($i / $TotalIPs) * 100)
                $percentdonerounded = "{0:N0}" -f $percentdone
                Write-Progress -Activity "Performing nslookups" -CurrentOperation "Working on IP: $address (IP $i of $TotalIPs)" -Status "$percentdonerounded% complete" -PercentComplete $percentdone
                ## End progress bar
                try {
                    [system.net.dns]::resolve($address) | Select HostName,AddressList
                    }
                    catch {
                        Write-host "$address was not found. $_" -ForegroundColor Green
                    }
                }
    write-host    ""            
    write-Host -ForegroundColor DarkYellow "Pinging each address..."
            foreach($address in $addresses) {
                ## Progress bar
                $j++
                $percentdone2 = (($j / $TotalIPs) * 100)
                $percentdonerounded2 = "{0:N0}" -f $percentdone2
                Write-Progress -Activity "Performing pings" -CurrentOperation "Pinging IP: $address (IP $j of $TotalIPs)" -Status "$percentdonerounded2% complete" -PercentComplete $percentdone2
                ## End progress bar
                    if (test-Connection -ComputerName $address -Count 2 -Quiet ) {  
                        write-Host "$address responded" -ForegroundColor Green 
                        } else 
                        { Write-Warning "$address does not respond to pings"              
                        }  
            }
    write-host    ""        
    write-host -ForegroundColor DarkYellow "Done!"

]

*****************************************************
*         Multiple Pings - Example-5                *
*         INPUT:  addm_hosts.txt file               *
*         OUTPUT: ipList.csv file                   *
*****************************************************
[
    $result=@()
    # Give the source file name of hosts name example_IP.txt
    Get-Content addm_hosts.txt | %{
    $start_name = $_

    $conn = Test-Connection -ComputerName $_ -Quiet
    if(-not $conn)
    {
      $start_name = ""
    }

    Try
    { 
      $dns = [System.Net.Dns]::GetHostEntry($_)
      $dns_host = $dns.HostName
      $dns_ip  = $dns.AddressList | select -ExpandProperty IPAddressToString
    }
    catch
    {
      $dns_host = "invalid host name" #as jrich proposed :)
      $dns_ip = "invalid host name" #as jrich proposed :)
      $start_name = ""
    }

    $HostObj = New-Object PSObject -Property @{
									    Host    = $start_name
		        					    IP      = $dns_ip
									    DNSHost = $dns_host
									    Active  = $conn     
		        		    }
    $result += $HostObj						
    }
    # generates a excel csv file of the result
    $result | Export-Csv ipList.csv -NoTypeInformation
]

*****************************************************
*                  Multiple Pings - Example-6       *
*****************************************************
[

    $ping = New-Object System.Net.Networkinformation.Ping
    1..225 | % { $ping.send(“192.168.1.$_”) | select address, status }

]

*****************************************************
*          Ping Sweeper with subnet                 *
*****************************************************
[

$start = 215
$end = 220
$ping = 1

$a = 1
$z = 3
$a..$z | foreach {
  $subnet = "7.40.0." -replace "0$",$_
  Test-Connection -ComputerName $IP -Count 1 -Quiet
  
  while ($start -le $end) {
    $IP = $subnet + "$start"
    Write-Host "Pinging $IP" -ForegroundColor Cyan
    Test-Connection -ComputerName $IP -count 1 -Quiet
    $start++
    }

  }


]

*****************************************************
*                 My Ping  Sweeper                  *
*****************************************************
[

$subnet = "7.40.3.215"
$start = 215
$end = 220
$ping = 1
$port = 443
    while ($start -le $end) {
    $IP = "7.40.3.$start"
    Write-Host "Pinging $IP" -ForegroundColor Cyan
    #Test-netconnection $IP -CommonTCPPort HTTP
    Test-NetConnection -Port $port $IP -InformationLevel Quiet
    #Test-Connection -ComputerName $IP -count 1 -Quiet
    $start++
    }

]

*****************************************************
* Retrieve IP addresses on nwtwork                  *
*****************************************************
[

Get-NetIPAddress | Format-Table

]

*****************************************************
* Get devices IP addresses, MAC and names on nwtwork*
*****************************************************
[

## Q:\Test\2017\01\21\SO_41785413.ps1
$FileOut = ".\Computers.csv"
## Ping subnet
$Subnet = "192.168.xyz."
1..254|ForEach-Object{
    Start-Process -WindowStyle ping.exe -Argumentlist "-n 1 -l 0 -f -i 2 -w 1 -4 $SubNet$_"
}

$Computers =(arp.exe -a | Select-String "$SubNet.*dynam") -replace ' +',','|
  ConvertFrom-Csv -Header Computername,IPv4,MAC,x,Vendor|
                   Select Computername,IPv4,MAC

ForEach ($Computer in $Computers){
  nslookup $Computer.IPv4|Select-String -Pattern "^Name:\s+([^\.]+).*$"|
    ForEach-Object{
      $Computer.Computername = $_.Matches.Groups[1].Value
    }
}
$Computers
$Computers | Export-Csv $FileOut -NotypeInformation
$Computers | Out-Gridview

]


*****************************************************
*                  Manual Port ping - Example-1     *
*****************************************************
[

    $computer=Read-Host "Computername | IP Address?"
    $port=Read-Host "Port Numbers? Separate them by comma"
    $port.split(',') | Foreach-Object -Process {If (($a=Test-NetConnection $computer -Port $_ -WarningAction SilentlyContinue).tcpTestSucceeded -eq $true) {Write-Host $a.Computername $a.RemotePort -ForegroundColor Green -Separator " ==> "} else {Write-Host $a.Computername $a.RemotePort -Separator " ==> " -ForegroundColor Red}}
 

]

*****************************************************
*                  Multiple Port ping - Example-2   *
*****************************************************
[

    function Test-Port
    {$computer=Read-Host "Computername | IP Address?"
     $port=Read-Host "Port Numbers? Separate them by comma"
     $port.split(',') | Foreach-Object -Process 
     {If (($a=Test-NetConnection $computer -Port $_ -WarningAction SilentlyContinue).tcpTestSucceeded -eq $true) 
     {Write-Host $a.Computername $a.RemotePort -ForegroundColor Green -Separator " ==> "} 
     else {Write-Host $a.Computername $a.RemotePort -Separator " ==> " -ForegroundColor Red}}
     }

]

*****************************************************
*         Find local admin of remote computer       *
*****************************************************
[

    invoke-command {
	    net localgroup administrators | 
	    where {$_ -AND $_ -notmatch "command completed successfully"} | 
	    select -skip 4
	    } -computer addmprd01

]

*****************************************************
*  Find when was user logged on to the machine      *
*****************************************************
[

    {
    Get-Item "$((Get-Item $env:USERPROFILE).Parent.FullName)\*\NTUSER.DAT" -Force |
		    ForEach-Object {
			    New-Object psobject -Property @{
				    Path = $_.DirectoryName
				    ProfileLastModified = $_.LastWriteTime
			    }
		    }
	    }

]

*****************************************************
*  IfConfig for local machine                       *
*****************************************************
[


    [cmdletbinding()]
    param (
     [parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [string[]]$ComputerName = $env:computername
    )

    begin {}
    process {
     foreach ($Computer in $ComputerName) {
      if(Test-Connection -ComputerName $Computer -Count 1 -ea 0) {
       $Networks = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $Computer | ? {$_.IPEnabled}
       foreach ($Network in $Networks) {
        $IPAddress  = $Network.IpAddress[0]
        $SubnetMask  = $Network.IPSubnet[0]
        $DefaultGateway = $Network.DefaultIPGateway
        $DNSServers  = $Network.DNSServerSearchOrder
        $IsDHCPEnabled = $false
        If($network.DHCPEnabled) {
         $IsDHCPEnabled = $true
        }
        $MACAddress  = $Network.MACAddress
        $OutputObj  = New-Object -Type PSObject
        $OutputObj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $Computer.ToUpper()
        $OutputObj | Add-Member -MemberType NoteProperty -Name IPAddress -Value $IPAddress
        $OutputObj | Add-Member -MemberType NoteProperty -Name SubnetMask -Value $SubnetMask
        $OutputObj | Add-Member -MemberType NoteProperty -Name Gateway -Value $DefaultGateway
        $OutputObj | Add-Member -MemberType NoteProperty -Name IsDHCPEnabled -Value $IsDHCPEnabled
        $OutputObj | Add-Member -MemberType NoteProperty -Name DNSServers -Value $DNSServers
        $OutputObj | Add-Member -MemberType NoteProperty -Name MACAddress -Value $MACAddress
        $OutputObj
       }
      }
     }
    }

    end {}

]

*****************************************************
*  Log security logs of local computer              *
*****************************************************
[

    Function Find-Matches {                        

     Param($Pattern)
     Process {
      $_ | Select-String -pattern $Pattern -AllMatches |
       select -ExpandProperty matches |
       select -ExpandProperty value
      }
     }                        

    Function Query-SecurityLog {               

        Param(
            [int]$MaxEvents,
            [array]$global:Users = @(),
            [string]$Comp = $env:computername,
            $notmatch = "System|IUSR|LOCAL|NETWORK"            

            )                 

        if($MaxEvents)
        { $events = Get-WinEvent -LogName security -MaxEvents $MaxEvents |
        Where-Object{$_.id -eq "4624"}
        } Else {  $events = Get-WinEvent -LogName security  |
        Where-Object{$_.id -eq "4624"}}            

        Foreach($i in $events) {                        

        $content = $i.message| Find-Matches -Pattern "account name:\s+\w+"
        if($content.Count -eq 2) {
        $account = $content[1]} else {$account =  $content }
        $account = (($account -split ":")[1]) -replace "\s+",""                        

        if($account -notmatch $notmatch) {                        

            if($i.Message | Select-String -Pattern "Logon Type:\s+[2]") {
            $logontype = "Interactive" }
            if($i.Message | Select-String -Pattern "Logon Type:\s+[3]") {
            $logontype = "Network" }
            if($i.Message | Select-String -Pattern "Logon Type:\s+[7]") {
            $logontype = "Computer Unlocked" }                        

       $user = $account
       $Date = $i.TimeCreated
       $obj = New-Object PSObject -Property @{
           User = $user
           Date = $Date
           LogonType = $LogonType
           }            

      $Global:Users += $Obj                        

           }
        }                        

     write-output $Global:Users | Select User,Date,LogonType |
                 Sort Date -Descending | Format-Table -Auto
    }                        

    Query-SecurityLog -MaxEvents 1000

]

*****************************************************
*  SSL protocol connectivity                        *
*****************************************************
[

<#
 .DESCRIPTION
   Outputs the SSL protocols that the client is able to successfully use to connect to a server.
 
 .NOTES
 
   Copyright 2014 Chris Duck
   http://blog.whatsupduck.net
 
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
 
     http://www.apache.org/licenses/LICENSE-2.0
 
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 
 .PARAMETER ComputerName
   The name of the remote computer to connect to.
 
 .PARAMETER Port
   The remote port to connect to. The default is 443.
 
 .EXAMPLE
   Test-SslProtocols -ComputerName "www.google.com"
   
   ComputerName       : www.google.com
   Port               : 443
   KeyLength          : 2048
   SignatureAlgorithm : rsa-sha1
   Ssl2               : False
   Ssl3               : True
   Tls                : True
   Tls11              : True
   Tls12              : True
 #>
 function Test-SslProtocols {
   param(
     [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true)]
     $ComputerName,
     
     [Parameter(ValueFromPipelineByPropertyName=$true)]
     [int]$Port = 443
   )
   begin {
     $ProtocolNames = [System.Security.Authentication.SslProtocols] | gm -static -MemberType Property | ?{$_.Name -notin @("Default","None")} | %{$_.Name}
   }
   process {
     $ProtocolStatus = [Ordered]@{}
     $ProtocolStatus.Add("ComputerName", $ComputerName)
     $ProtocolStatus.Add("Port", $Port)
     $ProtocolStatus.Add("KeyLength", $null)
     $ProtocolStatus.Add("SignatureAlgorithm", $null)
     
     $ProtocolNames | %{
       $ProtocolName = $_
       $Socket = New-Object System.Net.Sockets.Socket([System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
       $Socket.Connect($ComputerName, $Port)
       try {
         $NetStream = New-Object System.Net.Sockets.NetworkStream($Socket, $true)
         $SslStream = New-Object System.Net.Security.SslStream($NetStream, $true)
         $SslStream.AuthenticateAsClient($ComputerName,  $null, $ProtocolName, $false )
         $RemoteCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$SslStream.RemoteCertificate
         $ProtocolStatus["KeyLength"] = $RemoteCertificate.PublicKey.Key.KeySize
         $ProtocolStatus["SignatureAlgorithm"] = $RemoteCertificate.PublicKey.Key.SignatureAlgorithm.Split("#")[1]
         $ProtocolStatus.Add($ProtocolName, $true)
       } catch  {
         $ProtocolStatus.Add($ProtocolName, $false)
       } finally {
         $SslStream.Close()
       }
     }
     [PSCustomObject]$ProtocolStatus
   }
 }

]


*****************************************************
*  Windows Host STIG verification                   *
*****************************************************
[

<# 
    Writen By: Aamir Mukhtar
    Date Created: 06/21/2016
    Version: 1.0
#>

Clear-Host

While ($true){
Clear-Host
Write-Host   "-------------------------------------------------"
Write-Host   "    Script to STIG Windows 2012 R2 STD server"
Write-Host   "-------------------------------------------------"
Write-Output "  "
Write-Output " 1. Scan  CAT-1 vulnerabilities"
Write-Output " 2. Scan  CAT-2 vulnerabilities"
Write-Output " 3. Scan  CAT-3 vulnerabilities"
Write-Output " 4. Apply CAT-1 STIGs"
Write-Output " 5. Apply CAT-2 STIGs"
Write-Output " 6. Apply CAT-3 STIGs"
Write-Output " 7. EXIT  (e/E)"
Write-Output "  "

$input = Read-Host "Please select from the menu"

If ($input -eq "1" ) { Write-Output " "
    
    $(
    
    Write-Output "Vuln ID: V-1073: Systems must be maintained at a supported service pack level"
    $input = Get-WmiObject Win32_OperatingSystem | findStr "BuildNumber"
    if ($input -gt "9200" ) { Write-Output "Not a finding: $input" } else { Write-Warning "It is a finding: $input" }

    Write-Output "`nVuln ID: V-1074: An approved DoD antivirus program must be installed and used"
    Write-Host -ForegroundColor Cyan "Open a SR for installing DoD approved antivirus"

    Write-Output "`nVuln ID: V-1081: Local volumes must be formatted using NTFS"
    $input = Get-WmiObject Win32_Volume | findStr "FileSystem"
    if ($input -notLike "NTFS" ) { Write-Output "Not a finding: $input" } else { Write-Warning "It is a finding: $input" }

    Write-Output "`nVuln ID: V-1093: Anonymous enumeration of shares must be restricted"
    $input = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -Name RestrictAnonymous | findStr "restrictanonymous"
    if ($input -Like "1" ) { Write-Output "Not a finding: $input" } else { Write-Warning "It is a finding: $input" }

    Write-Output "`nVuln ID: V-1102: Unauthorized accounts must not have the Act as part of the operating system user right"
    Write-Host -ForegroundColor Cyan "Manual configuration is required!"

    Write-Output "`nVuln ID: V-1121: FTP servers must be configured to prevent access to the system drive"
    $input = Get-Service | findStr "FTP"
    if ($input -notLike "FTP" ) { Write-Output "Not a finding: $input" } else { Write-Warning "It is a finding: $input" }

    Write-host "`nVuln ID: V-1127: Only administrators responsible for the member server must have Administrator rights on the system" 
    Write-Host -ForegroundColor Cyan "Manual configuration is required!"

    Write-Host "`nVuln ID: V-1152: Anonymous access to the registry must be restricted"
    $path = Test-Path 'HKLM:\System\CurrentControlSet\Control\Lsa'
    if ($path -eq "True") {
    $key = Test-RegistryValue "HKLM:\System\CurrentControlSet\Control\Lsa" "RestrictAnonymous"
    $value = Read-RegistryEntry "HKLM:\System\CurrentControlSet\Control\Lsa" "RestrictAnonymous"
    if (($key -eq "True" ) -and ($value -eq "1")) { Write-Warning "Finding: Need to add a Key value" } else { Write-Warning "Key does not exists" } 
    } else { Write-Warning "Path does not exists"}


    Write-Host "`nVuln ID: V-1153: The LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM"
    $input = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -Name LmCompatibilityLevel | findStr "lmcompatibilitylevel"
    if ($input -eq "5" ) { Write-Output "Not a finding: $input" } else { Write-Warning "It is a finding: $input" }
    
    <#
    Write-Host "`nVuln ID: V-1159: The Recovery Console option must be set to prevent automatic logon to the system"
    $input = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\setup\recoveryconsole' -Name SecurityLevel | findStr "securitylevel"
    if ($input -eq "0" ) { Write-Output "Not a finding: $input" } else { Write-Warning "It is a finding: $input" }
     #>

    Write-host "`nVuln ID: V-2372: Reversible password encryption must be disabled" 
    Write-Host -ForegroundColor Cyan "Manual configuration is required!"


    Write-Host "`nVuln ID: V-1153: The LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM"
    $path = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    if ($path -eq "True") {
    $key = Test-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoRun"
    $value = Read-RegistryEntry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoRun"
    if (($key -eq "True" ) -and ($value -eq "1")) { Write-Warning "Finding: Need to add a Key value" } else { Write-Warning "Key does not exists" } 
    } else { Write-Warning "Path does not exists"}

    Write-Host "`nVuln ID: V-1159: The Recovery Console option must be set to prevent automatic logon to the system"
    $path = Test-Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole'
    if ($path -eq "True") {
    $key = Test-RegistryValue "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole" "SecurityLevel"
    $value = Read-RegistryEntry "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole" "SecurityLevel"
    if (($key -eq "True" ) -and ($value -eq "0")) { Write-Warning "Not a finding" } else { Write-Warning "Key does not exists" } 
    } else { Write-Warning "Path does not exists"}

    Write-Host "`nVuln ID: V-2374: Autoplay must be disabled for all drives"
    $path = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer'
    if ($path -eq "True") {
    $key = Test-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" "NoDriveTypeAutoRun"
    if ($key -eq "True") { $value = Read-RegistryEntry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" "NoDriveTypeAutoRun" }
    if (($key -eq "True" ) -and ($value -eq "255")) { Write-Warning "Not a finding" } else { Write-Warning "value does not exists" } 
    } else { Write-Warning "Path does not exists"}

    Write-host "`nVuln ID: V-3337: Anonymous SID/Name translation must not be allowed" 
    Write-Host -ForegroundColor Cyan "Manual configuration is required!"

    Write-Host "`nVuln ID: V-3338: Named pipes that can be accessed anonymously must be configured to contain no values on member servers"
    $path = Test-Path 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
    if ($path -eq "True") {
    $key = Test-RegistryValue "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" "NullSessionPipes"
    $value = Read-RegistryEntry "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" "NullSessionPipes"
    if (($key -eq "True" ) -and ($value -eq "" )) { Write-Warning "Not a finding" } else { Write-Warning "Key does not exists" } 
    } else { Write-Warning "Path does not exists"}


    ) *>&1 | Tee-Object -FilePath C:\temp\Windows_stigs.txt
}  # &notepad C:\temp\Windows_stigs.txt

If ($input -eq "2" ) { Write-Output "Scan CAT-2 ....." }
If ($input -eq "3" ) { Write-Output "Scan CAT-3 ....." }

# ------------------ Apply CAT-1 starts from here ---------------------------
If ($input -eq "4" ) {  
    
    $checklist_path = Read-Host "Please enter the Checklist path: (C:\Users\AM0100\Documents\Wiki\STIG_TEST.ckl) "
    [xml]$userfile = Get-Content  $checklist_path 

    $INFO= $userfile.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA
    $ITEM= $INFO.SID_DATA.Item(7)
    Write-Output $ITEM
    $counter=1
    $STATUS_COUNT_Open=0
    $STATUS_COUNT_Not_Reviewed=0
    $STATUS_COUNT_NotAFinding=0
    foreach( $STIG in $userfile.CHECKLIST.STIGS.iSTIG.VULN ) 
    { 
        $(

            #Write-Output $counter 
            Write-Output $STIG.STIG_DATA.Item(0), $STIG.STIG_DATA.Item(1), $STIG.STATUS | Out-Null
            #Write-Output '     '
            if ($STIG.STATUS -eq "Open"){ $STATUS_COUNT_Open++} elseIf ($STIG.STATUS -eq "Not_Reviewed"){$STATUS_COUNT_Not_Reviewed++} elseIf ($STIG.STATUS -eq "NotAFinding"){$STATUS_COUNT_NotAFinding++}
            $counter++

        ) *>&1 | Tee-Object -Append -FilePath  C:\Users\AM0100\Documents\Wiki\STIG_TEST.txt
    }  
        Write-Output "------------------------------------------------"
        Write-Output "Total Open         : $STATUS_COUNT"
        Write-Output "Total Not Reviewed : $STATUS_COUNT_Not_Reviewed"
        Write-Output "Total Not A Finding: $STATUS_COUNT_NotAFinding"
        Write-Output "------------------------------------------------"
        # &notepad C:\Users\AM0100\Documents\Wiki\STIG_TEST.txt
        Write-Output "  "

        $Choice_Stig = Read-Host "Do you want to continue to apply the Stigs (y/n)? "

        if ( $Choice_Stig -eq "y" ){
        
        $Apply_Stig = Read-Host "Do you want to apply Stig(s) manually or automatically (man/auto)? "
        
            Switch ($Apply_Stig)
            {
                 "man" { 
                            $Manual_Stig = Read-Host "Please enter a Stig ID one at a time? " 
                          
                            Manual-Stig($Manual_Stig)



                          }
                 "auto"   { 
                            $Automatic_Stig = Read-Host "Please enter the path of include list file (include.txt)? " 
                              
                             Auto-Stig($Automatic_Stig)
                             

                          }
                 Default  { "Unknown file name" }
             }

        

        } else { continue }

}


If ($input -eq "5" ) { Write-Output "Apply CAT-2 ....." }
If ($input -eq "6" ) { Write-Output "Apply CAT-3 ....." }

# -------------------- End of the Script ---------------------

If ($input -eq "exit" -or $input -eq "e") { break }
Write-Output "  "
$input = Read-Host "Enter to continue or type exit to leave? "

} 
Write-Warning "Script is terminated Bye...  "


# ----------------- Functions of Script ----------------------

function Test-RegistryValue ([string] $key, [string] $name)
{
    Get-ItemProperty -Path $key $name -ErrorAction SilentlyContinue | Out-Null;
    return $?;
}

function Read-RegistryEntry ([string] $ikey, [string] $iname)
{   
    if ( Test-RegistryEntry $ikey $iname )
    {         
        return (Get-ItemProperty -Path $ikey -Name $iname).$iname;       
    }
    else
    {
        return '';
    }
}


function Manual-Stig ($Manual_Stig){

    Switch($Manual_Stig){

                      1 { 'Number 1' }
                      2 { 'Number 2' }
                      3 { "Number 3" }
                          
                        }

}
#[int]$Manual_Stig = Read-Host "Please enter a Stig ID one at a time? "
#Manual-Stig($Manual_Stig)

function Auto-Stig ($Automatic_Stig){
    return "It will compare $Automatic_Stig to checklist and apply the stigs..."
}
#$Automatic_Stig = Read-Host "Please enter a Stig ID one at a time? "
#Auto-Stig($Automatic_Stig)


]