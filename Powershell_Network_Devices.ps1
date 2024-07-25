###########################
# Enable HTTPS
###########################

[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

###########################
# Get Token
###########################

# $array = "server01.company.net"
$array = "192.168.16.33"
$username = "svcAcc"
$password = "ADDMPrd01"

$data = @{
    username = $username
    password = $password
}

$body = convertto-json (@{ data = $data })

# $uri = "https://" + $array + ":5392/v1/tokens"
$uri = "https://" + $array + ":5392/v1/token"
$token = Invoke-RestMethod -Uri $uri -Method Post -Body $body
$token = $token.data.session_token

###########################
# Print Results
###########################

$token

# --------------------------------------------------------

###########################
# Enable HTTPS
###########################
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
###########################
# Get Token
###########################
$array = "server01.company.net"
$username = "svcAcc"
$password = "ADDMPrd!!" 

$data = @{
    username = $username
    password = $password
}

$body = convertto-json (@{ data = $data })
$uri = "https://" + $array + ":5392/v1/tokens"
$token = Invoke-RestMethod -Uri $uri -Method Post -Body $body
$token = $token.data.session_token

###########################
# Get Array
###########################
$header = @{ "X-Auth-Token" = $token }
$uri = "https://" + $array + ":5392/v1/arrays/detail/"
$volume_list = Invoke-RestMethod -Uri $uri -Method Get -Header $header
$vol_array = @();
foreach ($volume_id in $volume_list.data.id){
    
    $uri = "https://" + $array + ":5392/v1/arrays/detail/" + $volume_id
    $volume = Invoke-RestMethod -Uri $uri -Method Get -Header $header
    #write-host $volume.data.name :     $volume.data.id
    $vol_array += $volume.data
}
###########################
# Print Results
###########################

$vol_array | sort-object name, -descending | select name,status,role,serial,version| format-table -autosize
