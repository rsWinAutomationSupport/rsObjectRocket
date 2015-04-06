<#$networkInfo = @{}
foreach($adapter in ([System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces())){
    if($adapter.Supports([System.Net.NetworkInformation.NetworkInterfaceComponent]::IPv4)){
        $nicName = $adapter.Name
        $nicAddress = ((($adapter.GetIPProperties()).UnicastAddresses | ? IPv4Mask -ne "0.0.0.0").Address).IPAddressToString
    }
    if($nicName -notlike "Loopback*"){$networkInfo.Add($nicName,$nicAddress)}
}
if(!(($networkInfo.Contains("Public")) -and ($networkInfo.Contains("Private")))){
    Write-EventLog -LogName DevOps -Source rsCommon -EntryType Warning -EventId 1000 -Message "Expected adapters not present in system. Script cannot continue with null values.`nPlease check the adapter configuration for a Public and Private adapter"
    Return
}#>
function Test-TargetResource{
    [OutputType([boolean])]
    param(
        [ValidateNotNullorEmpty()][string]$orAPIKey,
        #[ValidateNotNullorEmpty()][string]$rsAPIKey,
        [ValidateNotNullorEmpty()][string]$Description,
        [ValidateNotNullorEmpty()][string]$orMetaTag,
        #[ValidateSet("Absent","Present")][string]$Ensure = 'Present'
    )
    Import-Module rsCommon
    . (Get-rsSecrets)

    $rsServers = Get-rsDetailsServers | ?{$_.metadata -match $orMetaTag} | Select -Property accessIPv4, -exp metadata | select accessIPv4,@{Name="or_Access";Expression=$orMetaTag}
    $currentACL = Invoke-RestMethod -Uri 'https://api.objectrocket.com/acl/get' -Body "api_key=$($orAPIKey)" -Method Post | select -exp Data | ? description -eq $Description | select -exp cidr_mask
    $rsCidrs = @()
    foreach($server in $rsServers){
        if($server.or_Access -eq "true"){
            $rsCidrs += $server.accessIPv4 + "/32"
        }
    }

    if((Compare-Object $rsCidrs $currentACL) -ne $null){Return $false}
    else{Return $true}
    
    <#[bool]$exists=$false
    $publicIP = ($networkInfo.Get_Item("Public")) + "/32"
    $privateIP = ($networkInfo.Get_Item("Private")) + "/32"
    $currentACL = Invoke-RestMethod -Uri 'https://api.objectrocket.com/acl/get' -Body "api_key=$($APIKey)" -Method Post | select -exp Data | select -exp cidr_mask

    switch($Ensure){
        Present{
            if($currentACL -contains $publicIP){$exists = $true}
        }
        Absent{
            if($currentACL -contains $publicIP){$exists = $false}
        }
    }#>
}
function Set-TargetResource{
    param(
        [ValidateNotNullorEmpty()][string]$orAPIKey,
        [ValidateNotNullorEmpty()][string]$rsAPIKey,
        [ValidateNotNullorEmpty()][string]$Description,
        [ValidateNotNullorEmpty()][string]$orMetaTag,
        #[ValidateSet("Absent","Present")][string]$Ensure = 'Present'
    )
    Import-Module rsCommon
    . (Get-rsSecrets)

    $rsServers = Get-rsDetailsServers | ?{$_.metadata -match $orMetaTag} | Select -Property accessIPv4, -exp metadata | select accessIPv4,@{Name="or_Access";Expression=$orMetaTag}
    $currentACL = Invoke-RestMethod -Uri 'https://api.objectrocket.com/acl/get' -Body "api_key=$($orAPIKey)" -Method Post | select -exp Data | ? description -eq $Description | select -exp cidr_mask
    $rsCidrs = @()
    foreach($server in $rsServers){
        if($server.or_Access -eq "true"){
            $rsCidrs += $server.accessIPv4 + "/32"
        }
    }

    foreach($ip in $rsCidrs){
        if(!($currentACL -contains $ip)){
            Invoke-RestMethod -Uri 'https://api.objectrocket.com/acl/add' -Body "api_key=$($orAPIKey)&doc={`"cidr_mask`": `"$($ip)`", `"description`": `"$($Description)`"}"
        }
    }
    foreach($ip in $currentACL){
        if(!($rsServers -contains $ip)){
            Invoke-RestMethod -Uri 'https://api.objectrocket.com/acl/delete' -Method Post -Body "api_key=$($orAPIKey)&doc={`"cidr_mask`": `"$($ip)`"}"
        }
    }

    <#param(
        [string]$APIKey = $null,
        [string]$Ensure = 'Present',
        [string]$description
    )
    $publicIP = ($networkInfo.Get_Item("Public")) + "/32"

    switch($Ensure){
        Present{
            Invoke-RestMethod -Uri 'https://api.objectrocket.com/acl/add' -Body "api_key=$($APIKey)&doc={`"cidr_mask`": $($publicIP), `"description`": $($description)}"
        }
        Absent{
            Invoke-RestMethod -Uri 'https://api.objectrocket.com/acl/delete' -Body "api_key=$($APIKey)&doc={`"cidr_mask`": $($publicIP)}"
        }
    }
}
function Get-TargetResource{
    param(
        [string]$APIKey = $null
    )
    $publicIP = ($networkInfo.Get_Item("Public")) + "/32"
    $currentACL = Invoke-RestMethod -Uri 'https://api.objectrocket.com/acl/get' -Body "api_key=$($APIKey)" -Method Post | select -exp Data | select -exp cidr_mask
    
    if($currentACL -contains $publicIP){$whiteListed = $true}
    else{$whiteListed = $false}
    return @{
        "Whitelisted" = $whiteListed
    }#>
}
Export-ModuleMember -Function *-TargetResource 