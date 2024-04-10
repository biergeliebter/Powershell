<#
.Replace server values with FQDN or other target value of the servers
#>
Set-Variable -name serversMYAPPSERVERS -value 'server1', 'server2' -option Constant
Set-Variable -name serversMYWEBSERVERS -value 'server1', 'server2' -option Constant


function Make-Credential{
    param (
    [string] $username = "replace_with_username",
    [string] $message = "Creates a credential to Global:credential for reuse"
    )
    $Global:credential = Get-Credential -Message $message -UserName $username
    }



function Get-Systeminfo{
<#
.Description
    Get-Systeminfo
    Gets system info of the remote server
.parameter servername
    Server(s) to search
.parameter resetusername
    Optional - used to reset the credential
#>
    param(
    [Parameter(Mandatory)]
    [string[]] $servername,
    [switch] $resetusername = $false
        )
    if(!$Global:credential -or $resetusername){
        Make-Credential
    }
    Invoke-Command -ComputerName $servername -Credential $Global:credential -ScriptBlock {systeminfo /fo csv | ConvertFrom-Csv | select OS*, System*, Hotfix* | Format-List }
}



function Get-Memory{
<#
.Description
    Get-Memory
    Gets RAM info of the remote server
.parameter servername
    Server(s) to search
.parameter resetusername
    Optional - used to reset the credential
#>
    param(
    [Parameter(Mandatory)]
    [string[]] $servername,
    [switch] $resetusername = $false
        )
    if(!$Global:credential -or $resetusername){
        Make-Credential
    }
    Invoke-Command -ComputerName $servername -Credential $Global:credential -ScriptBlock {(Get-CimInstance -ClassName 'Cim_PhysicalMemory' | Measure-Object -Property Capacity -Sum).Sum /1gb}
}



function Get-Admin-Group-Membership{
<#
.Description
    Get-Admin-Group-Membership
    Gets admin group membership info of the remote server
.parameter servername
    Server(s) to search
.parameter resetusername
    Optional - used to reset the credential
#>
    param(
    [Parameter(Mandatory)]
    [string[]] $servername,
    [switch] $resetusername = $false
        )
    if(!$Global:credential -or $resetusername){
        Make-Credential
    }
    Invoke-Command -ComputerName $servername -Credential $Global:credential -ScriptBlock {Get-LocalGroupMember -Group Administrators
    } | Sort-Object -Property PSComputerName | Format-Table -GroupBy PSComputerName
}



function Get-FreeSpace{
<#
.Description
    Get-FreeSpace
    Gets disk size and free space of the drive specified on the remote server
.parameter servername
    Server(s) to search
.parameter resetusername
    Optional - used to reset the credential
#>
    param(
    [Parameter(Mandatory)]
    [string[]] $servername,
    [switch] $resetusername = $false
        )
    if(!$Global:credential -or $resetusername){
        Make-Credential
    }
    Invoke-Command -ComputerName $servername -Credential $Global:credential -ScriptBlock {
        $disk = Get-WmiObject Win32_LogicalDisc -Filter "DriveType=3"
        $env:COMPUTERNAME
        foreach ($d in $disk){
            $d.DevideID[string] ([math]::Round(($d.FreeSpace / 1gb),3)) + ' Free Space'
            ($d.FreeSpace/$d.Size).tostring('P') + ' Percent Free'
            [string] ([math]::Round(($d.Size / 1gb),3)) + ' Disck Size'
            }
    }
}




function Get-WebsiteStatus{
<#
.Description
    Get-WebsiteStatus
    Gets the status of whether the sites are started or stopped
.parameter servername
    Server(s) to search
.parameter resetusername
    Optional - used to reset the credential
#>
    param(
    [Parameter(Mandatory)]
    [string[]] $servername,
    [switch] $resetusername = $false
        )
    if(!$Global:credential -or $resetusername){
        Make-Credential
    }
    Invoke-Command -ComputerName $servername -Credential $Global:credential -ScriptBlock {
        Import-Module -Name WebAdministration
        $s = Get-Website
        foreach ($i in $s){
            if ($i.state -eq 'Stopped'){
                Write-Host $env:COMPUTERNAME '////' $i.name '---' $i.state -ForegroundColor Red}
                else{
                Write-Host $env:COMPUTERNAME '////' $i.name '---' $i.state -ForegroundColor Green}
                }
        }
}




function Get-AppPools{
<#
.Description
    Get-AppPools
    Gets the app pools on the remote server
.parameter servername
    Server(s) to search
.parameter resetusername
    Optional - used to reset the credential
#>
    param(
    [Parameter(Mandatory)]
    [string[]] $servername,
    [switch] $resetusername = $false
        )
    if(!$Global:credential -or $resetusername){
        Make-Credential
    }
    Invoke-Command -ComputerName $servername -Credential $Global:credential -ScriptBlock {
        Import-Module -Name WebAdministration
        $apppools = gci IIS:\AppPools
        foreach ($apppool in $apppools){
            $Pool                     = $apppool.Name
            $CLR                      = $apppool.ManagedRuntimeVersion
            $bit32                    = $apppool.Enable32BitAppOnWin64
            $autostart                = $apppool.AutoStart
            $State                    = $apppool.State
        [PSCustomObject]@{
            AppPool                   = $Pool
            CLR                       = $CLR
            bit32                     = $bit32
            autostart                 = $autostart
            State                     = $State
            }
        }
    }
}




function Get-Websites{
<#
.Description
    Get-Websites
    Gets a list of the websites on the remote server(s)
.parameter servername
    Server(s) to search
.parameter resetusername
    Optional - used to reset the credential
#>
    param(
    [Parameter(Mandatory)]
    [string[]] $servername,
    [switch] $resetusername = $false
        )
    if(!$Global:credential -or $resetusername){
        Make-Credential
    }
    Invoke-Command -ComputerName $servername -Credential $Global:credential -ScriptBlock {
        Import-Module -Name WebAdministration
        Get-ChildItem -Path IIS:SSLBindings | ForEach-Object -Process `
        {
            if ($_.Sites)
            {
                $certificate = Get-ChildItem -Path Cert:\LocalMachine\My |
                    Where-Object -Property Thumbprint -EQ -Value $_.Thumbprint

                [PSCustomObject]@{
                    Sites                       = $_.Sites.Value
                    IPAddress                   = $_.IPAddress
                    CertificateFriendlyName     = $_.FriendlyName
                    CertificateDnsNameList      = $_.DnsNameList
                    CertificateNotAfter         = $_.NotAfter
                    CertificateIssuer           = $_.Issuer
                    CertificateThumbprint       = $_.Thumbprint
                }
            }
        }
    }
}



