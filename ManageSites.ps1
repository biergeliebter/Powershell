<#
.Description
    Creates Variables for server groups so you don't have to remember server names 
    Replace server values with FQDN or other target value of the remote servers. 
    These create an array, so if there is only one server it needs to be input twice for the variable to work correctly.

#>
Set-Variable -name serversMYAPPSERVERS -value 'server1', 'server2' -option Constant
Set-Variable -name serversMYWEBSERVERS -value 'server1', 'server2' -option Constant


function Make-Credential{
<#
.Description
    Make-Credential
    Creates a global credential to be used by the other functions so they can connect to the remote server(s). 
    Be sure to replace the username value below with the actual username, ie account@email.com.
#>
    param (
    [string] $username = "replace_with_username",
    [string] $message = "Creates a credential to Global:credential for reuse"
    )
    $Global:credential = Get-Credential -Message $message -UserName $username
    }





function Invoke-Copy-To{
<#
.Description
    Invoke-Copy-To
    Creates a session to copy from local to the remote server
.parameter servername
    Remote server
.parameter sourcefile
    Local file to copy
.parameter destinationFile
    Path and name of the destination file
.parameter resetusername
    Optional - used to reset the credential
#>
    param(
    [Parameter(Mandatory)]
    [string] $servername,
    [Parameter(Mandatory)]
    [string] $sourcefile,
    [Parameter(Mandatory)]
    [string] $destinationFile,
    [switch] $justcopy = $false,
    [switch] $resetusername = $false
        )
    if(!$Global:credential -or $resetusername){
        Make-Credential
    }
    Invoke-Command -ComputerName $servername -Credential $Global:credential -ArgumentList $destinationFile -ScriptBlock {
        if (!(Test-Path -Path $args[0])){mkdir $args[0]}}
            $session = New-PSSession -ComputerName $servername -Credential $Global:credential
            Copy-Item -Path $sourcefile -Destination $destinationFile -ToSession $session -Force
            if(!$justcopy){
                Invoke-Command -FilePath $profile -Session $session
                Enter-PSSession -Session $session

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
    [string] $servername,
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
    [string] $servername,
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




function Start-Website{
<#
.Description
    Start-Website
    Starts a website on the remote server(s)
.parameter servername
    Server(s) to execute on
.parameter sitename
    Name of the site to start. If none provide it starts them all.
.parameter resetusername
    Optional - used to reset the credential
#>
    param(
    [Parameter(Mandatory)]
    [string] $servername,
    [string] $sitename='all',
    [switch] $resetusername = $false
        )
    if(!$Global:credential -or $resetusername){
        Make-Credential
    }
    Invoke-Command -ComputerName $servername -Credential $Global:credential -ScriptBlock {
        Import-Module -Name WebAdministration
        if ($using:sitename -eq 'all'){
            Get-Website | Start-Website}
            else
            {
            Start-Website $using:sitename}
        }
    }
}





function Stop-Website{
<#
.Description
    Stop-Website
    Stops a website on the remote server(s)
.parameter servername
    Server(s) to execute on
.parameter sitename
    Name of the site to stop. If none provide it stops them all.
.parameter resetusername
    Optional - used to reset the credential
#>
    param(
    [Parameter(Mandatory)]
    [string] $servername,
    [string] $sitename='all',
    [switch] $resetusername = $false
        )
    if(!$Global:credential -or $resetusername){
        Make-Credential
    }
    Invoke-Command -ComputerName $servername -Credential $Global:credential -ScriptBlock {
        Import-Module -Name WebAdministration
        if ($using:sitename -eq 'all'){
            Get-Website | Stop-Website}
            else
            {
            Stop-Website $using:sitename}
        
    }
}







function Restart-Websites{
<#
.Description
    Restart-Websites
    Restarts IIS on the remote server(s)
.parameter servername
    Server(s) to execute on
.parameter resetusername
    Optional - used to reset the credential
#>
    param(
    [Parameter(Mandatory)]
    [string] $servername,
    [switch] $resetusername = $false
        )
    if(!$Global:credential -or $resetusername){
        Make-Credential
    }
    Invoke-Command -ComputerName $servername -Credential $Global:credential -ScriptBlock {iisreset /restart}
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










Start-AppPools
Stop-AppPools
Restart-AppPools

Change-IISPort
Delete-Old-IIS-Logs
