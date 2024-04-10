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




function Get-Remote-Service{
<#
.Description
    Get-Remote-Service
    Gets the status of the specified service on the remote server
.parameter servername
    Server(s) to search
.parameter servicename
    Name of the service you want to see
.parameter resetusername
    Optional - used to reset the credential
#>
    param(
    [Parameter(Mandatory)]
    [string] $servername,
    [Parameter(Mandatory)]
    [string] $servicename,
    [switch] $resetusername = $false
        )
    if(!$Global:credential -or $resetusername){
        Make-Credential
    }
    Invoke-Command -ComputerName $servername -Credential $Global:credential -ScriptBlock {
        gci Cert:\LocalMachine\My | Format-List -Property Thumbprint, NotAfter, Issuer, Subject, EnhancedKeyUsageList, HasPrivateKey }
}




function Copy-Between-Servers{
<#
.Description
    Copy-Between-Servers
    Copies files between remote servers but runs from the local machine
.parameter servernamefrom
    Server to be copied from
.parameter servernameto
    Server to be copied to
.parameter sourcefile
    Path and name of the file(s) to be copied
    Wildcards accepted
    Example: "D:\software\myfile.txt"
.parameter destination
    The destination folder you want to copy the file(s) to
    The drive is specified in the command so if you need it to be something other than D, change the command in the function.
    Example syntax: "\software\"
.parameter resetusername
    Optional - used to reset the credential
#>
    param(
    [Parameter(Mandatory)]
    [string] $servernamefrom,
    [Parameter(Mandatory)]
    [string] $servernameto,
    [Parameter(Mandatory)]
    [string] $ssourcefile,
    [Parameter(Mandatory)]
    [string] $destination,
    [switch] $resetusername = $false
        )
    if(!$Global:credential -or $resetusername){
        Make-Credential
    }
    $username = $Global:credential.UserName
    Invoke-Command -ComputerName $servernamefrom -Credential $Global:credential -ScriptBlock {
        $cred = Get-Credential -Message "server copy" -UserName $Using:username ; New-PSDrive -Name J -PSProvider FileSystem -Root \\$using:servernameto\D$ -Credential $cred ; copy $using:sourcefile J:\$using:destination -Force}
}





function Restart-Server{
<#
.Description
    Restart-Server
    Forces a restart on the remote server
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
    Invoke-Command -ComputerName $servername -Credential $Global:credential -ScriptBlock {Restart-Computer -Force }
}




function Stop-Remote-Service{
<#
.Description
    Stop-Remote-Service
    Stops a service on the remote server
.parameter servername
    Server(s) to search
.parameter servicename
    Name of the service to stop
.parameter resetusername
    Optional - used to reset the credential
#>
    param(
    [Parameter(Mandatory)]
    [string] $servername,
    [Parameter(Mandatory)]
    [string] $servicename,
    [switch] $resetusername = $false
        )
    if(!$Global:credential -or $resetusername){
        Make-Credential
    }
    Invoke-Command -ComputerName $servername -Credential $Global:credential -ArgumentList $servicename -ScriptBlock {Stop-Service -Name $servicename -Force}
}



function Start-Remote-Service{
<#
.Description
    Start-Remote-Service
    Starts a service on the remote server
.parameter servername
    Server(s) to search
.parameter servicename
    Name of the service to stop
.parameter resetusername
    Optional - used to reset the credential
#>
    param(
    [Parameter(Mandatory)]
    [string] $servername,
    [Parameter(Mandatory)]
    [string] $servicename,
    [switch] $resetusername = $false
        )
    if(!$Global:credential -or $resetusername){
        Make-Credential
    }
    Invoke-Command -ComputerName $servername -Credential $Global:credential -ArgumentList $servicename -ScriptBlock {param ($servicename) Start-Service -Name $servicename}
}




function Disable-Remote-Service{
<#
.Description
    Disable-Remote-Service
    Disables a service on the remote server
.parameter servername
    Server(s) to search
.parameter servicename
    Name of the service to stop
.parameter resetusername
    Optional - used to reset the credential
#>
    param(
    [Parameter(Mandatory)]
    [string] $servername,
    [Parameter(Mandatory)]
    [string] $servicename,
    [switch] $resetusername = $false
        )
    if(!$Global:credential -or $resetusername){
        Make-Credential
    }
    Invoke-Command -ComputerName $servername -Credential $Global:credential -ArgumentList $servicename -ScriptBlock {param ($servicename) Set-Service -Name $servicename -StartupType Disabled}
}




function Update-Help{
<#
.Description
    Update-Help
    Updates the Help associated with all cmdlets in all modules on the remote server
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
    Invoke-Command -ComputerName $servername -Credential $Global:credential -ScriptBlock {Update-Help}
}

