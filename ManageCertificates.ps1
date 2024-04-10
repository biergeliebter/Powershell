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





function Get-Certificates{
<#
.Description
    Get-Certificates
    Gets a list of the certificates on the remote server
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
        gci Cert:\LocalMachine\My | Format-List -Property Thumbprint, NotAfter, Issuer, Subject, EnhancedKeyUsageList, HasPrivateKey }
}




function Make-Certificate-Request{
<#
.Description
    Make-Certificate-Request
    Used to create the csr for a certificate request
    Broken the last time I tried to use it
.parameter servername
    Name of the server that will create the request
.parameter certtemplate
    The certificate template that will be used
.parameter certcsr
    Name of the csr that will be created
.parameter resetusername
    Optional - used to reset the credential
#>
    param(
    [Parameter(Mandatory)]
    [string[]] $servername,
    [Parameter(Mandatory)]
    [string[]] $certtemplate,
    [Parameter(Mandatory)]
    [string[]] $certcsr,
    [switch] $resetusername = $false
        )
    if(!$Global:credential -or $resetusername){
        Make-Credential
    }
        Invoke-Copy-To -servername $servername -sourcefile $certtemplate -destinationFile C:\Temp -justcopy
        $templist = $certtemplate.Split("\")
        $templatename = "C:\Temp\"+$templist[$templist.count-1]
        $certcsr2 = "C:\Temp\"+$certcsr
        $templatename
        $certcsr2
        Invoke-Command -ComputerName $servername -Credential $Global:credential -ScriptBlock {
        if(Test-Path $using:certcsr2){Remove-Item $using:certcsr2}
        C:\Windows\System32\certreq.exe -New $using:templatename $using:certcsr2
        Get-Content $using:certcsr2 }
}




function Import-Certificate-Request{
<#
.Description
    Import-Certificate-Request
    Used to import the certificate response from the issuer
.parameter servername
    Name of the server to execute on
.parameter certresponse
    Name of the certificate response from the issuer
.parameter resetusername
    Optional - used to reset the credential
#>
    param(
    [Parameter(Mandatory)]
    [string] $servername,
    [Parameter(Mandatory)]
    [string] $certresponse,
    [switch] $resetusername = $false
        )
    if(!$Global:credential -or $resetusername){
        Make-Credential
    }
        Invoke-Copy-To -servername $servername -sourcefile $certresponse -destinationFile C:\Temp -justcopy
        $templist = $certresponse.Split("\")
        $templatename = "C:\Temp\"+$templist[$templist.count-1]
        $templatename
        Invoke-Command -ComputerName $servername -Credential $Global:credential -ScriptBlock {C:\Windows\System32\certreq.exe -Accept $using:templatename }
}





function Export-PFX-Certificate{
<#
.Description
    Export-PFX-Certificate
    Exports a certificate in pfx format from a remote server
.parameter servername
    Name of the server to execute on
.parameter thumbprint
    certificate thumbprint (use Get-Certificates to retrieve it)
.parameter pfxname
    Name of the pfx file to export
.parameter path
    Location to export the pfx (include \ on the end)
    Default is D:\SSL-Cert\
.parameter password
    Password of the new pfx
.parameter resetusername
    Optional - used to reset the credential
#>
    param(
    [Parameter(Mandatory)]
    [string] $servername,
    [Parameter(Mandatory)]
    [string] $thumbprint,
    [Parameter(Mandatory)]
    [string] $pfxname,
    [Parameter(Mandatory)]
    [string] $path = "D:\SSL-Cert\",
    [Parameter(Mandatory)]
    [string] $password,
    [switch] $resetusername = $false
        )
    if(!$Global:credential -or $resetusername){
        Make-Credential
    }
        [securestring] $password1 = $password | ConvertTo-SecureString -AsPlainText -Force
        Invoke-Command -ComputerName $servername -Credential $Global:credential -ScriptBlock {
        gci Cert:\LocalMachine\My\$using:thumbprint | Export-PFXCertificate -password $using:password1 -FilePath $using:path$using:pfxname -Force
        }
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





function Import-PFX-Certificate{
<#
.Description
    Import-PFX-Certificate
    Imports a PFX certificate into the LocalMachine\My store on a remote server
.parameter servername
    Name of the server to execute on
.parameter pfxname
    Name of the pfx file to import
.parameter path
    Location to import the pfx from (include \ on the end)
    Default is D:\SSL-Cert\
.parameter password
    Password of the pfx being imported
.parameter resetusername
    Optional - used to reset the credential
#>
    param(
    [Parameter(Mandatory)]
    [string] $servername,
    [Parameter(Mandatory)]
    [string] $pfxname,
    [Parameter(Mandatory)]
    [string] $path = "D:\SSL-Cert\",
    [Parameter(Mandatory)]
    [string] $password,
    [switch] $resetusername = $false
        )
    if(!$Global:credential -or $resetusername){
        Make-Credential
    }
        [securestring] $password1 = $password | ConvertTo-SecureString -AsPlainText -Force
        Invoke-Command -ComputerName $servername -Credential $Global:credential -ScriptBlock {
        Import-PFXCertificate -Exportable -Password $using:password1 -CertStoreLocation Cert:\LocalMachine\My\ -FilePath $using:path$using:pfxname
        }
}





function Assign-Certificate{
<#
.Description
    Assign-Certificate
    Used to assign a certificate to a website on a remote server
.parameter servername
    Name of the server to execute on
.parameter thumbprint
    The thumbprint of the certificate to assign (get this via Get-Certificates)
.parameter website
    The website to assign the certificate to
.parameter resetusername
    Optional - used to reset the credential
#>
    param(
    [Parameter(Mandatory)]
    [string] $servername,
    [Parameter(Mandatory)]
    [string] $thumbprint,
    [Parameter(Mandatory)]
    [string] $website,
    [switch] $resetusername = $false
        )
    if(!$Global:credential -or $resetusername){
        Make-Credential
    }
        Invoke-Command -ComputerName $servername -Credential $Global:credential -ScriptBlock {
            Import-Module WebAdministration
            $binding = Get-WebBinding -Name $using:website
            $bindsplit = $binding.bindinginformation.split(":")
            $bindpath = "IIS:\SslBindings\"+$bindsplit[0]+"!"+$bindsplit[1]
            gci Cert:\LocalMachine\My\$using:thumbprint | Set-Item -Path $bindpath
            }
}



