# Powershell
 My place to work with powershell


Powershell Functions in MyFunctions.ps1:
    Make-Credential
        Creates a global credential for use by the other functions
    Get-Systeminfo
        Gets system info of the remote server
    Get-Memory
        Gets RAM info of the remote server
    Get-Admin_Group-Membership
        Gets admin group membership info of the remote server
    Get-FreeSpace
        Gets disk size and free space of the drive specified on the remote server
    Get-WebsiteStatus
        Gets the status of whether the sites are started or stopped
    Get-AppPools
        Gets the app pools on the remote server
    Get-Websites
        Gets a list of the websites on the remote server(s)
    Get-Certificates
        Gets a list of the certificates on the remote server
    Get-Remote-Service
        Gets the status of the specified service on the remote server


Powershell Functions in ManageServers.ps1:
    Make-Credential
        Creates a global credential for use by the other functions
    Get-Systeminfo
        Gets system info of the remote server
    Get-Memory
        Gets RAM info of the remote server
    Get-Admin_Group-Membership
        Gets admin group membership info of the remote server
    Get-FreeSpace
        Gets disk size and free space of the drive specified on the remote server
    Get-Remote-Service
        Gets the status of the specified service on the remote server
    Copy-Between-Servers
        Copies files between remote servers while running from the local machine
    Restart-Server
        Forces a restart on the remote server
    Stop-Remote-Service
        Stops a service on the remote server
    Start-Remote-Service
        Starts a service on the remote server
    Disable-Remote-Service
        Disables a service on the remote server
    Update-Help
        Updates the Help associated with all cmdlets in all modules on the remote server
    


Powershell Functions in ManageCertificates.ps1:
    Make-Credential
        Creates a global credential for use by the other functions
    Invoke-Copy-To
        Creates a session to copy from local to the remote server
    Get-Certificates
        Gets a list of the certificates on the remote server
    Make-Certificate-Request
        Used to create the csr for a certificate request
        Currently broken
    Import-Certificate-Request
        Used to import the certificate response from the issuer on a remote server
    Export-PFX-Certificate
        Exports a certificate in pfx format from a remote server
    Copy-Between-Servers
        Copies files between remote servers but runs from the local machine, so the exported PFX can be copied to other servers.
    Import-PFX-Certificate
        Imports a PFX certificate into the LocalMachine\My store on a remote server
    Assign-Certificate
        Used to assign a certificate to a website on a remote server


Powershell Functions in ManageSites.ps1:
    Make-Credential
        Creates a global credential for use by the other functions
    Invoke-Copy-To
        Creates a session to copy from local to the remote server
    Get-Websites
        Gets a list of the websites on the remote server(s)
    Get-WebsiteStatus
        Gets the status of whether the sites are started or stopped
    Start-Website
        Starts a website on the remote server(s)
    Stop-Website
        Stops a website on the remote server(s)
    Restart-Websites
        Restarts IIS on the remote server(s)
    Get-AppPools
        Gets the app pools on the remote server
    