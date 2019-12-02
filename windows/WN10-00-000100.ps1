#Rule Title: Internet Information System (IIS) or its subcomponents must not be installed on a workstation.

#Discussion: Installation of Internet Information System (IIS) may allow unauthorized internet services to be hosted. Websites must only be hosted on servers that have been designed for that purpose and can be adequately secured.

#Check Text: IIS is not installed by default. Verify it has not been installed on the system.

#Run "Programs and Features".
#Select "Turn Windows features on or off".

#If the entries for "Internet Information Services" or "Internet Information Services Hostable Web Core" are selected, this is a finding.

#If an application requires IIS or a subset to be installed to function, this needs be documented with the ISSO. In addition, any applicable requirements from the IIS STIG must be addressed.

#Fix Text: Uninstall "Internet Information Services" or "Internet Information Services Hostable Web Core" from the system.

#======================================================
#Derived From:
#CCI: CCI-000381: The organization configures the information system to provide only essential capabilities.
#NIST SP 800-53 :: CM-7
#NIST SP 800-53A :: CM-7.1 (ii)
#NIST SP 800-53 Revision 4 :: CM-7 a
#======================================================

$scriptMode=$args[0]
write-host "[*] WN10-00-000100.ps1 running in $scriptMode mode"

$webserverStatus=$(Get-WindowsOptionalFeature -Online -FeatureName IIS-WebServer)
$webserverStatus=$webserverStatus.State

if ($webserverStatus -eq 'Disabled'){
    Write-Host "[*] IIS Web Server is Disabled."
    Write-Host "[*] WN10-00-000100.ps1 Passes Successfully."
    Add-Content -Path '.\score.tmp' -Value "[*] WN10-00-000100.ps1:IISWebServer:Pass"
}
elseif ($webserverStatus -eq 'Enabled') {
    Write-Host "[!] IIS Web Server is Enabled."
    Write-Host "[!] WN10-00-000100.ps1 Failed."
    Add-Content -Path '.\score.tmp' -Value "[!] WN10-00-000100.ps1:IISWebServer:Fail"

    if($scriptMode -eq "-enforce"){
        write-host "[%] WN10-00-000100.ps1 enforcing STIG settings."
        $command="Disable-WindowsOptionalFeature -Online -FeatureName IIS-WebServer"
        write-host "[%] Disabled IIS Web Server"
        write-host "[%] Enforcing command $command"
    }
}
write-host " "