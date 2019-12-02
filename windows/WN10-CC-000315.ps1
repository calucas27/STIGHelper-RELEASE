#WN10-CC-000315
#Group Title: WN10-CC-000315

#Rule Title: The Windows Installer Always install with elevated privileges must be disabled.

#Discussion: Standard user accounts must not be granted elevated privileges. Enabling Windows Installer to elevate privileges when installing applications can allow malicious persons and applications to gain full control of a system.

#Check Text: If the following registry value does not exist or is not configured as specified, this is a finding:

#Registry Hive: HKEY_LOCAL_MACHINE
#Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Installer\
#HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated

#Value Name: AlwaysInstallElevated
#Value Type: REG_DWORD
#Value: 0

#Fix Text: Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Installer >> "Always install with elevated privileges" to "Disabled".

#======================================================
#Derived From:
#CCI: CCI-001812: The information system prohibits user installation of software without explicit privileged status.
#NIST SP 800-53 Revision 4 :: CM-11 (2)
#======================================================

#Get the mode from the script (enforce or audit)
$scriptMode=$args[0]
write-host "[*] WN10-CC-000315.ps1 running in $scriptMode mode"

$pathExists=$(test-path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer')
if ($pathExists -eq $false) {
    write-host "[!] Registry Path not present."
    write-host "[!] Windows Installer has elevated privileges"
    write-host "[!] WN10-CC-000315.ps1 Failed."
    Add-Content -Path '.\score.tmp' -Value "[!] WN10-CC-000315.ps1:ElevatedInstaller:Fail"

    if($scriptMode -eq "-enforce"){
        write-host "[%] WN10-CC-000315.ps1 enforcing STIG settings"
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Value 0
        write-host "[%] Disabling Elevated Windows Installer"
    }
}
elseif ($pathExists -eq $true) {
    $regKey=$(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated')
    $regkey=$regKey.AlwaysInstallElevated

    if($regKey -eq 0 ){
        write-host "[*] Registry Key for HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated set"
        write-host "[*] WN10-CC-000315.ps1 Passes Sucessfully."
        Add-Content -Path '.\score.tmp' -Value "[*] WN10-CC-000315.ps1:ElevatedInstaller:Pass"
    }
    else{
        Write-Host "[!] Windows Installer has elevated privileges."
        write-host "[!] WN10-CC-000315.ps1 Failed."
        Add-Content -Path '.\score.tmp' -Value "[!] WN10-CC-000315.ps1:ElevatedInstaller:Fail"

        if($scriptMode -eq "-enforce"){
            write-host "[%] WN10-CC-000315.ps1 enforcing STIG settings"
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Value 0
            write-host "[%] Disabling Elevated Windows Installer"
        }
    }
}
Write-Host " "