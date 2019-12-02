#Rule Title: The Windows Remote Management (WinRM) client must not use Basic authentication.

#Discussion: Basic authentication uses plain text passwords that could be used to compromise a system.

#Check Text: If the following registry value does not exist or is not configured as specified, this is a finding:

#Registry Hive: HKEY_LOCAL_MACHINE
#Registry Path: \SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\

#Value Name: AllowBasic

#Value Type: REG_DWORD
#Value: 0

#Fix Text: Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> WinRM Client >> "Allow Basic authentication" to "Disabled".


#======================================================
#Derived From:
#CCI: CCI-000877: The organization employs strong authenticators in the establishment of nonlocal maintenance and diagnostic sessions.
#NIST SP 800-53 :: MA-4 c
#NIST SP 800-53A :: MA-4.1 (iv)
#NIST SP 800-53 Revision 4 :: MA-4 c
#======================================================

#Get the mode from the script (enforce or audit)
$scriptMode=$args[0]
write-host "[*] WN10-CC-000330.ps1 running in $scriptMode mode"

$pathExists=$(test-path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client')
if ($pathExists -eq $false) {
    write-host "[!] Registry Path not present."
    write-host "[!] WN10-CC-000330.ps1 Failed."
    Add-Content -Path '.\score.tmp' -Value "[!] WN10-CC-000330.ps1:WinRMClient:Fail"

    if($scriptMode -eq "-enforce"){
        write-host "[%] WN10-CC-000330.ps1 enforcing STIG settings"
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\' -Name AllowBasic -Value 0
        write-host "[%] Disabling WinRM Basic Authentication"
    }
}
elseif ($pathExists -eq $true) {
    $regKey=$(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client')
    $regkey=$regKey.AllowBasic

    if($regKey -eq 0 ){
        write-host "[*] Registry Key for HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowBasic set"
        write-host "[*] WN10-CC-000330.ps1 Passes Sucessfully."
        Add-Content -Path '.\score.tmp' -Value "[*] WN10-CC-000330.ps1:WinRMClient:Pass"
    }
    else{
        Write-Host "[!] WinRM Basic Authentication is enabled."
        write-host "[!] WN10-CC-000330.ps1 Failed."
        Add-Content -Path '.\score.tmp' -Value "[!] WN10-CC-000330.ps1:WinRMClient:Fail"

        if($scriptMode -eq "-enforce"){
            write-host "[%] WN10-CC-000330.ps1 enforcing STIG settings"
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\' -Name AllowBasic -Value 0
            write-host "[%] Disabling WinRM Basic Authentication"
        }
    }
}
Write-Host " "

#Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Value 0