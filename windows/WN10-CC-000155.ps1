#Rule Title: Solicited Remote Assistance must not be allowed.

#Discussion: Remote assistance allows another user to view or take control of the local session of a user. Solicited assistance is help that is specifically requested by the local user. This may allow unauthorized parties access to the resources on the computer.

#Check Text: If the following registry value does not exist or is not configured as specified, this is a finding:

#Registry Hive: HKEY_LOCAL_MACHINE
#Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\
#HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp

#Value Name: fAllowToGetHelp

#Value Type: REG_DWORD
#Value: 0

#Fix Text: Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Remote Assistance >> "Configure Solicited Remote Assistance" to "Disabled".

#======================================================
#Derived From:
#CCI: CCI-001090: The information system prevents unauthorized and unintended information transfer via shared system resources.
#NIST SP 800-53 :: SC-4
#NIST SP 800-53A :: SC-4.1
#NIST SP 800-53 Revision 4 :: SC-4
#======================================================


$scriptMode=$args[0]
write-host "[*] WN10-CC-000155.ps1 running in $scriptMode mode"

$pathExists=$(test-path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services')
if ($pathExists -eq $false) {
    write-host "[!] Registry Path not present."
    Write-Host "[!] Remote Assistance is Enabled."
    write-host "[!] WN10-CC-000155.ps1 Failed."
    Add-Content -Path '.\score.tmp' -Value "[!] WN10-CC-000155.ps1:RemoteAssistance:Fail"

    if($scriptMode -eq "-enforce"){
        write-host "[%] WN10-CC-000155.ps1 enforcing STIG settings"
        write-host "[%] Disabling Remote Assistance"
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' -Name 'fAllowToGetHelp' -Value 0
    }
}
elseif ($pathExists -eq $true) {
    $regKey=$(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fAllowToGetHelp)
    $regkey=$regKey.fAllowToGetHelp

    if($regKey -eq 0 ){
        write-host "[*] Registry Key for HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp set"
        write-host "[*] Remote Assistance is Disabled"
        write-host "[*] WN10-CC-000155.ps1 Passes Sucessfully."
        Add-Content -Path '.\score.tmp' -Value "[*] WN10-CC-000155.ps1:RemoteAssistance:Pass"
    }
    else{
        Write-Host "[!] Remote Assistance is Enabled."
        write-host "[!] WN10-CC-000155.ps1 Failed."
        Add-Content -Path '.\score.tmp' -Value "[!] WN10-CC-000155.ps1:RemoteAssistance:Fail"

        if($scriptMode -eq "-enforce"){
            write-host "[%] WN10-CC-000155.ps1 enforcing STIG settings"
            write-host "[%] Disabling Remote Assistance"
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' -Name 'fAllowToGetHelp' -Value 0
        }
    }
}

write-host " "