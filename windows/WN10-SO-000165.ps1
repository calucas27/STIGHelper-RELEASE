#Rule Title: Anonymous access to Named Pipes and Shares must be restricted.

#Discussion: Allowing anonymous access to named pipes or shares provides the potential for unauthorized system access. This setting restricts access to those defined in "Network access: Named Pipes that can be accessed anonymously" and "Network access: Shares that can be accessed anonymously", both of which must be blank under other requirements.

#Check Text: If the following registry value does not exist or is not configured as specified, this is a finding:

#Registry Hive: HKEY_LOCAL_MACHINE
#Registry Path: \SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\

#'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name 'RestrictNullSessAccess' -Value 1

#Value Name: RestrictNullSessAccess

#Value Type: REG_DWORD
#Value: 1

#Fix Text: Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network access: Restrict anonymous access to Named Pipes and Shares" to "Enabled".

#======================================================
#Derived From:
#CCI: CCI-001090: The information system prevents unauthorized and unintended information transfer via shared system resources.
#NIST SP 800-53 :: SC-4
#NIST SP 800-53A :: SC-4.1
#NIST SP 800-53 Revision 4 :: SC-4
#======================================================

$scriptMode=$args[0]
write-host "[*] WN10-SO-000165.ps1 running in $scriptMode mode"

$pathExists=$(test-path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters')
if ($pathExists -eq $false) {
    write-host "[!] Registry Path not present."
    write-host "[!] Anonymous access to named pipes and shares is allowed."
    write-host "[!] WN10-SO-000165.ps1 Failed."
    Add-Content -Path '.\score.tmp' -Value "[!] WN10-SO-000165.ps1:NamedPipes:Fail"

    if($scriptMode -eq "-enforce"){
        write-host "[%] WN10-SO-000165.ps1 enforcing STIG settings"
        write-host "[%] Disabling anonymous access to named pipes and shares."
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name 'RestrictNullSessAccess' -Value 1
    }
}
elseif ($pathExists -eq $true) {
    $regKey=$(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters')
    $regkey=$regKey.RestrictNullSessAccess

    if($regKey -eq 1 ){
        write-host "[*] HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess set"
        write-host "[*] Anonymous access to named pipes and shares is restricted."
        write-host "[*] WN10-SO-000165.ps1 Passes Sucessfully."
        Add-Content -Path '.\score.tmp' -Value "[*] WN10-SO-000165.ps1:NamedPipes:Pass"
    }
    else{
        write-host "[!] Anonymous access to named pipes and shares is allowed."
        write-host "[!] WN10-SO-000165.ps1 Failed."
        Add-Content -Path '.\score.tmp' -Value "[!] WN10-SO-000165.ps1:NamedPipes:Fail"

        if($scriptMode -eq "-enforce"){
            write-host "[%] WN10-SO-000165.ps1 enforcing STIG settings"
            write-host "[%] Disabling anonymous access to named pipes and shares."
            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name 'RestrictNullSessAccess' -Value 1
        }
    }
}
write-host " "