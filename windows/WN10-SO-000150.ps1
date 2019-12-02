#Rule Title: Anonymous enumeration of shares must be restricted.

#Discussion: Allowing anonymous logon users (null session connections) to list all account names and enumerate all shared resources can provide a map of potential points to attack the system.

#Check Text: If the following registry value does not exist or is not configured as specified, this is a finding:

#Registry Hive: HKEY_LOCAL_MACHINE
#Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\

#Value Name: RestrictAnonymous

#Value Type: REG_DWORD
#Value: 1

#Fix Text: Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network access: Do not allow anonymous enumeration of SAM accounts and shares" to "Enabled".

#======================================================
#Derived From:
#CCI: CCI-001090: The information system prevents unauthorized and unintended information transfer via shared system resources.
#NIST SP 800-53 :: SC-4
#NIST SP 800-53A :: SC-4.1
#NIST SP 800-53 Revision 4 :: SC-4
#======================================================

$scriptMode=$args[0]
write-host "[*] WN10-SO-000150.ps1 running in $scriptMode mode"

$pathExists=$(test-path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa')
if ($pathExists -eq $false) {
    write-host "[!] Registry Path not present."
    write-host "[!] Anonymous enumeration of network shares is allowed."
    write-host "[!] WN10-SO-000150.ps1 Failed."
    Add-Content -Path '.\score.tmp' -Value "[!] WN10-SO-000150.ps1:AnonymousShares:Fail"

    if($scriptMode -eq "-enforce"){
        write-host "[%] WN10-SO-000150.ps1 enforcing STIG settings"
        write-host "[%] Disabling enumeration of network shares."
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Value 1
    }
}
elseif ($pathExists -eq $true) {
    $regKey=$(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa')
    $regkey=$regKey.RestrictAnonymous

    if($regKey -eq 1 ){
        write-host "[*] HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymous set"
        write-host "[*] Anonymous enumeration of network shares is disabled."
        write-host "[*] WN10-SO-000150.ps1 Passes Sucessfully."
        Add-Content -Path '.\score.tmp' -Value "[*] WN10-SO-000150.ps1:AnonymousShares:Pass"
    }
    else{
        write-host "[!] Anonymous enumeration of network shares is allowed."
        write-host "[!] WN10-SO-000150.ps1 Failed."
        Add-Content -Path '.\score.tmp' -Value "[!] WN10-SO-000150.ps1:AnonymousShares:Fail"

        if($scriptMode -eq "-enforce"){
            write-host "[%] WN10-SO-000150.ps1 enforcing STIG settings"
            write-host "[%] Disabling enumeraiton of network shares."
            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Value 1
        }
    }
}
write-host " "