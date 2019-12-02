#Rule Title: Anonymous enumeration of SAM accounts must not be allowed.

#Discussion: Anonymous enumeration of SAM accounts allows anonymous log on users (null session connections) to list all accounts names, thus providing a list of potential points to attack the system.

#Check Text: If the following registry value does not exist or is not configured as specified, this is a finding:

#Registry Hive: HKEY_LOCAL_MACHINE
#Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\

#Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -Value 1

#Value Name: RestrictAnonymousSAM

#Value Type: REG_DWORD
#Value: 1

#Fix Text: Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network access: Do not allow anonymous enumeration of SAM accounts" to "Enabled".

#======================================================
#Derived From:
#CCI: CCI-000366: The organization implements the security configuration settings.
#NIST SP 800-53 :: CM-6 b
#NIST SP 800-53A :: CM-6.1 (iv)
#NIST SP 800-53 Revision 4 :: CM-6 b
#======================================================

$scriptMode=$args[0]
write-host "[*] WN10-SO-000145.ps1 running in $scriptMode mode"

$pathExists=$(test-path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa')
if ($pathExists -eq $false) {
    write-host "[!] Registry Path not present."
    write-host "Anonymous enumeration of SAM accounts is allowed."
    write-host "[!] WN10-SO-000145.ps1 Failed."
    Add-Content -Path '.\score.tmp' -Value "[!] WN10-SO-000145.ps1:AnonymousSAMAccounts:Fail"

    if($scriptMode -eq "-enforce"){
        write-host "[%] WN10-SO-000145.ps1 enforcing STIG settings"
        write-host "[%] Disabling enumeration of SAM accounts."
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -Value 1
    }
}
elseif ($pathExists -eq $true) {
    $regKey=$(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa')
    $regkey=$regKey.RestrictAnonymousSAM

    if($regKey -eq 1 ){
        write-host "[*] HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM set"
        write-host "[*] Anonymous SAM enumeration is disabled."
        write-host "[*] WN10-SO-000145.ps1 Passes Sucessfully."
        Add-Content -Path '.\score.tmp' -Value "[*] WN10-SO-000145.ps1:AnonymousSAMAccounts:Pass"
    }
    else{
        write-host "Anonymous enumeration of SAM accounts is allowed."
        write-host "[!] WN10-SO-000145.ps1 Failed."
        Add-Content -Path '.\score.tmp' -Value "[!] WN10-SO-000145.ps1:AnonymousSAMAccounts:Fail"

        if($scriptMode -eq "-enforce"){
            write-host "[%] WN10-SO-000145.ps1 enforcing STIG settings"
            write-host "[%] Disabling enumeration of SAM accounts."
            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -Value 1
        }
    }
}
write-host " "