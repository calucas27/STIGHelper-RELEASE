#Rule Title: The system must be configured to prevent the storage of the LAN Manager hash of passwords.

#Discussion: The LAN Manager hash uses a weak encryption algorithm and there are several tools available that use this hash to retrieve account passwords. This setting controls whether or not a LAN Manager hash of the password is stored in the SAM the next time the password is changed.

#Check Text: If the following registry value does not exist or is not configured as specified, this is a finding:

#Registry Hive: HKEY_LOCAL_MACHINE
#Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\

#Value Name: NoLMHash

#Value Type: REG_DWORD
#Value: 1

#Fix Text: Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network security: Do not store LAN Manager hash value on next password change" to "Enabled".

#======================================================
#CCI: CCI-000196: The information system, for password-based authentication, stores only encrypted representations of passwords.
#NIST SP 800-53 :: IA-5 (1) (c)
#NIST SP 800-53A :: IA-5 (1).1 (v)
#NIST SP 800-53 Revision 4 :: IA-5 (1) (c)
#======================================================

$scriptMode=$args[0]
write-host "[*] WN10-SO-000195.ps1 running in $scriptMode mode"

$pathExists=$(test-path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa')
if ($pathExists -eq $false) {
    write-host "[!] Registry Path not present."
    write-host "[!] LAN Manager hash is stored."
    write-host "[!] WN10-SO-000195.ps1 Failed."
    Add-Content -Path '.\score.tmp' -Value "[!] WN10-SO-000195.ps1:LanManHash:Fail"

    if($scriptMode -eq "-enforce"){
        write-host "[%] WN10-SO-000195.ps1 enforcing STIG settings"
        write-host "[%] Disabling storage of LAN Manager passwords."
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -Value 1
    }
}
elseif ($pathExists -eq $true) {
    $regKey=$(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa')
    $regkey=$regKey.NoLMHash

    if($regKey -eq 1 ){
        write-host "[*] HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\NoLMHash set"
        write-host "[*] Storage of Lan Manager hashes are disabled."
        write-host "[*] WN10-SO-000195.ps1 Passes Sucessfully."
        Add-Content -Path '.\score.tmp' -Value "[*] WN10-SO-000195.ps1:LanManHash:Pass"
    }
    else{
        write-host "[!] LAN Manager hash is stored."
        write-host "[!] WN10-SO-000195.ps1 Failed."
        Add-Content -Path '.\score.tmp' -Value "[!] WN10-SO-000195.ps1:LanManHash:Fail"

        if($scriptMode -eq "-enforce"){
            write-host "[%] WN10-SO-000195.ps1 enforcing STIG settings"
            write-host "[%] Disabling storage of LAN Manager passwords."
            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -Value 1
        }
    }
}
write-host " "