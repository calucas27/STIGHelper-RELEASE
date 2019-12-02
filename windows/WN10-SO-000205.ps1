#Rule Title: The LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM.

#Discussion: The Kerberos v5 authentication protocol is the default for authentication of users who are logging on to domain accounts. NTLM, which is less secure, is retained in later Windows versions for compatibility with clients and servers that are running earlier versions of Windows or applications that still use it. It is also used to authenticate logons to stand-alone computers that are running later versions.

#Check Text: If the following registry value does not exist or is not configured as specified, this is a finding:

#Registry Hive: HKEY_LOCAL_MACHINE
#Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\

#Value Name: LmCompatibilityLevel

#Value Type: REG_DWORD
#Value: 5

#Fix Text: Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network security: LAN Manager authentication level" to "Send NTLMv2 response only. Refuse LM & NTLM".

$scriptMode=$args[0]
write-host "[*] WN10-SO-000205.ps1 running in $scriptMode mode"

$pathExists=$(test-path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa')
if ($pathExists -eq $false) {
    write-host "[!] Registry Path not present."
    write-host "[!] LM and NTLM responses are not refused."
    write-host "[!] WN10-SO-000205.ps1 Failed."
    Add-Content -Path '.\score.tmp' -Value "[!] WN10-SO-000205.ps1:NTLMv2Only:Fail"

    if($scriptMode -eq "-enforce"){
        write-host "[%] WN10-SO-000205.ps1 enforcing STIG settings"
        write-host "[%] Allowing only NTLMv2 Responses."
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 5
    }
}
elseif ($pathExists -eq $true) {
    $regKey=$(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa')
    $regkey=$regKey.LmCompatibilityLevel

    if($regKey -eq 5 ){
        write-host "[*] HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel set"
        write-host "[*] Only NTLMv2 responses allowed."
        write-host "[*] WN10-SO-000205.ps1 Passes Sucessfully."
        Add-Content -Path '.\score.tmp' -Value "[*] WN10-SO-000205.ps1:NTLMv2Only:Pass"
    }
    else{
        write-host "[!] LM and NTLM responses are not refused."
        write-host "[!] WN10-SO-000205.ps1 Failed."
        Add-Content -Path '.\score.tmp' -Value "[!] WN10-SO-000205.ps1:NTLMv2Only:Fail"

        if($scriptMode -eq "-enforce"){
            write-host "[%] WN10-SO-000205.ps1 enforcing STIG settings"
            write-host "[%] Allowing only NTLMv2 Responses."
            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 5
        }
    }
}
write-host " "