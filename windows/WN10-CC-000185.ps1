#Rule Title: The default autorun behavior must be configured to prevent autorun commands.

#Discussion: Allowing autorun commands to execute may introduce malicious code to a system. Configuring this setting prevents autorun commands from executing.

#Check Text: If the following registry value does not exist or is not configured as specified, this is a finding:

#Registry Hive: HKEY_LOCAL_MACHINE
#Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\

#Value Name: NoAutorun

#Value Type: REG_DWORD
#Value: 1

#Fix Text: Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> AutoPlay Policies >> "Set the default behavior for AutoRun" to "Enabled:Do not execute any autorun commands".


#======================================================
#Derived From:
#CCI: CCI-001764: The information system prevents program execution in accordance with organization-defined policies regarding software program usage and restrictions, and/or rules authorizing the terms and conditions of software program usage.
#NIST SP 800-53 Revision 4 :: CM-7 (2)
#======================================================

$scriptMode=$args[0]
write-host "[*] WN10-CC-000185.ps1 running in $scriptMode mode"

$pathExists=$(test-path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer')
if ($pathExists -eq $false) {
    write-host "[!] Registry Path not present."
    Write-Host "[!] Autoplay is Enabled."
    write-host "[!] WN10-CC-000185.ps1 Failed."
    Add-Content -Path '.\score.tmp' -Value "[!] WN10-CC-000185.ps1:AutoplayEnabled:Fail"

    if($scriptMode -eq "-enforce"){
        write-host "[%] WN10-CC-000185.ps1 enforcing STIG settings"
        write-host "[%] Disabling AutoPlay"
        New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name 'NoAutorun' -Value 1 -Force
    }
}
elseif ($pathExists -eq $true) {
    $regKey=$(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name NoAutorun)
    $regkey=$regKey.NoAutorun

    if($regKey -eq 1 ){
        write-host "[*] HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoAutorun set"
        write-host "[*] WN10-CC-000185.ps1 Passes Sucessfully."
        Add-Content -Path '.\score.tmp' -Value "[*] WN10-CC-000185.ps1:AutoplayEnabled:Pass"
    }
    else{
        Write-Host "[!] Autoplay is Enabled."
        write-host "[!] WN10-CC-000185.ps1 Failed."
        Add-Content -Path '.\score.tmp' -Value "[!] WN10-CC-000185.ps1:AutoplayEnabled:Fail"

        if($scriptMode -eq "-enforce"){
            write-host "[%] WN10-CC-000185.ps1 enforcing STIG settings"
            write-host "[%] Disabling AutoPlay"
            New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name 'NoAutorun' -Value 1 -Force
        }
    }
}

write-host " "