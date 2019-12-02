#Rule Title: Autoplay must be turned off for non-volume devices.

#Discussion: Allowing autoplay to execute may introduce malicious code to a system. Autoplay begins reading from a drive as soon as you insert media in the drive. As a result, the setup file of programs or music on audio media may start. This setting will disable autoplay for non-volume devices (such as Media Transfer Protocol (MTP) devices).

#Check Text: If the following registry value does not exist or is not configured as specified, this is a finding:

#Registry Hive: HKEY_LOCAL_MACHINE
#Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Explorer\

#Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name 'NoAutoplayfornonVolume' -Value 1

#Value Name: NoAutoplayfornonVolume

#Value Type: REG_DWORD
#Value: 1

#Fix Text: Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> AutoPlay Policies >> "Disallow Autoplay for non-volume devices" to "Enabled".

#======================================================
#Derived From:
#CCI: CCI-001764: The information system prevents program execution in accordance with organization-defined policies regarding software program usage and restrictions, and/or rules authorizing the terms and conditions of software program usage.
#NIST SP 800-53 Revision 4 :: CM-7 (2)
#======================================================

$scriptMode=$args[0]
write-host "[*] WN10-CC-000180.ps1 running in $scriptMode mode"

$pathExists=$(test-path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer')
if ($pathExists -eq $false) {
    write-host "[!] Registry Path not present."
    Write-Host "[!] Autoplay for non-volumes is Enabled."
    write-host "[!] WN10-CC-000180.ps1 Failed."
    Add-Content -Path '.\score.tmp' -Value "[!] WN10-CC-000180.ps1:AutoplayEnabledNonVolume:Fail"

    if($scriptMode -eq "-enforce"){
        write-host "[%] WN10-CC-000180.ps1 enforcing STIG settings"
        write-host "[%] Disabling AutoPlay for non-volume devices"
        New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name 'NoAutoplayfornonVolume' -Value 1 -Force
    }
}
elseif ($pathExists -eq $true) {
    $regKey=$(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name NoAutoplayfornonVolume)
    $regkey=$regKey.NoAutoplayfornonVolume

    if($regKey -eq 1 ){
        write-host "[*] HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume set"
        write-host "[*] WN10-CC-000180.ps1 Passes Sucessfully."
        Add-Content -Path '.\score.tmp' -Value "[*] WN10-CC-000180.ps1:AutoplayEnabledNonVolume:Pass"
    }
    else{
        Write-Host "[!] Autoplay for non-volumes is Enabled."
        write-host "[!] WN10-CC-000180.ps1 Failed."
        Add-Content -Path '.\score.tmp' -Value "[!] WN10-CC-000180.ps1:AutoplayEnabledNonVolume:Fail"

        if($scriptMode -eq "-enforce"){
            write-host "[%] WN10-CC-000180.ps1 enforcing STIG settings"
            write-host "[%] Disabling AutoPlay"
            New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name 'NoAutoplayfornonVolume' -Value 1 -Force
        }
    }
}

write-host " "