#Rule Title: Autoplay must be disabled for all drives.

#Discussion: Allowing autoplay to execute may introduce malicious code to a system. Autoplay begins reading from a drive as soon as you insert media in the drive. As a result, the setup file of programs or music on audio media may start. By default, autoplay is disabled on removable drives, such as the floppy disk drive (but not the CD-ROM drive) and on network drives. If you enable this policy, you can also disable autoplay on all drives.

#Check Text: If the following registry value does not exist or is not configured as specified, this is a finding:

#Registry Hive: HKEY_LOCAL_MACHINE
#Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\

#Value Name: NoDriveTypeAutoRun

#Value Type: REG_DWORD
#Value: 0x000000ff (255)

#Note: If the value for NoDriveTypeAutorun is entered manually, it must be entered as "ff" when Hexadecimal is selected, or "255" with Decimal selected. Using the policy value specified in the Fix section will enter it correctly.

#Fix Text: Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> AutoPlay Policies >> "Turn off AutoPlay" to "Enabled:All Drives".

#======================================================
#Derived From:
#CCI: CCI-001764: The information system prevents program execution in accordance with organization-defined policies regarding software program usage and restrictions, and/or rules authorizing the terms and conditions of software program usage.
#NIST SP 800-53 Revision 4 :: CM-7 (2)
#======================================================

$scriptMode=$args[0]
write-host "[*] WN10-CC-000190.ps1 running in $scriptMode mode"

$pathExists=$(test-path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer')
if ($pathExists -eq $false) {
    write-host "[!] Registry Path not present."
    Write-Host "[!] Autoplay is Enabled for all drives."
    write-host "[!] WN10-CC-000190.ps1 Failed."
    Add-Content -Path '.\score.tmp' -Value "[!] WN10-CC-000190.ps1:AutoplayEnabledAllDrives:Fail"

    if($scriptMode -eq "-enforce"){
        write-host "[%] WN10-CC-000190.ps1 enforcing STIG settings"
        write-host "[%] Disabling AutoPlay for all drives"
        New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name 'NoDriveTypeAutoRun' -Value 255 -Force
    }
}
elseif ($pathExists -eq $true) {
    $regKey=$(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name NoDriveTypeAutoRun)
    $regkey=$regKey.NoDriveTypeAutoRun

    if($regKey -eq 255 ){
        write-host "[*] HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoDriveTypeAutoRun set"
        write-host "[*] Autoplay is disabled for all drives."
        write-host "[*] WN10-CC-000190.ps1 Passes Sucessfully."
        Add-Content -Path '.\score.tmp' -Value "[*] WN10-CC-000190.ps1:AutoplayEnabledAllDrives:Pass"
    }
    else{
        Write-Host "[!] Autoplay for all drives is Enabled."
        write-host "[!] WN10-CC-000190.ps1 Failed."
        Add-Content -Path '.\score.tmp' -Value "[!] WN10-CC-000190.ps1:AutoplayEnabledAllDrives:Fail"

        if($scriptMode -eq "-enforce"){
            write-host "[%] WN10-CC-000190.ps1 enforcing STIG settings"
            write-host "[%] Disabling AutoPlay for all drives"
            New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name 'NoDriveTypeAutoRun' -Value 255 -Force
        }
    }
}
write-host " "