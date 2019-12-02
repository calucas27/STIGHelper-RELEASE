#Rule Title: Structured Exception Handling Overwrite Protection (SEHOP) must be enabled.

#Discussion: Attackers are constantly looking for vulnerabilities in systems and applications. Structured Exception Handling Overwrite Protection (SEHOP) blocks exploits that use the Structured Exception Handling overwrite technique, a common buffer overflow attack.

#Check Text: This is applicable to Windows 10 prior to v1709.

#Verify SEHOP is turned on.

#If the following registry value does not exist or is not configured as specified, this is a finding.

#Registry Hive: HKEY_LOCAL_MACHINE
#Registry Path: \SYSTEM\CurrentControlSet\Control\Session Manager\kernel\

#Value Name: DisableExceptionChainValidation

#Value Type: REG_DWORD
#Value: 0x00000000 (0)

#Fix Text: Configure the policy value for Computer Configuration >> Administrative Templates >> MS Security Guide >> "Enable Structured Exception Handling Overwrite Protection (SEHOP)" to "Enabled".

#This policy setting requires the installation of the SecGuide custom templates included with the STIG package. "SecGuide.admx" and "SecGuide.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.

#======================================================
#CCI: CCI-002824: The information system implements organization-defined security safeguards to protect its memory from unauthorized code execution.
#NIST SP 800-53 Revision 4 :: SI-16
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