#Group Title: WN10-00-000045

#Rule Title: The Windows 10 system must use an anti-virus program.

#Discussion: Malicious software can establish a base on individual desktops and servers. Employing an automated mechanism to detect this type of software will aid in elimination of the software from the operating system.

#Check Text: Verify an anti-virus solution is installed on the system. The anti-virus solution may be bundled with an approved host-based security solution.

#If there is no anti-virus solution installed on the system, this is a finding.

#Fix Text: Install an anti-virus solution on the system.

#======================================================
#CCI: CCI-000366: The organization implements the security configuration settings.
#NIST SP 800-53 :: CM-6 b
#NIST SP 800-53A :: CM-6.1 (iv)
#NIST SP 800-53 Revision 4 :: CM-6 b
#======================================================


#Get the mode from the script (enforce or audit)
$scriptMode=$args[0]
write-host "[*] WN10-00-000045.ps1 running in $scriptMode mode"

$isEnabled=$(Get-MPComputerStatus)
$isEnabled=$isEnabled.AntivirusEnabled

if($isEnabled -eq "True" ){
    write-host "[*] Anti-Virus Software is Enabled"
    write-host "[*] WN10-00-000045.ps1 Passes Sucessfully."
    Add-Content -Path '.\score.tmp' -Value "[*] WN10-00-000045.ps1:AntiVirus-Enabled:Pass"
}
else{
    write-host "[!] WN10-00-000045.ps1 Failed."
    Add-Content -Path '.\score.tmp' -Value "[!] WN10-00-000045.ps1:AntiVirus-Enabled:Fail"
    if($scriptMode -eq "-enforce"){
        write-host "[%] WN10-00-000045.ps1 enforcing STIG settings"
        $command="Start-Service WinDefend"
        write-host "[%] Re-Enabled Anti-Virus Protection via Windows Defender"
        write-host "[%] Enforcing command $command"
    }
}
Write-Host " "
