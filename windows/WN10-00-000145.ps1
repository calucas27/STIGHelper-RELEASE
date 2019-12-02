#Rule Title: Data Execution Prevention (DEP) must be configured to at least OptOut.

#Discussion: Attackers are constantly looking for vulnerabilities in systems and applications. Data Execution Prevention (DEP) prevents harmful code from running in protected memory locations reserved for Windows and other programs.

#Check Text: Verify the DEP configuration.
#Open a command prompt (cmd.exe) or PowerShell with elevated privileges (Run as administrator).
#Enter "BCDEdit /enum {current}". (If using PowerShell "{current}" must be enclosed in quotes.)
#If the value for "nx" is not "OptOut", this is a finding.
#(The more restrictive configuration of "AlwaysOn" would not be a finding.)

#Fix Text: Configure DEP to at least OptOut.

#Note: Suspend BitLocker before making changes to the DEP configuration.

#Open a command prompt (cmd.exe) or PowerShell with elevated privileges (Run as administrator).
#Enter "BCDEDIT /set {current} nx OptOut". (If using PowerShell "{current}" must be enclosed in quotes.)
#"AlwaysOn", a more restrictive selection, is also valid but does not allow applications that do not function properly to be opted out of DEP.

#Opted out exceptions can be configured in the "System Properties".

#Open "System" in Control Panel.
#Select "Advanced system settings".
#Click "Settings" in the "Performance" section.
#Select the "Data Execution Prevention" tab.
#Applications that are opted out are configured in the window below the selection "Turn on DEP for all programs and services except those I select:".

#======================================================
#Derived From:
#CCI: CCI-002824: The information system implements organization-defined security safeguards to protect its memory from unauthorized code execution.
#NIST SP 800-53 Revision 4 :: SI-16
#======================================================

$scriptMode=$args[0]
write-host "[*] WN10-00-000100.ps1 running in $scriptMode mode"

$depStatus=$(bcdedit /enum | Select-String "nx").ToString()
$depStatus=$depStatus -replace '(^\s+|\s+$)','' -replace '\s+',' '

if ($depStatus -eq 'nx OptOut') {
    Write-Host "[*] DEP Opt-In Disabled."
    Write-Host "[*] WN10-00-000145.ps1 Passes Successfully"
    Add-Content -Path '.\score.tmp' -Value "[*] WN10-00-000145.ps1:DEPOptIn:Pass"
}
elseif ($depStatus -eq 'nx AlwaysOn') {
    Write-Host "[*] DEP Opt-In Disabled."
    Write-Host "[*] WN10-00-000145.ps1 Passes Successfully"
    Add-Content -Path '.\score.tmp' -Value "[*] WN10-00-000145.ps1:DEPOptIn:Pass"
}
elseif ($depStatus -eq 'nx OptIn') {
    Write-Host "[!] DEP Opt-In Enabled."
    Write-Host "[!] WN10-00-000145.ps1 Failed."
    Add-Content -Path '.\score.tmp' -Value "[*] WN10-00-000145.ps1:DEPOptIn:Fail"

    if($scriptMode -eq "-enforce"){
        Write-Host "[%] WN-00-000145 enforcing STIG settings."
        Write-Host "[%] Disabled DEP Opt-In"
        $areYouSure = read-host -Prompt "[!] This WILL break your computer if BitLocker is enabled.  Are you sure BitLocker is disabled? (Y/N)"
        if ($areYouSure -eq "Y") {
            bcdedit /set '{current}' nx OptOut
        }
        elseif ($areYouSure -eq "N") {
            break
        }
        else{
            Write-Host "[!] Exiting"
            break
        }
    }
}
write-host " "