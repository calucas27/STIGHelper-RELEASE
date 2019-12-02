#Group Title: WN10-00-000040

#Rule Title: Windows 10 systems must be maintained at a supported servicing level.

#Discussion: Windows 10 is maintained by Microsoft at servicing levels for specific periods of time to support Windows as a Service. Systems at unsupported servicing levels or releases will not receive security updates for new vulnerabilities which leaves them subject to exploitation.

#New versions with feature updates are planned to be released on a semi-annual basis with an estimated support timeframe of 18 to 30 months depending on the release. Support for previously released versions has been extended for Enterprise editions.

#A separate servicing branch intended for special purpose systems is the Long-Term Servicing Channel (LTSC, formerly Branch - LTSB) which will receive security updates for 10 years but excludes feature updates.

#Check Text: Run "winver.exe".

#If the "About Windows" dialog box does not display:

#"Microsoft Windows Version 1703 (OS Build 15063.0)"

#or greater, this is a finding.

#======================================================
#Derived From:
#CCI: CCI-000366: The organization implements the security configuration settings.
#NIST SP 800-53 :: CM-6 b
#NIST SP 800-53A :: CM-6.1 (iv)
#NIST SP 800-53 Revision 4 :: CM-6 b
#======================================================

#Get the mode from the script (enforce or audit)
$scriptMode=$args[0]
write-host "[*] WN10-00-000040.ps1 running in $scriptMode mode"

$osVersion=$(Get-WmiObject -Class Win32_OperatingSystem)
$osVersion=$osVersion.version
$p1,$p2,$p3=$osVersion | foreach-object split .

if([int]$p3 -ge 15063.0){
    Write-Host "[*] Windows Operating System (v. $osVersion) is up to date!"
    write-host "[*] WN10-00-000040.ps1 Passes Sucessfully."
    Add-Content -Path '.\score.tmp' -Value "[*] WN10-00-000040.ps1:WindowsUpdated:Pass" 
}
elseif ([int]$p3 -lt 15063.0) {
    write-host "[!] Windows Operating System (v. $osVersion) is not up to date!"
    write-host "[!] WN10-00-000040.ps1 Failed."
    Add-Content -Path '.\score.tmp' -Value "[!] WN10-00-000040.ps1:WindowsUpdated:Fail"
}

#This script has no enforce mode for right now, since patches may not always be available, or desired - depending on the organization's patch management.

write-host " "




