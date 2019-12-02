#Rule Title: Local volumes must be formatted using NTFS.

#Discussion: The ability to set access permissions and auditing is critical to maintaining the security and proper access controls of a system. To support this, volumes must be formatted using the NTFS file system.

#Check Text: Run "Computer Management".
#Navigate to Storage >> Disk Management.

#If the "File System" column does not indicate "NTFS" for each volume assigned a drive letter, this is a finding.

#This does not apply to system partitions such the Recovery and EFI System Partition.

#Fix Text: Format all local volumes to use NTFS.

#======================================================
#Derived From:
#CCI: CCI-000213: The information system enforces approved authorizations for logical access to information and system resources in accordance with applicable access control policies.
#NIST SP 800-53 :: AC-3
#NIST SP 800-53A :: AC-3.1
#NIST SP 800-53 Revision 4 :: AC-3
#======================================================

#Get the mode from the script (enforce or audit)
$scriptMode=$args[0]
write-host "[*] WN10-00-000050.ps1 running in $scriptMode mode"

$getDriveType=$(Get-Volume -DriveLetter C)
$partitionType=$getDriveType.FileSystemType

if ($partitionType -eq 'NTFS') {
    Write-Host "[*] Main OS disk uses NTFS partitions."
    write-host "[*] WN10-00-000050.ps1 Passes Sucessfully."
    Add-Content -Path '.\score.tmp' -Value "[*] WN10-00-000050.ps1:NTFSPartitions:Pass"
}
elseif ($partitionType -ne 'NTFS') {
    Write-Host "[*] Main OS disk uses non-NTFS partitions."
    write-host "[*] WN10-00-000050.ps1 Failed."
    Add-Content -Path '.\score.tmp' -Value "[!] WN10-00-000050.ps1:NTFSPartitions:Fail"
}

#This script has no audit mode for right now, since enforcing would cause a reformat of the disk.

write-host " "