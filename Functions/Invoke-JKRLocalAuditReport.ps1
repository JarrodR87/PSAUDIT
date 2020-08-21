function Invoke-JKRLocalAuditReport {
    <#
        .SYNOPSIS
            Creates a Local Audit Report
        .DESCRIPTION
            Creates a Local Audit Report at the location specified, and also hashes any Files passed to the Function as part of the report
        .PARAMETER ReportPath
            Path to save the report to excluding Filename as it will be automatically named
        .PARAMETER FilestoHash
            Comma Separated list of files to Hash during report generation
        .EXAMPLE
            Invoke-JKRLocalAuditReport -ReportPath 'C:\AuditReports\' -FilestoHash "FILE1", "FILE2"
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]$ReportPath,    
        [Parameter(Mandatory = $true)]$FilestoHash,
        [Parameter()]$Days

    ) 
    BEGIN { 
        $Date = Get-Date -Format MM-dd-yyyy

        $ReportPath = $ReportPath.Trimend('\')
        $ReportPath = $ReportPath + '\'
        $ReportPath = $ReportPath + 'AuditReport' + $Date + '.html'


        if ($NULL -eq $Days) {
            $Days = '14'
        }
        else {
            $Days = $Days
        }

        $StartDate = Get-Date ((Get-Date).AddDays(-$Days)) -Format MM-dd-yyyy


        # HTML Formatting - Will use JKR-MISC in the future with New-HTMLHead
        $HtmlHead = '<style>
    body {
        background-color: white;
        font-family:      "Calibri";
    }

    table {
        border-width:     1px;
        border-style:     solid;
        border-color:     black;
        border-collapse:  collapse;
        width:            100%;
    }

    th {
        border-width:     1px;
        padding:          5px;
        border-style:     solid;
        border-color:     black;
        background-color: #98C6F3;
    }

    td {
        border-width:     1px;
        padding:          5px;
        border-style:     solid;
        border-color:     black;
        background-color: White;
    }

    tr {
        text-align:       left;
    }
</style>'

        $ErrorActionPreference = 'silentlycontinue'

    } #BEGIN

    PROCESS {
        #Local Users
        $UserList = Get-Localuser
        
        $LocalUserInfo = @()

        foreach ($LocalUser in $UserList) {
            $UserSID = $Localuser.SID.Value
            $ProfilePath = (Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\ProfileList' | Where-object -FilterScript { $_.pspath -like "*$UserSID*" }).GetValue('ProfileImagePath')

            if ($NULL -eq $ProfilePath) {
                $ProfilePath = 'NOPROFILE'
            }

            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "Name" -Value $Localuser.Name
            $Row | Add-Member -MemberType noteproperty -Name "Description" -Value $Localuser.Description
            $Row | Add-Member -MemberType noteproperty -Name "LastLogon" -Value $Localuser.LastLogon
            $Row | Add-Member -MemberType noteproperty -Name "Enabled" -Value $Localuser.Enabled
            $Row | Add-Member -MemberType noteproperty -Name "PasswordExpires" -Value $Localuser.PasswordExpires
            $Row | Add-Member -MemberType noteproperty -Name "ProfilePath" -Value $ProfilePath
    
            $LocalUserInfo += $Row

            $ProfilePath = $NULL
        }

        $LocalUserInfo = $LocalUserInfo | Sort-Object -Property LastLogon -Descending | ConvertTo-Html -Fragment


        #Local Groups
        $GroupList = Get-LocalGroup
        
        $LocalGroupInfo = @()

        foreach ($LocalGroup in $GroupList) {
            $Members = Get-localgroupmember $LocalGroup

            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "Name" -Value $LocalGroup.Name
            $Row | Add-Member -MemberType noteproperty -Name "Description" -Value $LocalGroup.Description
            $Row | Add-Member -MemberType noteproperty -Name "Members" -Value ($Members.Name -join ',' | out-string)
            $LocalGroupInfo += $Row

            $Members = $Null
        }
        $LocalGroupInfo = $LocalGroupInfo | ConvertTo-Html -Fragment

        # Local Volumes
        $LocalVolumes = Get-Volume
        $LocalVolumeInfo = @()

        foreach ($LocalVolume in $LocalVolumes) {
            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "UniqueID" -Value $LocalVolume.UniqueID
            $Row | Add-Member -MemberType noteproperty -Name "DriveLetter" -Value $LocalVolume.DriveLetter
            $Row | Add-Member -MemberType noteproperty -Name "DriveType" -Value $LocalVolume.DriveType
            $Row | Add-Member -MemberType noteproperty -Name "FileSystem" -Value $LocalVolume.FileSystem
            $Row | Add-Member -MemberType noteproperty -Name "FileSystemLabel" -Value $LocalVolume.FileSystemLabel
            $Row | Add-Member -MemberType noteproperty -Name "HealthStatus" -Value $LocalVolume.HealthStatus
            $Row | Add-Member -MemberType noteproperty -Name "FriendlyName" -Value $LocalVolume.FriendlyName
            $Row | Add-Member -MemberType noteproperty -Name "Size in GB" -Value ($LocalVolume.Size / 1GB)
            $Row | Add-Member -MemberType noteproperty -Name "SizeRemaining in GB" -Value ($LocalVolume.SizeRemaining / 1GB)
            $LocalVolumeInfo += $Row
        }
        $LocalVolumeInfo = $LocalVolumeInfo | ConvertTo-Html -Fragment

        #LocalDisks
        $LocalDisks = Get-Disk

        $LocalDiskInfo = @()

        foreach ($LocalDisk in $LocalDisks) {
            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "Model" -Value $LocalDisk.Model
            $Row | Add-Member -MemberType noteproperty -Name "Manufacturer" -Value $LocalDisk.Manufacturer
            $Row | Add-Member -MemberType noteproperty -Name "SerialNumber" -Value $LocalDisk.SerialNumber
            $Row | Add-Member -MemberType noteproperty -Name "Size in GB" -Value ($LocalDisk.Size / 1GB)
            $Row | Add-Member -MemberType noteproperty -Name "PartitionStyle" -Value ($LocalDisk.PartitionStyle)

            $LocalDiskInfo += $Row
        }
        $LocalDiskInfo = $LocalDiskInfo | ConvertTo-Html -Fragment

        # OfficeScan DAT Info
        $OfficeScanDATs = Get-ChildItem -Path "${env:ProgramFiles(x86)}\Trend Micro\OfficeScan Client" | Where-Object -FilterScript { $_.Name -Like '*icrc$oth*' } | Select-Object Name, LastWriteTime | ConvertTo-Html -Fragment


        # Software
        $SoftwareInfo = (Get-ComputerSWInfo).ComputerSWInfo | Select-Object DisplayName, InstallDate, Publisher, Version | Sort-Object -Property InstallDate -Descending
        $SoftwareInfo = $SoftwareInfo | ConvertTo-Html -Fragment

        # 4624 - An account was successfully logged on - (TimeCreated - Username)
        $Event4624 = Get-AuditEventData -EventLog Security -EventID 4624 -Days $Days | Where-Object -FilterScript { ($_.User -ne 'SYSTEM') -and ($_.User -ne 'LOCAL SERVICE') -and ($_.User -ne 'NETWORK SERVICE') }
        If ($Event4624 -like '*No Events Located*') { $Event4624 = $Event4624 } Else { $Event4624 = $Event4624 | ConvertTo-Html -Fragment }

        # 4720 - A user account was created
        $Event4720 = Get-AuditEventData -EventLog Security -EventID 4720 -Days $Days 
        If ($Event4720 -like '*No Events Located*') { $Event4720 = $Event4720 } Else { $Event4720 = $Event4720 | ConvertTo-Html -Fragment }

        # 4722 - A user account was enabled
        $Event4722 = Get-AuditEventData -EventLog Security -EventID 4722 -Days $Days 
        If ($Event4722 -like '*No Events Located*') { $Event4722 = $Event4722 } Else { $Event4722 = $Event4722 | ConvertTo-Html -Fragment }

        # 4725 - A user account was disabled
        $Event4725 = Get-AuditEventData -EventLog Security -EventID 4725 -Days $Days 
        If ($Event4725 -like '*No Events Located*') { $Event4725 = $Event4725 } Else { $Event4725 = $Event4725 | ConvertTo-Html -Fragment }

        # 4726 - A user account was deleted
        $Event4726 = Get-AuditEventData -EventLog Security -EventID 4726 -Days $Days 
        If ($Event4726 -like '*No Events Located*') { $Event4726 = $Event4726 } Else { $Event4726 = $Event4726 | ConvertTo-Html -Fragment }

        # 4738 - A user account was changed 
        $Event4738 = Get-AuditEventData -EventLog Security -EventID 4738 -Days $Days 
        If ($Event4738 -like '*No Events Located*') { $Event4738 = $Event4738 } Else { $Event4738 = $Event4738 | ConvertTo-Html -Fragment }

        # 4740 - A user account was locked out
        $Event4740 = Get-AuditEventData -EventLog Security -EventID 4740 -Days $Days 
        If ($Event4740 -like '*No Events Located*') { $Event4740 = $Event4740 } Else { $Event4740 = $Event4740 | ConvertTo-Html -Fragment }

        # 4767 - A user account was unlocked
        $Event4767 = Get-AuditEventData -EventLog Security -EventID 4767 -Days $Days 
        If ($Event4767 -like '*No Events Located*') { $Event4767 = $Event4767 } Else { $Event4767 = $Event4767 | ConvertTo-Html -Fragment }

        # 4731 - A security-enabled local group was created
        $Event4731 = Get-AuditEventData -EventLog Security -EventID 4731 -Days $Days 
        If ($Event4731 -like '*No Events Located*') { $Event4731 = $Event4731 } Else { $Event4731 = $Event4731 | ConvertTo-Html -Fragment }

        # 4732 - A member was added to a security-enabled local group
        $Event4732 = Get-AuditEventData -EventLog Security -EventID 4732 -Days $Days 
        If ($Event4732 -like '*No Events Located*') { $Event4732 = $Event4732 } Else { $Event4732 = $Event4732 | ConvertTo-Html -Fragment }

        # 4733 - A member was removed from a security-enabled local group
        $Event4733 = Get-AuditEventData -EventLog Security -EventID 4733 -Days $Days 
        If ($Event4733 -like '*No Events Located*') { $Event4733 = $Event4733 } Else { $Event4733 = $Event4733 | ConvertTo-Html -Fragment }

        # 4734 - A security-enabled local group was deleted
        $Event4734 = Get-AuditEventData -EventLog Security -EventID 4734 -Days $Days 
        If ($Event4734 -like '*No Events Located*') { $Event4734 = $Event4734 } Else { $Event4734 = $Event4734 | ConvertTo-Html -Fragment }

        # 4735 - A security-enabled local group was changed
        $Event4735 = Get-AuditEventData -EventLog Security -EventID 4735 -Days $Days 
        If ($Event4735 -like '*No Events Located*') { $Event4735 = $Event4735 } Else { $Event4735 = $Event4735 | ConvertTo-Html -Fragment }

        # 4608 - Windows is starting up
        $Event4608 = Get-AuditEventData -EventLog Security -EventID 4608 -Days $Days 
        If ($Event4608 -like '*No Events Located*') { $Event4608 = $Event4608 } Else { $Event4608 = $Event4608 | ConvertTo-Html -Fragment }

        # 4616 - The system time was changed
        $Event4616 = Get-AuditEventData -EventLog Security -EventID 4616 -Days $Days 
        If ($Event4616 -like '*No Events Located*') { $Event4616 = $Event4616 } Else { $Event4616 = $Event4616 | ConvertTo-Html -Fragment }

        # 4697 - A service was installed in the system
        $Event4697 = Get-AuditEventData -EventLog Security -EventID 4697 -Days $Days | Where-Object -FilterScript { ($_.'Servide Path' -notlike '*C:\Windows\system32\svchost.exe*') }
        If ($Event4697 -like '*No Events Located*') { $Event4697 = $Event4697 } Else { $Event4697 = $Event4697 | ConvertTo-Html -Fragment }

        # 6416 - A new external device was recognized by the system
        $Event6416 = Get-AuditEventData -EventLog Security -EventID 6416 -Days $Days | Where-Object -FilterScript { ($_.'Class Name' -ne 'PrintQueue') -and ($_.'Class Name' -ne 'Keyboard') -and ($_.'Class Name' -ne 'Mouse') -and ($_.'Class Name' -ne 'HIDClass') }
        If ($Event6416 -like '*No Events Located*') { $Event6416 = $Event6416 } Else { $Event6416 = $Event6416 | ConvertTo-Html -Fragment }

        # 6419 - A request was made to disable a device
        $Event6419 = Get-AuditEventData -EventLog Security -EventID 6419 -Days $Days 
        If ($Event6419 -like '*No Events Located*') { $Event6419 = $Event6419 } Else { $Event6419 = $Event6419 | ConvertTo-Html -Fragment }

        # 6420 - A device was disabled
        $Event6420 = Get-AuditEventData -EventLog Security -EventID 6420 -Days $Days 
        If ($Event6420 -like '*No Events Located*') { $Event6420 = $Event6420 } Else { $Event6420 = $Event6420 | ConvertTo-Html -Fragment }

        # 6421 - A request was made to enable a device
        $Event6421 = Get-AuditEventData -EventLog Security -EventID 6421 -Days $Days 
        If ($Event6421 -like '*No Events Located*') { $Event6421 = $Event6421 } Else { $Event6421 = $Event6421 | ConvertTo-Html -Fragment }

        # 6422 - A device was enabled
        $Event6422 = Get-AuditEventData -EventLog Security -EventID 6422 -Days $Days 
        If ($Event6422 -like '*No Events Located*') { $Event6422 = $Event6422 } Else { $Event6422 = $Event6422 | ConvertTo-Html -Fragment }

        # 4705 - A user right was removed
        $Event4705 = Get-AuditEventData -EventLog Security -EventID 4705 -Days $Days 
        If ($Event4705 -like '*No Events Located*') { $Event4705 = $Event4705 } Else { $Event4705 = $Event4705 | ConvertTo-Html -Fragment }

        # 4719 - System audit policy was changed
        $Event4719 = Get-AuditEventData -EventLog Security -EventID 4719 -Days $Days 
        If ($Event4719 -like '*No Events Located*') { $Event4719 = $Event4719 } Else { $Event4719 = $Event4719 | ConvertTo-Html -Fragment }

        # 4907 - Auditing settings on object were changed
        $Event4907 = Get-AuditEventData -EventLog Security -EventID 4907 -Days $Days 
        If ($Event4907 -like '*No Events Located*') { $Event4907 = $Event4907 } Else { $Event4907 = $Event4907 | ConvertTo-Html -Fragment }

        # 4625 - An account failed to log on
        $Event4625 = Get-AuditEventData -EventLog Security -EventID 4625 -Days $Days 
        If ($Event4625 -like '*No Events Located*') { $Event4625 = $Event4625 } Else { $Event4625 = $Event4625 | ConvertTo-Html -Fragment }

        # 4647 - User initiated logoff
        $Event4647 = Get-AuditEventData -EventLog Security -EventID 4647 -Days $Days 
        If ($Event4647 -like '*No Events Located*') { $Event4647 = $Event4647 } Else { $Event4647 = $Event4647 | ConvertTo-Html -Fragment }

        # 4672 - Special privileges assigned to new logon
        $Event4672 = Get-AuditEventData -EventLog Security -EventID 4672 -Days $Days | Where-Object -FilterScript { ($_.'User Name' -ne 'SYSTEM') }
        If ($Event4672 -like '*No Events Located*') { $Event4672 = $Event4672 } Else { $Event4672 = $Event4672 | ConvertTo-Html -Fragment }

        # 1102 - The audit log was cleared
        $Event1102 = Get-AuditEventData -EventLog Security -EventID 1102 -Days $Days 
        If ($Event1102 -like '*No Events Located*') { $Event1102 = $Event1102 } Else { $Event1102 = $Event1102 | ConvertTo-Html -Fragment }

        # 4609 - Windows is shutting down
        $Event4609 = Get-AuditEventData -EventLog Security -EventID 4609 -Days $Days 
        If ($Event4609 -like '*No Events Located*') { $Event4609 = $Event4609 } Else { $Event4609 = $Event4609 | ConvertTo-Html -Fragment }

        # 4715 - The audit policy (SACL) on an object was changed
        $Event4715 = Get-AuditEventData -EventLog Security -EventID 4715 -Days $Days 
        If ($Event4715 -like '*No Events Located*') { $Event4715 = $Event4715 } Else { $Event4715 = $Event4715 | ConvertTo-Html -Fragment }

        # 4724 - A password was reset by another account
        $Event4724 = Get-AuditEventData -EventLog Security -EventID 4724 -Days $Days 
        If ($Event4724 -like '*No Events Located*') { $Event4724 = $Event4724 } Else { $Event4724 = $Event4724 | ConvertTo-Html -Fragment }

        # 4634 - Successful logout
        $Event4634 = Get-AuditEventData -EventLog Security -EventID 4634 -Days $Days 
        If ($Event4634 -like '*No Events Located*') { $Event4634 = $Event4634 } Else { $Event4634 = $Event4634 | ConvertTo-Html -Fragment }

        # File Ownership Changes
        $FileOwnershipChanges = Get-WinEvent -FilterHashtable @{LogName = "Security"; ID = 4674 ; StartTime = ((Get-Date).AddDays(-$Days)) ; EndTIme = ((Get-Date).AddDays(1)) } | Where-Object -FilterScript { $_.Message -like "*.evtx*" -and $_.Message -like "*WRITE_OWNER*" } | ConvertTo-Html -Fragment

        # Combine Report
        $Head = $HtmlHead # New-HTMLHead
        $DateGenerated = '<h1>' + 'Generated at ' + (Get-Date) + ' By ' + $env:UserName + ' on ' + $env:ComputerName + ' From ' + $StartDate + '<h1>'
        $UserHeading = '<h2>Local User List</h2>'
        $GroupHeading = '<h2>Local Group List</h2>'
        $HashHeading = '<h2>File Hashes</h2>'
        $4624Heading = '<h2>4624 - An account was successfully logged on</h2>'
        $4720Heading = '<h2>4720 - A User Account was Created</h2>'
        $4722Heading = '<h2>4722 - A user account was enabled</h2>'
        $4725Heading = '<h2>4725 - A user account was disabled</h2>'
        $4726Heading = '<h2>4726 - A user account was deleted</h2>'
        $4738Heading = '<h2>4738 - A user account was changed</h2>'
        $4740Heading = '<h2>4740 - A user account was locked out</h2>'
        $4767Heading = '<h2>4767 - A user account was unlocked</h2>'
        $4731Heading = '<h2>4731 - A security-enabled local group was created</h2>'
        $4732Heading = '<h2>4732 - A member was added to a security-enabled local group</h2>'
        $4733Heading = '<h2>4733 - A member was removed from a security-enabled local group</h2>'
        $4734Heading = '<h2>4734 - A security-enabled local group was deleted</h2>'
        $4735Heading = '<h2>4735 - A security-enabled local group was changed</h2>'
        $4608Heading = '<h2>4608 - Windows is starting up</h2>'
        $4616Heading = '<h2>4616 - The system time was changed</h2>'
        $4697Heading = '<h2>4697 - A service was installed in the system</h2>'
        $6416Heading = '<h2>6416 - A new external device was recognized by the system</h2>'
        $6419Heading = '<h2>6419 - A request was made to disable a device</h2>'
        $6420Heading = '<h2>6420 - A device was disabled</h2>'
        $6421Heading = '<h2>6421 - A request was made to enable a device</h2>'
        $6422Heading = '<h2>6422 - A device was enabled</h2>'
        $4705Heading = '<h2>4705 - A user right was removed</h2>'
        $4719Heading = '<h2>4719 - System audit policy was changed</h2>'
        $4907Heading = '<h2>4907 - Auditing settings on object were changed</h2>'
        $4625Heading = '<h2>4625 - An account failed to log on</h2>'
        $4647Heading = '<h2>4647 - User initiated logoff</h2>'
        $4672Heading = '<h2>4672 - Special privileges assigned to new logon</h2>'
        $1102Heading = '<h2>1102 - The Audit Log was Cleared</h2>'
        $4609Heading = '<h2>4609 - Windows is shutting down</h2>'
        $4715Heading = '<h2>4715 - The audit policy (SACL) on an object was changed</h2>'
        $4724Heading = '<h2>4724 - A password was reset by another account</h2>'
        $4634Heading = '<h2>4634 - Successful logout</h2>'
        $LocalVolumeHeading = '<h2>Local Volume List</h2>'
        $LocalDiskHeading = '<h2>Local Disk List</h2>'
        $OfficeScanHeading = '<h2>OfficeScan DATs</h2>'
        $SoftwareHeading = '<h2>Installed Software</h2>'
        $FileOwnershipChangesHeading = '<h2>Ownership Changed on Files</h2>'



        $FileHashes = @()

        foreach ($File in $FilestoHash) {
            $Hash = Get-FileHash -Path $File -Algorithm SHA256
            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "Path" -Value $Hash.Path
            $Row | Add-Member -MemberType noteproperty -Name "Hash" -Value $Hash.Hash
            $Row | Add-Member -MemberType noteproperty -Name "Algorithm" -Value $Hash.Algorithm
            $FileHashes += $Row
            $Hash = $Null
        }
        $FileHashes = $FileHashes | ConvertTo-Html -Fragment

    } #PROCESS

    END { 
        (
            $Head `
                + $DateGenerated `
                + $HashHeading `
                + $FileHashes `
                + $UserHeading `
                + $LocalUserInfo `
                + $GroupHeading `
                + $LocalGroupInfo `
                + $LocalDiskHeading `
                + $LocalDiskInfo `
                + $LocalVolumeHeading `
                + $LocalVolumeInfo `
                + $OfficeScanHeading `
                + $OfficeScanDATs `
                + $SoftwareHeading `
                + $SoftwareInfo `
                + $1102Heading `
                + $Event1102 `
                + $4624Heading `
                + $Event4624 `
                + $4625Heading `
                + $Event4625 `
                + $4720Heading `
                + $Event4720 `
                + $4722Heading `
                + $Event4722 `
                + $4725Heading `
                + $Event4725 `
                + $4726Heading `
                + $Event4726 `
                + $4738Heading `
                + $Event4738 `
                + $4740Heading `
                + $Event4740 `
                + $4767Heading `
                + $Event4767 `
                + $4731Heading `
                + $Event4731 `
                + $4732Heading `
                + $Event4732 `
                + $4733Heading `
                + $Event4733 `
                + $4734Heading `
                + $Event4734 `
                + $4735Heading `
                + $Event4735 `
                + $4608Heading `
                + $Event4608 `
                + $4616Heading `
                + $Event4616 `
                + $4697Heading `
                + $Event4697 `
                + $6416Heading `
                + $Event6416 `
                + $6419Heading `
                + $Event6419 `
                + $6420Heading `
                + $Event6420 `
                + $6421Heading `
                + $Event6421 `
                + $6422Heading `
                + $Event6422 `
                + $4705Heading `
                + $Event4705 `
                + $4719Heading `
                + $Event4719 `
                + $4907Heading `
                + $Event4907 `
                + $4647Heading `
                + $Event4647 `
                + $4672Heading `
                + $Event4672 `
                + $4609Heading `
                + $Event4609 `
                + $4715Heading `
                + $Event4715 `
                + $4724Heading `
                + $Event4724 `
                + $4634Heading `
                + $Event4634 `
                + $FileOwnershipChangesHeading `
                + $FileOwnershipChanges `
        ) > $ReportPath
    } #END

} #FUNCTION