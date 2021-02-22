function Get-AuditEventData {
    <#
        .SYNOPSIS
            Grabs specified Event from the Event log, and parses the data based on event ID
        .DESCRIPTION
            Pulls specified Events from the Specified Log and then outputs the information in a PowerShell Object
        .PARAMETER EventID
            ID of event to lookup in the specified Event Log
        .PARAMETER EventLog
            Event Log to lookup specified ID in
        .PARAMETER Days
            Number of Days in the past ot look at Events. Will default to 14 if no input is provided
        .PARAMETER FilePath
            Needed if EventLog is set to 'File'. It specifies the Path for the File
        .PARAMETER EndDate
            Needed if specifying a custom date Range
        .EXAMPLE
            Get-AuditEventData -EventLog Security -EventID 4624
        .EXAMPLE
            Get-AuditEventData -EventLog File -EventID 4624 -FilePath C:\Temp\Security.evtx
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)][string]$EventID,
        [Parameter(Mandatory = $true)][string]$EventLog,
        [Parameter()]$Days,
        [Parameter()]$FilePath,
        [Parameter()]$StartDate,
        [Parameter()]$EndDate
    ) 
    BEGIN { 
        if ($NULL -eq $Days) {
            $Days = '14'
        }
        else {
            $Days = $Days
        }

        if ($NULL -eq $StartDate) {
            $StartDate = (Get-Date).AddDays(-$Days)
        }
        else {
            $StartDate = $StartDate
        }

        if ($NULL -eq $EndDate) {
            $EndDate = (Get-Date).AddDays(1)
        }
        else {
            $EndDate = $EndDate
        }

        if ($EventLog -eq 'File') {
            $Events = Get-WinEvent -FilterHashtable @{PATH = $FilePath ; ID = $EventID ; StartTime = $StartDate ; EndTIme = $EndDate } -ErrorAction SilentlyContinue
        }
        else {
            $Events = Get-WinEvent -FilterHashtable @{Logname = $EventLog; ID = $EventID ; StartTime = $StartDate ; EndTIme = $EndDate } -ErrorAction SilentlyContinue
        }


        $AuditEventData = @()

    } #BEGIN

    PROCESS {
        # No Events
        if ($Null -eq $Events) { 
            $AuditEventData = "No Events Located for $EventID in the $EventLog Log"
        }
        Else {
            foreach ( $Event in $Events) {
                # 4624 - An account was successfully logged on
                If ($EventID -eq '4624' -and $Null -ne $Events) {
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "User" -Value $Event.Properties.value[5] 
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }
                # Windows 4720    A user account was created
                Elseif ($EventID -eq '4720' -and $Null -ne $Events) { 
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "User Created" -Value $Event.properties.Value[0]
                    $Row | Add-Member -MemberType noteproperty -Name "Created By" -Value $Event.properties.Value[4]
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }

                # Windows 4722    A user account was enabled
                Elseif ($EventID -eq '4722' -and $Null -ne $Events) { 
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "User Enabled" -Value $Event.properties.Value[0]
                    $Row | Add-Member -MemberType noteproperty -Name "Enabled By" -Value $Event.properties.Value[4]
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }

                # Windows 4725    A user account was disabled
                Elseif ($EventID -eq '4725' -and $Null -ne $Events) { 
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "User Disabled" -Value $Event.properties.Value[0]
                    $Row | Add-Member -MemberType noteproperty -Name "Disabled By" -Value $Event.properties.Value[4]
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }

                # Windows 4726    A user account was deleted
                Elseif ($EventID -eq '4726' -and $Null -ne $Events) { 
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "User Deleted" -Value $Event.properties.Value[0]
                    $Row | Add-Member -MemberType noteproperty -Name "Deleted By" -Value $Event.properties.Value[4]
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }

                # Windows 4738    A user account was changed
                Elseif ($EventID -eq '4738' -and $Null -ne $Events) { 
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "User Changed" -Value $Event.properties.Value[1]
                    $Row | Add-Member -MemberType noteproperty -Name "Changed By" -Value $Event.properties.Value[5]
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }

                # Windows 4740    A user account was locked out
                Elseif ($EventID -eq '4740' -and $Null -ne $Events) { 
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "User Locked" -Value $Event.properties.Value[0]
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }

                # Windows 4767    A user account was unlocked
                Elseif ($EventID -eq '4767' -and $Null -ne $Events) { 
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "User Unlocked" -Value $Event.properties.Value[0]
                    $Row | Add-Member -MemberType noteproperty -Name "Unlocked By" -Value $Event.properties.Value[4]
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }

                # Windows 4731    A security-enabled local group was created
                Elseif ($EventID -eq '4731' -and $Null -ne $Events) { 
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "Group Name" -Value $Event.properties.Value[0]
                    $Row | Add-Member -MemberType noteproperty -Name "Created By" -Value $Event.properties.Value[4]
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }

                # Windows 4732    A member was added to a security-enabled local group
                Elseif ($EventID -eq '4732' -and $Null -ne $Events) { 
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "Group Name" -Value $Event.properties.Value[2]
                    $Row | Add-Member -MemberType noteproperty -Name "Member" -Value (Get-Localuser | Where-Object -FilterScript { $_.SID -eq ($Event.properties.value[1]).value }).name
                    $Row | Add-Member -MemberType noteproperty -Name "Added By" -Value $Event.properties.Value[6]
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }

                # Windows 4733    A member was removed from a security-enabled local group
                Elseif ($EventID -eq '4733' -and $Null -ne $Events) { 
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "Group Name" -Value $Event.properties.Value[2]
                    $Row | Add-Member -MemberType noteproperty -Name "Member" -Value (Get-Localuser | Where-Object -FilterScript { $_.SID -eq ($Event.properties.value[1]).value }).name
                    $Row | Add-Member -MemberType noteproperty -Name "Removed By" -Value $Event.properties.Value[6]
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }

                # Windows 4734    A security-enabled local group was deleted
                Elseif ($EventID -eq '4734' -and $Null -ne $Events) { 
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "Group Name" -Value $Event.properties.Value[0]
                    $Row | Add-Member -MemberType noteproperty -Name "Deleted By" -Value $Event.Properties.Value[4]
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }

                # Windows 4735    A security-enabled local group was changed
                Elseif ($EventID -eq '4735' -and $Null -ne $Events) { 
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "Group Name" -Value $Event.properties.Value[0]
                    $Row | Add-Member -MemberType noteproperty -Name "Changed By" -Value $Event.Properties.Value[4]
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }

                # Windows 4608    Windows is starting up
                Elseif ($EventID -eq '4608' -and $Null -ne $Events) { 
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "Startup" -Value 'Startup'
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }

                # Windows 4616    The system time was changed
                Elseif ($EventID -eq '4616' -and $Null -ne $Events) { 
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "Changed By" -Value $Event.Properties.Value[1]
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }

                # Windows 4697    A service was installed in the system
                Elseif ($EventID -eq '4697' -and $Null -ne $Events) { 
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "Service Name" -Value $Event.Properties.Value[4]
                    $Row | Add-Member -MemberType noteproperty -Name "Service Path" -Value $Event.Properties.Value[5]
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }

                # Windows 6416    A new external device was recognized by the system
                Elseif ($EventID -eq '6416' -and $Null -ne $Events) { 
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "Device Name" -Value $Event.Properties.Value[5]
                    $Row | Add-Member -MemberType noteproperty -Name "Class Name" -Value $Event.Properties.Value[7]
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }

                # Windows 6419    A request was made to disable a device
                Elseif ($EventID -eq '6419' -and $Null -ne $Events) { 
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "Device Name" -Value $Event.Properties.Value[5]
                    $Row | Add-Member -MemberType noteproperty -Name "Disabled By" -Value $Event.Properties.Value[1]
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }

                # Windows 6420    A device was disabled
                Elseif ($EventID -eq '6420' -and $Null -ne $Events) { 
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "Device Name" -Value $Event.Properties.Value[5]
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }

                # Windows 6421    A request was made to enable a device
                Elseif ($EventID -eq '6421' -and $Null -ne $Events) { 
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "Device Name" -Value $Event.Properties.Value[5]
                    $Row | Add-Member -MemberType noteproperty -Name "Enabled By" -Value $Event.Properties.Value[1]
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }

                # Windows 6422    A device was enabled
                Elseif ($EventID -eq '6422' -and $Null -ne $Events) { 
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "Device Name" -Value $Event.Properties.Value[5]
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }

                # Windows 4673    A privileged service was called
                Elseif ($EventID -eq '4673' -and $Null -ne $Events) { 
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "Service" -Value $Event.Properties.Value[8]
                    $Row | Add-Member -MemberType noteproperty -Name "Called By" -Value $Event.Properties.Value[1]
                    $Row | Add-Member -MemberType noteproperty -Name "Priveleges" -Value $Event.Properties.Value[6]
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }

                # Windows 4674    An operation was attempted on a privileged object
                Elseif ($EventID -eq '4674' -and $Null -ne $Events) { 
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "Process Name" -Value $Event.Properties.Value[11]
                    $Row | Add-Member -MemberType noteproperty -Name "User" -Value $Event.Properties.Value[1]
                    $Row | Add-Member -MemberType noteproperty -Name "Priveleges" -Value $Event.Properties.Value[9]
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }

                # Windows 4670    Permissions on an object were changed
                Elseif ($EventID -eq '4670' -and $Null -ne $Events) { 
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "Process Name" -Value $Event.Properties.Value[11]
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }

                # Windows 4705    A user right was removed
                Elseif ($EventID -eq '4705' -and $Null -ne $Events) { 
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "Account SID" -Value ($Event.properties.value[4]).value
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }

                # Windows 4719    System audit policy was changed - When, Policy?
                Elseif ($EventID -eq '4719' -and $Null -ne $Events) { 
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "SubCategory GUID" -Value $Event.Properties.Value[6]
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }

                # Windows 4907    Auditing settings on object were changed
                Elseif ($EventID -eq '4907' -and $Null -ne $Events) { 
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "Changed By" -Value $Event.Properties.Value[1]
                    $Row | Add-Member -MemberType noteproperty -Name "Path" -Value $Event.Properties.Value[6]
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }

                # Windows 4625    An account failed to log on
                Elseif ($EventID -eq '4625' -and $Null -ne $Events) { 
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "User Name" -Value $Event.Properties.Value[5]
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }

                # Windows 4647    User initiated logoff
                Elseif ($EventID -eq '4647' -and $Null -ne $Events) { 
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "User Name" -Value $Event.Properties.Value[1]
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }

                # Windows 4672    Special privileges assigned to new logon
                Elseif ($EventID -eq '4672' -and $Null -ne $Events) { 
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "User Name" -Value $Event.Properties.Value[1]
                    $Row | Add-Member -MemberType noteproperty -Name "Priveleges" -Value $Event.Properties.Value[4]
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }
                # Windows 1102 - The audit log was cleared - When, Who
                Elseif ($EventID -eq '1102' -and $Null -ne $Events) { 
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "User Name" -Value $Event.Properties.Value[1]
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }
                
                # Windows 4609 - Windows is shutting down - When
                Elseif ($EventID -eq '4609' -and $Null -ne $Events) { 
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }
                # Windows 4715 - The audit policy (SACL) on an object was changed - When, Object, Who
                Elseif ($EventID -eq '4715' -and $Null -ne $Events) { 
                    #Need Event Data
                }
                # Windows 4724 - A password was reset by another account
                Elseif ($EventID -eq '4724' -and $Null -ne $Events) { 
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "User Reset" -Value $Event.Properties.Value[0]
                    $Row | Add-Member -MemberType noteproperty -Name "Reset By" -Value $Event.Properties.Value[4]
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }
                # Windows 4634 - Successful logout
                Elseif ($EventID -eq '4634' -and $Null -ne $Events) { 
                    $Row = New-Object PSObject
                    $Row | Add-Member -MemberType noteproperty -Name "User Name" -Value $Event.Properties.Value[1]
                    $Row | Add-Member -MemberType noteproperty -Name "Timecreated" -Value $Event.TimeCreated

                    $AuditEventData += $Row
                }
            }
               
        }
    } #PROCESS

    END { 
        $AuditEventData
    } #END

} #FUNCTION