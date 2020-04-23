function Get-LocalNonAdmins {
    <#
        .SYNOPSIS
            Gets Local Accounts that are not a member of the Local Administrators Group
        .DESCRIPTION
            Checks for Local Users, and then checks the membership of the Local Administrators Group to see if the User is a member and then returns the users who are not.
        .EXAMPLE
            Get-LocalNonAdmins
    #>
    [CmdletBinding()]
    Param(
        
    ) 
    BEGIN { 
        $ComputerName = $ENV:COMPUTERNAME
        $ComputerNameReplace = $ComputerName + '\'
    } #BEGIN

    PROCESS {


        $LocalUsers = Get-LocalUser | Where-Object -FilterScript { $_.enabled -eq 'true' }
        $LocalAdministrators = (Get-LocalGroupMember -Group Administrators | Where-Object -FilterScript { $_.PrincipalSource -eq 'Local' }).name

        $LocalAdmins = foreach ($LocalAdministrator in $LocalAdministrators) {
            $LocalAdministrator.replace($ComputerNameReplace, '')
        }


        $NonAdmins = $LocalUsers | Where-Object -FilterScript { $LocalAdmins -notcontains $_.Name }

        $NonAdmins
    } #PROCESS

    END { 

    } #END

} #FUNCTION


function Set-LocalNonAdminExpiration {
    <#
        .SYNOPSIS
            Sets Local Non-Admin Accounts to Expire after a specified amount of time
        .DESCRIPTION
            Gets Local Non-Admin Users with no current Expiration Set, and then sets the Expiration to the date specified. Default is one year if not specified
        .PARAMETER Days
            Specified number of days in the future to expire the Account - Defaults to 365
        .EXAMPLE
            Set-LocalNonAdminExpiration
        .EXAMPLE
            Set-LocalNonAdminExpiration -Days 30
    #>
    [CmdletBinding()]
    Param(
        [Parameter()]$Days
    ) 
    BEGIN { 

        if ($NULL -eq $Days) {
            $Days = '365'
        }

        $Expires = (Get-Date).AddDays($Days)
    } #BEGIN

    PROCESS {
        $NonExpiringUsers = Get-LocalNonAdmins | Where-Object -FilterScript { $NULL -eq $_.AccountExpires }

        if ($Null -eq $NonExpiringUsers) {
            Write-Host 'No Local Users without Expiration Date'
        }

        else {
            foreach ($NonExpiringUser in $NonExpiringUsers) {
                Set-LocalUser $NonExpiringUser -AccountExpires $Expires

                Get-LocalUser $NonExpiringUser | Select-Object Name, AccountExpires
            }
        }
    } #PROCESS

    END { 

    } #END

} #FUNCTION


function New-LocalTestUsers {
    <#
        .SYNOPSIS
            Creates specified number of Test Users as Local Accounts 
        .DESCRIPTION
            Creates TEST01 - 0X where X is the number specified
        .PARAMETER TestAccounts
            Number of Test Accounts to create Defaults to 1 if none entered
        .EXAMPLE
            New-LocalTestUsers -TestAccounts 12
    #>
    [CmdletBinding()]
    Param(
        [Parameter()]$TestAccounts
    ) 
    BEGIN { 
        $Password = "TEST"
        $Password = $Password | ConvertTo-SecureString -AsPlainText -Force

        $TotalAccounts = @()

        1..$TestAccounts | ForEach-Object { $TotalAccounts += $_.ToString("00") }
    } #BEGIN

    PROCESS {
        foreach ($Account in $TotalAccounts) {
            $Username = 'TEST' + $Account
            New-LocalUser -Name $Username -Password $Password
        }
    } #PROCESS

    END { 

    } #END

} #FUNCTION


function Get-ComputerHWInfo {
    <#
        .SYNOPSIS
            Gets Physical Hardware Information from the specified PC/PC's
        .DESCRIPTION
            Gathers Hardware Information from the specified, or Local, PC/PC's and then returs the data as a nested Hash table
        .PARAMETER ComputerName
            Optional - Will use the local PC name if none specified
        .EXAMPLE
            Get-ComputerHWInfo
        .EXAMPLE
            Get-ComputerHWInfo -ComputerName TestPC01
        .EXAMPLE
            Get-ComputerHWInfo -ComputerName TestPC01,TESTPC02
    #>
    [CmdletBinding()]
    Param(
        [Parameter()]$ComputerName
    ) 
    BEGIN { 

        If ($NULL -eq $ComputerName) {
            $ComputerName = $ENV:COMPUTERNAME
        }

        $ComputerHWInventory = @()
    } #BEGIN

    PROCESS {

        foreach ($Computer in $ComputerName) {
            $ComputerInfo = Get-CimInstance -Class Win32_ComputerSystem -ComputerName $Computer
            $ProcessorInfo = Get-CimInstance -Class win32_processor -ComputerName $Computer
            $BIOSInfo = Get-CimInstance -Class Win32_Bios -ComputerName $Computer
            $SoundInfo = Get-CimInstance -Class Win32_SoundDevice -ComputerName $Computer
            $VideoInfo = Get-CimInstance -Class Win32_VideoController -ComputerName $Computer
            $PhysicalMediaInfo = Get-CimInstance -Class win32_physicalmedia -ComputerName $Computer
            $LogicalDiskInfo = Get-CimInstance -Class Win32_LogicalDisk -ComputerName $Computer

            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "Computername" -Value $Computer
            $Row | Add-Member -MemberType noteproperty -Name "ComputerInfo" -Value $ComputerInfo
            $Row | Add-Member -MemberType noteproperty -Name "BIOSInfo" -Value $BIOSInfo
            $Row | Add-Member -MemberType noteproperty -Name "LogicalDiskInfo" -Value $LogicalDiskInfo
            $Row | Add-Member -MemberType noteproperty -Name "ProcessorInfo" -Value $ProcessorInfo
            $Row | Add-Member -MemberType noteproperty -Name "SoundInfo" -Value $SoundInfo
            $Row | Add-Member -MemberType noteproperty -Name "VideoInfo" -Value $VideoInfo
            $Row | Add-Member -MemberType noteproperty -Name "PhysicalMediaInfo" -Value $PhysicalMediaInfo

            $ComputerHWInventory += $Row
        }

    } #PROCESS

    END { 
        $ComputerHWInventory
    } #END

} #FUNCTION


function Get-ComputerSWInfo {
    <#
        .SYNOPSIS
            Gets Software Information from the specified PC/PC's
        .DESCRIPTION
            Gathers Software Information from the specified, or Local, PC/PC's and then returs the data as a nested Hash table
        .PARAMETER ComputerName
            Optional - Will use the local PC name if none specified
        .EXAMPLE
            Get-ComputerSWInfo
        .EXAMPLE
            Get-ComputerSWInfo -ComputerName TestPC01
        .EXAMPLE
            Get-ComputerSWInfo -ComputerName TestPC01,TESTPC02
    #>
    [CmdletBinding()]
    Param(
        [Parameter()]$ComputerName
    ) 
    BEGIN { 

        If ($NULL -eq $ComputerName) {
            $ComputerName = $ENV:COMPUTERNAME
        }

        $ComputerSWInventory = @()

    } #BEGIN

    PROCESS {
        foreach ($Computer in $ComputerName) {
            $ComputerSWInfo = Get-CimInstance -Class Win32_Product -ComputerName $Computer | Select-Object Name, Vendor, Version
            
            $Row = New-Object PSObject
            $Row | Add-Member -MemberType noteproperty -Name "ComputerName" -Value $Computer
            $Row | Add-Member -MemberType noteproperty -Name "ComputerSWInfo" -Value $ComputerSWInfo

            $ComputerSWInventory += $Row
        }
    } #PROCESS

    END { 
        $ComputerSWInventory 
    } #END

} #FUNCTION


function Get-EventLogBackup {
    <#
        .SYNOPSIS
            Copies the Event Log Files to the specified location
        .DESCRIPTION
            Makes a copy of the Event Log, but does not clear the current contents
        .PARAMETER Path
            Path to location to save Logs. Folder path only is needed as it will name the items with a Date and Log Name.
        .EXAMPLE
            Get-EventLogBackup -Path C:\Temp\
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]$Path
    ) 
    BEGIN { 
        $Path = $Path.Trimend('\')
        $Path = $Path + '\'


        $ApplicationLog = Get-WmiObject Win32_NTEventlogFile -Filter "LogFileName = 'Application'"
        $SystemLog = Get-WmiObject Win32_NTEventlogFile -Filter "LogFileName = 'System'"
        $SecurityLog = Get-WmiObject Win32_NTEventlogFile -Filter "LogFileName = 'Security'"


        $Date = Get-Date -UFormat %m
        $Month = (Get-Culture).DateTimeFormat.GetMonthName($Date)
    } #BEGIN

    PROCESS {
        $ApplicationLog.BackupEventlog(($Path + '\' + 'Application_' + $Month + '.evt'))
        $SystemLog.BackupEventlog(($Path + '\' + 'System_' + $Month + '.evt'))
        if ($NULL -eq $SecurityLog) {
            Write-Host 'Insufficient Rights to Backup Security Log'
        }
        Else {
            $SecurityLog.BackupEventlog(($Path + 'Security_' + $Month + '.evt'))
        }        
    } #PROCESS

    END { 

    } #END

} #FUNCTION


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
        .EXAMPLE
            Get-AuditEventData -EventLog Security -EventID 4624
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)][string]$EventID,
        [Parameter(Mandatory = $true)][string]$EventLog,
        [Parameter()]$Days
    ) 
    BEGIN { 
        if ($NULL -eq $Days) {
            $Days = '14'
        }
        else {
            $Days = $Days
        }

        $Events = Get-WinEvent -FilterHashtable @{Logname = $EventLog; ID = $EventID ; StartTime = (Get-Date).AddDays(-$Days) } -ErrorAction SilentlyContinue
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
            }
               
        }
    } #PROCESS

    END { 
        $AuditEventData
    } #END

} #FUNCTION