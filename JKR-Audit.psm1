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
        [Parameter(Mandatory = $true)]$FilestoHash

    ) 
    BEGIN { 
        $Date = get-date -Format MM-dd-yyyy

        $ReportPath = $ReportPath.Trimend('\')
        $ReportPath = $ReportPath + '\'
        $ReportPath = $ReportPath + 'AuditReport' + $Date + '.html'

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


    } #BEGIN

    PROCESS {
        $UserList = Get-Localuser | Select-Object Name, Description, LastLogon, Enabled, PasswordExpires | ConvertTo-Html
        $GroupList = Get-LocalGroup | Select-Object Name, Description | ConvertTo-Html

        # 4624 - An account was successfully logged on - (TimeCreated - Username)
        $Event4624 = Get-AuditEventData -EventLog Security -EventID 4624 | Where-Object -FilterScript { ($_.User -ne 'SYSTEM') -and ($_.User -ne 'LOCAL SERVICE') -and ($_.User -ne 'NETWORK SERVICE') }
        If ($Event4624 -like '*No Events Located*') { $Event4624 = $Event4624 } Else { $Event4624 = $Event4624 | ConvertTo-Html }

        # 4720 - A user account was created
        $Event4720 = Get-AuditEventData -EventLog Security -EventID 4720
        If ($Event4720 -like '*No Events Located*') { $Event4720 = $Event4720 } Else { $Event4720 = $Event4720 | ConvertTo-Html }

        # 4722 - A user account was enabled
        $Event4722 = Get-AuditEventData -EventLog Security -EventID 4722
        If ($Event4722 -like '*No Events Located*') { $Event4722 = $Event4722 } Else { $Event4722 = $Event4722 | ConvertTo-Html }

        # 4725 - A user account was disabled
        $Event4725 = Get-AuditEventData -EventLog Security -EventID 4725
        If ($Event4725 -like '*No Events Located*') { $Event4725 = $Event4725 } Else { $Event4725 = $Event4725 | ConvertTo-Html }

        # 4726 - A user account was deleted
        $Event4726 = Get-AuditEventData -EventLog Security -EventID 4726
        If ($Event4726 -like '*No Events Located*') { $Event4726 = $Event4726 } Else { $Event4726 = $Event4726 | ConvertTo-Html }

        # 4738 - A user account was changed 
        $Event4738 = Get-AuditEventData -EventLog Security -EventID 4738
        If ($Event4738 -like '*No Events Located*') { $Event4738 = $Event4738 } Else { $Event4738 = $Event4738 | ConvertTo-Html }

        # 4740 - A user account was locked out
        $Event4740 = Get-AuditEventData -EventLog Security -EventID 4740
        If ($Event4740 -like '*No Events Located*') { $Event4740 = $Event4740 } Else { $Event4740 = $Event4740 | ConvertTo-Html }

        # 4767 - A user account was unlocked
        $Event4767 = Get-AuditEventData -EventLog Security -EventID 4767
        If ($Event4767 -like '*No Events Located*') { $Event4767 = $Event4767 } Else { $Event4767 = $Event4767 | ConvertTo-Html }

        # 4731 - A security-enabled local group was created
        $Event4731 = Get-AuditEventData -EventLog Security -EventID 4731
        If ($Event4731 -like '*No Events Located*') { $Event4731 = $Event4731 } Else { $Event4731 = $Event4731 | ConvertTo-Html }

        # 4732 - A member was added to a security-enabled local group
        $Event4732 = Get-AuditEventData -EventLog Security -EventID 4732
        If ($Event4732 -like '*No Events Located*') { $Event4732 = $Event4732 } Else { $Event4732 = $Event4732 | ConvertTo-Html }

        # 4733 - A member was removed from a security-enabled local group
        $Event4733 = Get-AuditEventData -EventLog Security -EventID 4733
        If ($Event4733 -like '*No Events Located*') { $Event4733 = $Event4733 } Else { $Event4733 = $Event4733 | ConvertTo-Html }

        # 4734 - A security-enabled local group was deleted
        $Event4734 = Get-AuditEventData -EventLog Security -EventID 4734
        If ($Event4734 -like '*No Events Located*') { $Event4734 = $Event4734 } Else { $Event4734 = $Event4734 | ConvertTo-Html }

        # 4735 - A security-enabled local group was changed
        $Event4735 = Get-AuditEventData -EventLog Security -EventID 4735
        If ($Event4735 -like '*No Events Located*') { $Event4735 = $Event4735 } Else { $Event4735 = $Event4735 | ConvertTo-Html }

        # 4608 - Windows is starting up
        $Event4608 = Get-AuditEventData -EventLog Security -EventID 4608
        If ($Event4608 -like '*No Events Located*') { $Event4608 = $Event4608 } Else { $Event4608 = $Event4608 | ConvertTo-Html }

        # 4616 - The system time was changed
        $Event4616 = Get-AuditEventData -EventLog Security -EventID 4616
        If ($Event4616 -like '*No Events Located*') { $Event4616 = $Event4616 } Else { $Event4616 = $Event4616 | ConvertTo-Html }

        # 4697 - A service was installed in the system
        $Event4697 = Get-AuditEventData -EventLog Security -EventID 4697 | Where-Object -FilterScript { ($_.'Servide Path' -notlike '*C:\Windows\system32\svchost.exe*') }
        If ($Event4697 -like '*No Events Located*') { $Event4697 = $Event4697 } Else { $Event4697 = $Event4697 | ConvertTo-Html }

        # 6416 - A new external device was recognized by the system
        $Event6416 = Get-AuditEventData -EventLog Security -EventID 6416 | Where-Object -FilterScript { ($_.'Class Name' -ne 'PrintQueue') -and ($_.'Class Name' -ne 'Keyboard') -and ($_.'Class Name' -ne 'Mouse') -and ($_.'Class Name' -ne 'HIDClass') }
        If ($Event6416 -like '*No Events Located*') { $Event6416 = $Event6416 } Else { $Event6416 = $Event6416 | ConvertTo-Html }

        # 6419 - A request was made to disable a device
        $Event6419 = Get-AuditEventData -EventLog Security -EventID 6419
        If ($Event6419 -like '*No Events Located*') { $Event6419 = $Event6419 } Else { $Event6419 = $Event6419 | ConvertTo-Html }

        # 6420 - A device was disabled
        $Event6420 = Get-AuditEventData -EventLog Security -EventID 6420
        If ($Event6420 -like '*No Events Located*') { $Event6420 = $Event6420 } Else { $Event6420 = $Event6420 | ConvertTo-Html }

        # 6421 - A request was made to enable a device
        $Event6421 = Get-AuditEventData -EventLog Security -EventID 6421
        If ($Event6421 -like '*No Events Located*') { $Event6421 = $Event6421 } Else { $Event6421 = $Event6421 | ConvertTo-Html }

        # 6422 - A device was enabled
        $Event6422 = Get-AuditEventData -EventLog Security -EventID 6422
        If ($Event6422 -like '*No Events Located*') { $Event6422 = $Event6422 } Else { $Event6422 = $Event6422 | ConvertTo-Html }

        # 4705 - A user right was removed
        $Event4705 = Get-AuditEventData -EventLog Security -EventID 4705
        If ($Event4705 -like '*No Events Located*') { $Event4705 = $Event4705 } Else { $Event4705 = $Event4705 | ConvertTo-Html }

        # 4719 - System audit policy was changed
        $Event4719 = Get-AuditEventData -EventLog Security -EventID 4719
        If ($Event4719 -like '*No Events Located*') { $Event4719 = $Event4719 } Else { $Event4719 = $Event4719 | ConvertTo-Html }

        # 4907 - Auditing settings on object were changed
        $Event4907 = Get-AuditEventData -EventLog Security -EventID 4907
        If ($Event4907 -like '*No Events Located*') { $Event4907 = $Event4907 } Else { $Event4907 = $Event4907 | ConvertTo-Html }

        # 4625 - An account failed to log on
        $Event4625 = Get-AuditEventData -EventLog Security -EventID 4625
        If ($Event4625 -like '*No Events Located*') { $Event4625 = $Event4625 } Else { $Event4625 = $Event4625 | ConvertTo-Html }

        # 4647 - User initiated logoff
        $Event4647 = Get-AuditEventData -EventLog Security -EventID 4647
        If ($Event4647 -like '*No Events Located*') { $Event4647 = $Event4647 } Else { $Event4647 = $Event4647 | ConvertTo-Html }

        # 4672 - Special privileges assigned to new logon
        $Event4672 = Get-AuditEventData -EventLog Security -EventID 4672 | Where-Object -FilterScript { ($_.'User Name' -ne 'SYSTEM') }
        If ($Event4672 -like '*No Events Located*') { $Event4672 = $Event4672 } Else { $Event4672 = $Event4672 | ConvertTo-Html }

        # 1102 - The audit log was cleared
        $Event1102 = Get-AuditEventData -EventLog Security -EventID 1102
        If ($Event1102 -like '*No Events Located*') { $Event1102 = $Event1102 } Else { $Event1102 = $Event1102 | ConvertTo-Html }

        # 4609 - Windows is shutting down
        $Event4609 = Get-AuditEventData -EventLog Security -EventID 4609
        If ($Event4609 -like '*No Events Located*') { $Event4609 = $Event4609 } Else { $Event4609 = $Event4609 | ConvertTo-Html }

        # 4715 - The audit policy (SACL) on an object was changed
        $Event4715 = Get-AuditEventData -EventLog Security -EventID 4715
        If ($Event4715 -like '*No Events Located*') { $Event4715 = $Event4715 } Else { $Event4715 = $Event4715 | ConvertTo-Html }


        # Combine Report
        $Head = $HtmlHead # New-HTMLHead
        $DateGenerated = '<h1>' + 'Generated at ' + (Get-Date) + '<h1>'
        $UserHeading = '<h2>Local User List</h2>'
        $GroupHeading = '<h2>Local Group List</h2>'
        $HashHeading = '<h2>File Hashes</h2>'
        $4624Heading = '<h2>4624 - An account was successfully logged on</h2>'
        $4720Heading = '<h2>4720 - A user account was created</h2>'
        $4722Heading = '<h2>4722 - A user account was enabled</h2>'
        $4725Heading = '<h2>4725 - A user account was disabled</h2>'
        $4726Heading = '<h2>4726 - A user account was deleted</h2>'
        $4738Heading = '<h2>4738 - A user account was changed</h2>'
        $4740Heading = '<h2>4740 - A user account was locked out</h2>'
        $4767Heading = '<h2>4767 - A user account was unlocked</h2>'
        $4731Heading = '<h2>4731 - A security-enabled local group was created</h2>'
        $4732Heading = '<h2>4732 - A member was added to a security-enabled local group</h2>'
        $4733Heading = '<h2>4733 - A member was removed from a security-enabled local group</h2>'
        $4734Heading = '<h2>4734 - A security-enabled local group was deleted</h2>'
        $4735Heading = '<h2>4735 - A security-enabled local group was changed</h2>'
        $4608Heading = '<h2>4608 - Windows is starting up</h2>'
        $4616Heading = '<h2>4616 - The system time was changed</h2>'
        $4697Heading = '<h2>4697 - A service was installed in the system</h2>'
        $6416Heading = '<h2>6416 - A new external device was recognized by the system</h2>'
        $6419Heading = '<h2>6419 - A request was made to disable a device</h2>'
        $6420Heading = '<h2>6420 - A device was disabled</h2>'
        $6421Heading = '<h2>6421 - A request was made to enable a device</h2>'
        $6422Heading = '<h2>6422 - A device was enabled</h2>'
        $4705Heading = '<h2>4705 - A user right was removed</h2>'
        $4719Heading = '<h2>4719 - System audit policy was changed</h2>'
        $4907Heading = '<h2>4907 - Auditing settings on object were changed</h2>'
        $4625Heading = '<h2>4625 - An account failed to log on</h2>'
        $4647Heading = '<h2>4647 - User initiated logoff</h2>'
        $4672Heading = '<h2>4672 - Special privileges assigned to new logon</h2>'
        $1102Heading = '<h2>1102 - The audit log was cleared</h2>'
        $4609Heading = '<h2>4609 - Windows is shutting down</h2>'
        $4715Heading = '<h2>4715 - The audit policy (SACL) on an object was changed</h2>'


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
        $FileHashes = $FileHashes | ConvertTo-Html

    } #PROCESS

    END { 
        ($Head + `
                $DateGenerated `
                + $HashHeading `
                + $FileHashes `
                + $UserHeading `
                + $UserList `
                + $GroupHeading `
                + $GroupList `
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
        ) > $ReportPath
    } #END

} #FUNCTION