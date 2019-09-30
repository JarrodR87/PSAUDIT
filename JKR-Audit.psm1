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