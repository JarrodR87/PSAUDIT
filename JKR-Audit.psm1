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


