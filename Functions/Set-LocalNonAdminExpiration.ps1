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