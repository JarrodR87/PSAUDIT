function Invoke-LocalUserAudit {
    <#
        .SYNOPSIS
            Audits local user accounts with options to set or clear expiration, optionally including admin accounts.

        .DESCRIPTION
            Lists enabled local users and manages account expirations. By default, acts only on non-admins,
            but can include admins via the -IncludeAdmins flag.

        .PARAMETER SetExpiration
            If provided, sets expiration for accounts without one. Defaults to 365 days.

        .PARAMETER ClearExpiration
            If provided, clears expiration date from all target accounts.

        .PARAMETER Days
            Optional. Number of days in the future for expiration if -SetExpiration is used. Defaults to 365.

        .PARAMETER IncludeAdmins
            Optional. Includes local admin accounts in the output and modification scope.

        .EXAMPLE
            Invoke-LocalUserAudit

        .EXAMPLE
            Invoke-LocalUserAudit -SetExpiration -Days 30

        .EXAMPLE
            Invoke-LocalUserAudit -ClearExpiration -IncludeAdmins
    #>
    [CmdletBinding(DefaultParameterSetName = 'Audit')]
    param(
        [Parameter(ParameterSetName = 'Set')]
        [switch]$SetExpiration,

        [Parameter(ParameterSetName = 'Clear')]
        [switch]$ClearExpiration,

        [Parameter(ParameterSetName = 'Set')]
        [int]$Days = 365,

        [Parameter()]
        [switch]$IncludeAdmins
    )

    begin {
        $ComputerName = $env:COMPUTERNAME
        $ComputerPrefix = "$ComputerName\"
        $localUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true }

        $adminGroupMembers = Get-LocalGroupMember -Group Administrators | Where-Object { $_.PrincipalSource -eq 'Local' }
        $localAdmins = $adminGroupMembers.Name | ForEach-Object { $_ -replace [regex]::Escape($ComputerPrefix), '' }

        if ($IncludeAdmins) {
            $targetUsers = $localUsers
        }
        else {
            $targetUsers = $localUsers | Where-Object { $localAdmins -notcontains $_.Name }
        }
    }

    process {
        if ($targetUsers.Count -eq 0) {
            Write-Output "No matching local users found."
            return
        }

        if ($ClearExpiration) {
            foreach ($user in $targetUsers) {
                Set-LocalUser -Name $user.Name -AccountExpires ([datetime]::MaxValue)
                Write-Output ([PSCustomObject]@{
                        User           = $user.Name
                        Action         = "Expiration Cleared"
                        AccountExpires = $null
                    })
            }
        }
        elseif ($SetExpiration) {
            $expireDate = (Get-Date).AddDays($Days)
            $usersWithoutExpiration = $targetUsers | Where-Object { $_.AccountExpires -eq $null }

            if ($usersWithoutExpiration.Count -eq 0) {
                Write-Output "No users without expiration date."
                return
            }

            foreach ($user in $usersWithoutExpiration) {
                Set-LocalUser -Name $user.Name -AccountExpires $expireDate
                Write-Output ([PSCustomObject]@{
                        User           = $user.Name
                        Action         = "Expiration Set"
                        AccountExpires = $expireDate
                    })
            }
        }
        else {
            $targetUsers | Select-Object Name, AccountExpires
        }
    }
}
