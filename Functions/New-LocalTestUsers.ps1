function New-LocalTestUsers {
    <#
        .SYNOPSIS
            Creates a specified number of local test user accounts.

        .DESCRIPTION
            Creates test users named TEST01, TEST02, ..., up to the specified count.
            Optionally adds them to the local Administrators group.

        .PARAMETER TestAccounts
            Number of test accounts to create. Defaults to 1.

        .PARAMETER AsAdmin
            If provided, adds each test user to the local Administrators group.

        .EXAMPLE
            New-LocalTestUsers -TestAccounts 5

        .EXAMPLE
            New-LocalTestUsers -TestAccounts 3 -AsAdmin
    #>
    [CmdletBinding()]
    param(
        [int]$TestAccounts = 1,
        [switch]$AsAdmin
    )

    begin {
        $Password = ConvertTo-SecureString "TEST" -AsPlainText -Force
        $TotalAccounts = 1..$TestAccounts | ForEach-Object { $_.ToString("00") }
    }

    process {
        foreach ($Account in $TotalAccounts) {
            $Username = "TEST$Account"

            try {
                New-LocalUser -Name $Username -Password $Password -AccountNeverExpires -ErrorAction Stop
                Write-Host "Created user: $Username" -ForegroundColor Green

                if ($AsAdmin) {
                    Add-LocalGroupMember -Group "Administrators" -Member $Username -ErrorAction Stop
                    Write-Host "→ Added $Username to Administrators group" -ForegroundColor Red
                }
            }
            catch {
                Write-Warning "Failed to create ${Username}: $($_.Exception.Message)"
            }
        }
    }
}
