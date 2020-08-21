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