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