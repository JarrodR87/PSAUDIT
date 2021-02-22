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
            $ComputerSWInfo = Get-CimInstance -Class Win32Reg_AddRemovePrograms -ComputerName $Computer
            
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