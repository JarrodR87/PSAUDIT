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