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