function Invoke-EventLogBackup {
    <#
        .SYNOPSIS
            Copies selected Event Log files to a specified location on local or remote machines.
        .DESCRIPTION
            Creates backups of Windows Event Logs (Application, System, Security) without clearing them.
            File names include timestamp for uniqueness. Supports local and remote backup via WMI/remoting.
        .PARAMETER Path
            Destination folder for log backups.
        .PARAMETER Logs
            Optional list of logs to back up (e.g. Application, System, Security). Defaults to all three.
        .PARAMETER ComputerName
            One or more computer names. Defaults to the local computer.
        .EXAMPLE
            Invoke-EventLogBackup -Path C:\Backups
        .EXAMPLE
            Invoke-EventLogBackup -Path C:\Backups -Logs Application,Security
        .EXAMPLE
            Invoke-EventLogBackup -Path C:\Backups -ComputerName PC01,PC02
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter()]
        [ValidateSet("Application", "System", "Security")]
        [string[]]$Logs = @("Application", "System", "Security"),

        [Parameter()]
        [string[]]$ComputerName = $env:COMPUTERNAME
    )

    begin {
        $Path = $Path.TrimEnd('\') + '\'
        $Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    }

    process {
        foreach ($Computer in $ComputerName) {
            Invoke-Command -ComputerName $Computer -ScriptBlock {
                param($RemotePath, $RemoteLogs, $RemoteTimestamp)

                $RemotePath = $RemotePath.TrimEnd('\') + '\'

                foreach ($Log in $RemoteLogs) {
                    try {
                        $WmiLog = Get-WmiObject Win32_NTEventlogFile -Filter "LogFileName = '$Log'"
                        if ($null -eq $WmiLog) {
                            Write-Warning "Log $Log not found or access denied."
                            continue
                        }

                        if (-not (Test-Path $RemotePath)) {
                            New-Item -ItemType Directory -Path $RemotePath -Force | Out-Null
                        }

                        $BackupFile = "$RemotePath$Log`_$RemoteTimestamp.evt"
                        $WmiLog.BackupEventlog($BackupFile)
                        Write-Verbose "Backed up $Log log to $BackupFile"
                    }
                    catch {
                        Write-Warning ("Failed to back up {0} log: {1}" -f $Log, $_)
                    }
                }

            } -ArgumentList $Path, $Logs, $Timestamp -ErrorAction Continue
        }
    }

    end {
        Write-Output "Event log backup completed to: $Path"
    }
}
