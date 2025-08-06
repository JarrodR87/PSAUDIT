function Get-AuditEventData {
    <#
         .SYNOPSIS
             Retrieves and parses specific audit events from the event log or an exported .evtx file.
         .DESCRIPTION
             Queries events based on Event ID and source (log name or file), returning structured audit information for well-known security event types.
         .PARAMETER EventID
             The event ID to filter on (e.g., 4624).
         .PARAMETER EventLog
             The event log name (e.g., Security), or 'File' to specify an .evtx file.
         .PARAMETER Days
             Optional. How many days back to search. Defaults to 14.
         .PARAMETER FilePath
             Path to the .evtx file if EventLog is 'File'.
         .PARAMETER StartDate
             Optional custom start date. Overrides -Days.
         .PARAMETER EndDate
             Optional custom end date. Defaults to tomorrow.
         .EXAMPLE
             Get-AuditEventData -EventLog Security -EventID 4624
         .EXAMPLE
             Get-AuditEventData -EventLog File -EventID 4624 -FilePath C:\Logs\Security.evtx
     #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][string]$EventID,
        [Parameter(Mandatory = $true)][string]$EventLog,
        [Parameter()] [int]$Days = 14,
        [Parameter()] [string]$FilePath,
        [Parameter()] [datetime]$StartDate,
        [Parameter()] [datetime]$EndDate
    )

    BEGIN {
        $StartDate = $StartDate ?? (Get-Date).AddDays(-$Days)
        $EndDate = $EndDate ?? (Get-Date).AddDays(1)

        $filter = @{ ID = $EventID; StartTime = $StartDate; EndTime = $EndDate }
        $filterKey = if ($EventLog -eq 'File') { 'Path' } else { 'LogName' }
        $filter[$filterKey] = ($EventLog -eq 'File') ? $FilePath : $EventLog

        try {
            $Events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to retrieve events: $_"
            return
        }

        $AuditEventData = @()
    }

    PROCESS {
        if (-not $Events) {
            Write-Verbose "No events found for ID $EventID"
            return
        }

        foreach ($Event in $Events) {
            $props = $Event.Properties.Value
            $output = [pscustomobject]@{
                TimeCreated = $Event.TimeCreated
            }

            switch ($EventID) {
                '4624' { $output | Add-Member NoteProperty User $props[5] }
                '4625' { $output | Add-Member NoteProperty 'User Name' $props[5] }
                '4647' { $output | Add-Member NoteProperty 'User Name' $props[1] }
                '4634' { $output | Add-Member NoteProperty 'User Name' $props[1] }
                '4672' {
                    $output | Add-Member NoteProperty 'User Name' $props[1]
                    $output | Add-Member NoteProperty 'Privileges' $props[4]
                }
                '4720' {
                    $output | Add-Member NoteProperty 'User Created' $props[0]
                    $output | Add-Member NoteProperty 'Created By' $props[4]
                }
                '4724' {
                    $output | Add-Member NoteProperty 'User Reset' $props[0]
                    $output | Add-Member NoteProperty 'Reset By' $props[4]
                }
                '4722' {
                    $output | Add-Member NoteProperty 'User Enabled' $props[0]
                    $output | Add-Member NoteProperty 'Enabled By' $props[4]
                }
                '4725' {
                    $output | Add-Member NoteProperty 'User Disabled' $props[0]
                    $output | Add-Member NoteProperty 'Disabled By' $props[4]
                }
                '4726' {
                    $output | Add-Member NoteProperty 'User Deleted' $props[0]
                    $output | Add-Member NoteProperty 'Deleted By' $props[4]
                }
                '4738' {
                    $output | Add-Member NoteProperty 'User Changed' $props[1]
                    $output | Add-Member NoteProperty 'Changed By' $props[5]
                }
                '4740' { $output | Add-Member NoteProperty 'User Locked' $props[0] }
                '4767' {
                    $output | Add-Member NoteProperty 'User Unlocked' $props[0]
                    $output | Add-Member NoteProperty 'Unlocked By' $props[4]
                }
                '4731' {
                    $output | Add-Member NoteProperty 'Group Name' $props[0]
                    $output | Add-Member NoteProperty 'Created By' $props[4]
                }
                '4732' {
                    $output | Add-Member NoteProperty 'Group Name' $props[2]
                    $sid = $props[1].Value
                    $localUser = (Get-LocalUser | Where-Object { $_.SID -eq $sid }).Name
                    $output | Add-Member NoteProperty 'Member' $localUser
                    $output | Add-Member NoteProperty 'Added By' $props[6]
                }
                '4733' {
                    $output | Add-Member NoteProperty 'Group Name' $props[2]
                    $sid = $props[1].Value
                    $localUser = (Get-LocalUser | Where-Object { $_.SID -eq $sid }).Name
                    $output | Add-Member NoteProperty 'Member' $localUser
                    $output | Add-Member NoteProperty 'Removed By' $props[6]
                }
                '4734' {
                    $output | Add-Member NoteProperty 'Group Name' $props[0]
                    $output | Add-Member NoteProperty 'Deleted By' $props[4]
                }
                '4735' {
                    $output | Add-Member NoteProperty 'Group Name' $props[0]
                    $output | Add-Member NoteProperty 'Changed By' $props[4]
                }
                '4608' { $output | Add-Member NoteProperty Startup 'Startup' }
                '4609' { }
                '4673' {
                    $output | Add-Member NoteProperty 'Service' $props[8]
                    $output | Add-Member NoteProperty 'Called By' $props[1]
                    $output | Add-Member NoteProperty 'Privileges' $props[6]
                }
                '4674' {
                    $output | Add-Member NoteProperty 'Process Name' $props[11]
                    $output | Add-Member NoteProperty 'User' $props[1]
                    $output | Add-Member NoteProperty 'Privileges' $props[9]
                }
                '4670' { $output | Add-Member NoteProperty 'Process Name' $props[11] }
                '4705' { $output | Add-Member NoteProperty 'Account SID' $props[4].Value }
                '4719' { $output | Add-Member NoteProperty 'SubCategory GUID' $props[6] }
                '4697' {
                    $output | Add-Member NoteProperty 'Service Name' $props[4]
                    $output | Add-Member NoteProperty 'Service Path' $props[5]
                }
                '6416' {
                    $output | Add-Member NoteProperty 'Device Name' $props[5]
                    $output | Add-Member NoteProperty 'Class Name' $props[7]
                }
                '6419' {
                    $output | Add-Member NoteProperty 'Device Name' $props[5]
                    $output | Add-Member NoteProperty 'Disabled By' $props[1]
                }
                '6420' { $output | Add-Member NoteProperty 'Device Name' $props[5] }
                '6421' {
                    $output | Add-Member NoteProperty 'Device Name' $props[5]
                    $output | Add-Member NoteProperty 'Enabled By' $props[1]
                }
                '6422' { $output | Add-Member NoteProperty 'Device Name' $props[5] }
                '1102' { $output | Add-Member NoteProperty 'User Name' $props[1] }
                '4715' { Write-Verbose "Event ID 4715: parsing not implemented." }
                default { Write-Verbose "Unknown or unparsed Event ID: $EventID" }
            }

            $AuditEventData += $output
        }
    }

    END {
        return $AuditEventData
    }
}
