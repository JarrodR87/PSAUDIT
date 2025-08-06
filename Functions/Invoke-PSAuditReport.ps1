function Invoke-PSAuditReport {
  <#
        .SYNOPSIS
            Creates a Local Audit Report or returns audit data as a hashtable.
        .DESCRIPTION
            Generates a local audit report with user, group, disk, volume, hardware, software, and optionally security event log data.
            Can either export the report to HTML or return data as a hashtable for further use.
        .PARAMETER ReportPath
            Directory path to save the report to. Filename is auto-generated.
        .PARAMETER FilestoHash
            Optional comma-separated list of file paths to hash and include in the report.
        .PARAMETER Days
            Number of days to include in event log lookups (default: 14).
        .PARAMETER AsHashtable
            If specified, returns all audit data as a hashtable instead of generating HTML.
        .PARAMETER ExcludeEvents
            If specified, skips event log data collection to improve performance.
        .EXAMPLE
            Invoke-PSAuditReport -ReportPath 'C:\AuditReports\' -FilestoHash 'C:\File1.txt','C:\File2.txt'
        .EXAMPLE
            Invoke-PSAuditReport -ReportPath 'C:\AuditReports\' -AsHashtable -ExcludeEvents
    #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [string]$ReportPath,

    [Parameter()]
    [string[]]$FilestoHash,

    [Parameter()]
    [int]$Days = 14,

    [Parameter()]
    [switch]$AsHashtable,

    [Parameter()]
    [switch]$ExcludeEvents
  )

  begin {
    $Date = Get-Date -Format 'MM-dd-yyyy'
    $StartDate = (Get-Date).AddDays(-$Days)
    $ReportFile = Join-Path -Path $ReportPath -ChildPath "AuditReport$Date.html"

    $HtmlHead = '<style>body {font-family: Calibri;} table {border: 1px solid black; border-collapse: collapse; width: 100%;} th, td {border: 1px solid black; padding: 5px;} th {background-color: #98C6F3;} td {background-color: white;} tr {text-align: left;}</style>'

    $ErrorActionPreference = 'SilentlyContinue'

    $AuditData = @{}

    $EventDescriptions = @{
      4624 = "An account was successfully logged on"
      4625 = "An account failed to log on"
      4634 = "An account was logged off"
      4647 = "User initiated logoff"
      4672 = "Special privileges assigned to new logon"
      4608 = "Windows is starting up"
      4609 = "Windows is shutting down"
      4616 = "System time was changed"
      4720 = "User account was created"
      4722 = "User account was enabled"
      4724 = "User password was reset"
      4725 = "User account was disabled"
      4726 = "User account was deleted"
      4731 = "Security-enabled local group was created"
      4732 = "Member added to a local group"
      4733 = "Member removed from a local group"
      4734 = "Security-enabled local group was deleted"
      4735 = "Local group was changed"
      4738 = "User account was changed"
      4740 = "User account was locked out"
      4767 = "User account was unlocked"
      4697 = "Service was installed"
      4705 = "User right was removed"
      4715 = "Audit policy (SACL) was changed"
      4719 = "System audit policy was changed"
      4907 = "Auditing settings on object were changed"
      6416 = "External device was recognized"
      6419 = "Request to disable a device"
      6420 = "Device was disabled"
      6421 = "Request to enable a device"
      6422 = "Device was enabled"
      1102 = "Audit log was cleared"
    }
  }

  process {
    $FileHashesRaw = @()
    if ($FilestoHash) {
      foreach ($File in $FilestoHash) {
        if (Test-Path $File) {
          $Hash = Get-FileHash -Path $File -Algorithm SHA256
          $FileHashesRaw += [pscustomobject]@{
            Path      = $Hash.Path
            Hash      = $Hash.Hash
            Algorithm = $Hash.Algorithm
          }
        }
      }
    }
    else {
      $FileHashesRaw += [pscustomobject]@{
        Path      = 'No files specified'
        Hash      = ''
        Algorithm = ''
      }
    }
    $AuditData.FileHashes = $FileHashesRaw
    $FileHashes = $FileHashesRaw | ConvertTo-Html -Fragment | Out-String

    $HardwareRaw = Get-ComputerHardware | Select-Object * -ExcludeProperty ComputerName
    $AuditData.Hardware = $HardwareRaw
    $HardwareTable = $HardwareRaw | ForEach-Object {
      $_ | Get-Member -MemberType NoteProperty | ForEach-Object {
        "<tr><th>$($_.Name)</th><td>$($_.Definition.Split('=')[-1].Trim())</td></tr>"
      } | Out-String
    }
    $HardwareTable = "<table>$HardwareTable</table>"

    $LocalUsersRaw = Get-LocalUser | ForEach-Object {
      $SID = $_.SID.Value
      $ProfilePath = (Get-Item "HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\*").Where({ $_.Name -like "*$SID" }).GetValue('ProfileImagePath')
      [pscustomobject]@{
        Name            = $_.Name
        Description     = $_.Description
        LastLogon       = $_.LastLogon
        Enabled         = $_.Enabled
        PasswordExpires = $_.PasswordExpires
        ProfilePath     = $ProfilePath ?? 'NOPROFILE'
      }
    }
    $AuditData.LocalUsers = $LocalUsersRaw
    $LocalUsers = $LocalUsersRaw | Sort-Object LastLogon -Descending | ConvertTo-Html -Fragment | Out-String

    $LocalGroupsRaw = Get-LocalGroup | ForEach-Object {
      [pscustomobject]@{
        Name        = $_.Name
        Description = $_.Description
        Members     = (Get-LocalGroupMember $_ | Select-Object -ExpandProperty Name) -join ", "
      }
    }
    $AuditData.LocalGroups = $LocalGroupsRaw
    $LocalGroups = $LocalGroupsRaw | ConvertTo-Html -Fragment | Out-String

    $LocalDisksRaw = Get-Disk | ForEach-Object {
      [pscustomobject]@{
        Model          = $_.Model
        Manufacturer   = $_.Manufacturer
        SerialNumber   = $_.SerialNumber
        'Size in GB'   = [math]::Round($_.Size / 1GB, 2)
        PartitionStyle = $_.PartitionStyle
      }
    }
    $AuditData.LocalDisks = $LocalDisksRaw
    $LocalDisks = $LocalDisksRaw | ConvertTo-Html -Fragment | Out-String

    $VolumesRaw = Get-Volume | ForEach-Object {
      [pscustomobject]@{
        UniqueID           = $_.UniqueID
        DriveLetter        = $_.DriveLetter
        DriveType          = $_.DriveType
        FileSystem         = $_.FileSystem
        FileSystemLabel    = $_.FileSystemLabel
        HealthStatus       = $_.HealthStatus
        FriendlyName       = $_.FriendlyName
        'Size in GB'       = [math]::Round($_.Size / 1GB, 2)
        'Free Space in GB' = [math]::Round($_.SizeRemaining / 1GB, 2)
      }
    }
    $AuditData.Volumes = $VolumesRaw
    $Volumes = $VolumesRaw | ConvertTo-Html -Fragment | Out-String

    $SoftwareRaw = Get-InstalledSoftware | Select-Object Name, Version, Publisher, InstallDate, UninstallString, Source
    $AuditData.InstalledSoftware = $SoftwareRaw
    $Software = $SoftwareRaw | ConvertTo-Html -Fragment | Out-String

    $EventHtmlSections = @()
    if (-not $ExcludeEvents) {
      $AuditEvents = $EventDescriptions.Keys
      $AuditData.Events = @{}
      $EventHtmlSections = foreach ($EventID in $AuditEvents) {
        $EventData = Get-AuditEventData -EventLog Security -EventID $EventID -Days $Days
        $AuditData.Events["Event_$EventID"] = $EventData
        $Heading = "<h2>Event $EventID - $($EventDescriptions[$EventID])</h2>"
        if ($EventData -like '*No Events Located*') {
          $Heading + $EventData
        }
        else {
          $Heading + ($EventData | ConvertTo-Html -Fragment | Out-String)
        }
      }
    }

    $HtmlSections = @(
      $HtmlHead,
      "<h1>Audit Report - $(Get-Date) - $env:COMPUTERNAME</h1>",
      "<h2>File Hashes</h2>", $FileHashes,
      "<h2>Hardware Summary</h2>", $HardwareTable,
      "<h2>Local Users</h2>", $LocalUsers,
      "<h2>Local Groups</h2>", $LocalGroups,
      "<h2>Local Disks</h2>", $LocalDisks,
      "<h2>Volumes</h2>", $Volumes,
      "<h2>Installed Software</h2>", $Software
    ) + ($EventHtmlSections | ForEach-Object { $_ | Out-String })
  }

  end {
    if ($AsHashtable) {
      return $AuditData
    }
    else {
      $HtmlSections -join "`n" | Out-File -FilePath $ReportFile -Encoding UTF8
      Write-Output "Audit report saved to: $ReportFile"
    }
  }
}
