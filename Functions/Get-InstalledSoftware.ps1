function Get-InstalledSoftware {
  <#
        .SYNOPSIS
            Retrieves installed software from 64-bit and 32-bit registry hives on local or remote computers.
        .DESCRIPTION
            Scans both registry locations for installed software entries:
            - HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
            - HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall
            Returns Name, Version, Publisher, InstallDate, UninstallString, and source path for each detected application.
        .PARAMETER ComputerName
            One or more computer names to query. Defaults to the local computer.
        .EXAMPLE
            Get-InstalledSoftware
            Returns the installed software list for the local machine.
        .EXAMPLE
            Get-InstalledSoftware -ComputerName "PC01","PC02"
            Returns the installed software list for multiple remote computers.
        .EXAMPLE
            "PC01","PC02" | Get-InstalledSoftware
            Returns the installed software list from a pipeline of computer names.
    #>
  [CmdletBinding()]
  Param(
    [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [string[]]$ComputerName = $env:COMPUTERNAME
  )
  BEGIN {
    $inventory = @()
  } #BEGIN

  PROCESS {
    foreach ($Computer in $ComputerName) {
      Write-Verbose "Querying $Computer..."

      $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
      )

      foreach ($path in $paths) {
        try {
          if ($Computer -eq $env:COMPUTERNAME) {
            $regKeys = Get-ChildItem -Path $path -ErrorAction Stop
          }
          else {
            $regBase = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Computer)
            $subKey = $path -replace 'HKLM:\\', ''
            $regKeys = $regBase.OpenSubKey($subKey).GetSubKeyNames() | ForEach-Object {
              $regBase.OpenSubKey("$subKey\$_")
            }
          }

          foreach ($key in $regKeys) {
            $displayName = $key.GetValue('DisplayName')
            if ($displayName) {
              $inventory += [PSCustomObject]@{
                ComputerName    = $Computer
                Name            = $displayName
                Version         = $key.GetValue('DisplayVersion')
                Publisher       = $key.GetValue('Publisher')
                InstallDate     = $key.GetValue('InstallDate')
                UninstallString = $key.GetValue('UninstallString')
                Source          = "Registry ($path)"
              }
            }
          }
        }
        catch {
          Write-Warning ("Registry access failed on {0} for path {1}: {2}" -f $Computer, $path, $_)
        }
      }
    }
  } #PROCESS

  END {
    $inventory
  } #END

} #FUNCTION
