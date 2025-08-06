function Remove-LocalTestUsers {
  <#
        .SYNOPSIS
            Removes local test accounts matching the 'TEST##' pattern.

        .DESCRIPTION
            Deletes local accounts that begin with "TEST" followed by digits.
            You can filter to only remove admin test users if needed.

        .PARAMETER Count
            Number of test accounts to remove (e.g., 10 will try to remove TEST01–TEST10). If omitted, all TEST## users will be checked.

        .PARAMETER OnlyAdmins
            Only removes TEST## users that are in the Administrators group.

        .EXAMPLE
            Remove-LocalTestUsers -Count 5

        .EXAMPLE
            Remove-LocalTestUsers -OnlyAdmins

        .EXAMPLE
            Remove-LocalTestUsers
    #>
  [CmdletBinding()]
  param(
    [int]$Count,
    [switch]$OnlyAdmins
  )

  begin {
    $prefix = 'TEST'
    $ComputerName = $env:COMPUTERNAME
    $ComputerPrefix = "$ComputerName\"
    $adminUsers = @()

    if ($OnlyAdmins) {
      $adminUsers = Get-LocalGroupMember -Group Administrators |
      Where-Object { $_.Name -like "$prefix*" -and $_.PrincipalSource -eq 'Local' } |
      ForEach-Object { $_.Name -replace [regex]::Escape($ComputerPrefix), '' }
    }
  }

  process {
    $targetUsers = Get-LocalUser | Where-Object {
      $_.Name -like "$prefix*" -and
      ($Count -eq 0 -or $_.Name -match "$prefix\d{2}" -and [int]($_.Name -replace "$prefix") -le $Count)
    }

    if ($OnlyAdmins) {
      $targetUsers = $targetUsers | Where-Object { $adminUsers -contains $_.Name }
    }

    foreach ($user in $targetUsers) {
      try {
        Remove-LocalUser -Name $user.Name -ErrorAction Stop
        Write-Host "Removed $($user.Name)" -ForegroundColor Green
      }
      catch {
        Write-Warning "Failed to remove $($user.Name): $($_.Exception.Message)"
      }
    }

    if (-not $targetUsers) {
      Write-Host "No matching test users found to remove." -ForegroundColor Yellow
    }
  }
}
