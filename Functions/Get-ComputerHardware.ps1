function Get-ComputerHardware {
  <#
        .SYNOPSIS
            Retrieves summary hardware information from local or remote computers.
        .DESCRIPTION
            Queries system, processor, BIOS, sound, video, disk, and physical media info using CIM.
            Returns one flat object per computer, suitable for export, filtering, or GUI display.
        .PARAMETER ComputerName
            One or more computer names. Defaults to the local computer.
        .EXAMPLE
            Get-ComputerHardware
            Returns hardware info for the local machine.
        .EXAMPLE
            Get-ComputerHardware -ComputerName "PC01","PC02"
            Returns hardware info for multiple remote computers.
        .EXAMPLE
            "PC01","PC02" | Get-ComputerHardware
            Accepts piped input of computer names.
    #>
  [CmdletBinding()]
  param(
    [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [string[]]$ComputerName = $env:COMPUTERNAME
  )

  BEGIN {
    $results = @()
  }

  PROCESS {
    foreach ($Computer in $ComputerName) {
      Write-Verbose "Querying $Computer"

      try {
        $sys = Get-CimInstance -Class Win32_ComputerSystem -ComputerName $Computer -ErrorAction Stop
        $cpu = Get-CimInstance -Class Win32_Processor -ComputerName $Computer -ErrorAction Stop
        $bios = Get-CimInstance -Class Win32_BIOS -ComputerName $Computer -ErrorAction Stop
        $video = Get-CimInstance -Class Win32_VideoController -ComputerName $Computer -ErrorAction SilentlyContinue
        $sound = Get-CimInstance -Class Win32_SoundDevice -ComputerName $Computer -ErrorAction SilentlyContinue
        $disk = Get-CimInstance -Class Win32_LogicalDisk -ComputerName $Computer -Filter "DriveType=3" -ErrorAction SilentlyContinue
        $media = Get-CimInstance -Class Win32_PhysicalMedia -ComputerName $Computer -ErrorAction SilentlyContinue

        $results += [pscustomobject]@{
          ComputerName    = $Computer
          Manufacturer    = $sys.Manufacturer
          Model           = $sys.Model
          TotalRAMGB      = [math]::Round($sys.TotalPhysicalMemory / 1GB, 2)
          CPU             = $cpu.Name
          CPUCores        = $cpu.NumberOfCores
          CPULogical      = $cpu.NumberOfLogicalProcessors
          BIOSVersion     = ($bios.SMBIOSBIOSVersion -join ", ")
          BIOSSerial      = $bios.SerialNumber
          VideoAdapter    = ($video | Select-Object -First 1).Name
          SoundCard       = ($sound | Select-Object -First 1).Name
          DiskDrives      = ($disk | ForEach-Object { "$($_.DeviceID) $([math]::Round($_.Size / 1GB))GB" }) -join "; "
          PhysicalSerials = ($media | ForEach-Object { $_.SerialNumber }) -join "; "
        }
      }
      catch {
        Write-Warning ("Failed to retrieve hardware info from {0}: {1}" -f $Computer, $_)
      }
    }
  }

  END {
    $results
  }
}
