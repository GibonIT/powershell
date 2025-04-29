<#
.SYNOPSIS
This script retrieves shared folder details from a local server
and replicates them on a target server, with an option to copy folder data.

.DESCRIPTION
This script retrieves shared folder details (permissions, paths, etc.) from the local server.
Users can select shares to replicate to the target server. It ensures target paths exist,
replicates share configurations, and optionally copies data. Default admin shares are excluded.

.PARAMETER TargetServer
The name of the target server where the shared folders will be created.

.PARAMETER CopyData
Indicates whether to copy the data from the source shared folders to the target shared folders.
Set to $true to enable data copying; defaults to $false.

.EXAMPLE
.\Copy-SharedFolders.ps1 -TargetServer "TargetServerName"

.EXAMPLE
.\Copy-SharedFolders.ps1 -TargetServer "TargetServerName" -CopyData:$true

.NOTES
Ensure you have the necessary permissions to read and write shares and permissions
on both source and target servers.
#>
param (
  [Parameter(Position = 0,
            Mandatory = $true,
            HelpMessage = "Specify the target server where the shared folders will be created.")]
  [string]
  $TargetServer,

  [Parameter(Position = 1,
            Mandatory = $false,
            HelpMessage = "Specify whether to copy the data from the source shares
            to the target shares.")]
  [bool]
  $CopyData = $false
)

function Get-Shares {
  Write-Host "Retrieving shared folders from $env:COMPUTERNAME..." -ForegroundColor Cyan
  $shares = Get-SmbShare | Where-Object {
    $_.ShareType -eq "FileSystem" -and
    $_.Name -notmatch '^[a-zA-Z]\$$' -and $_.Name -notin @('ADMIN$', 'IPC$')
  }

  $selectedShares = $shares | Select-Object Name, Path |
  Out-GridView -Title "Select shares to retrieve details from $env:COMPUTERNAME" -PassThru

  if (-not $selectedShares) {
    Write-Host "No shares selected. Exiting function." -ForegroundColor Red
    return @()
  }

  $shareDetails = @()

  foreach ($share in $selectedShares) {
    $fullShare = $shares | Where-Object { $_.Name -eq $share.Name }

    $permissions = Get-SmbShareAccess -Name $fullShare.Name | ForEach-Object {
      @{
        Account = $_.AccountName
        Access = $_.AccessControlType
        Rights = $_.AccessRight
      }
    }

    $shareDetails += @(
      @{
        Name = $fullShare.Name
        Path = $fullShare.Path
        Permissions = $permissions
        FolderEnumerationMode = $fullShare.FolderEnumerationMode
        CachingMode = $fullShare.CachingMode
      }
    )
  }
  return $shareDetails
}

function New-Shares {
  param (
    [string]$Server,
    [array]$Shares
  )

  foreach ($share in $Shares) {
    Write-Host "Processing share '$($share.Name)' on $Server..." -ForegroundColor Cyan
    $session = New-PSSession -ComputerName $Server

    try {
      # Check if the share already exists on the target server
      $existingShare = Invoke-Command -Session $session -ScriptBlock {
        param ($ShareName)
        Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue
      } -ArgumentList $share.Name

      if ($existingShare) {
        if ($existingShare.Path -ne $share.Path) {
          Write-Host "Share '$($share.Name)' already exists on $Server but with a different path. Fixing the path..." -ForegroundColor Yellow

          # Remove the existing share with the incorrect path
          Invoke-Command -Session $session -ScriptBlock {
            param ($ShareName)
            Remove-SmbShare -Name $ShareName -Force
          } -ArgumentList $share.Name | Out-Null

          # Create the share with the correct path
          Invoke-Command -Session $session -ScriptBlock {
            param ($SharePath)
            if (-not (Test-Path -Path $SharePath)) {
              New-Item -ItemType Directory -Path $SharePath -Force
            }
          } -ArgumentList $share.Path | Out-Null

          Invoke-Command -Session $session -ScriptBlock {
            param ($ShareName, $SharePath, $FolderEnumerationMode, $CachingMode)
            New-SmbShare -Name $ShareName -Path $SharePath -FolderEnumerationMode $FolderEnumerationMode -CachingMode $CachingMode
          } -ArgumentList $share.Name, $share.Path, $share.FolderEnumerationMode, $share.CachingMode | Out-Null

          Write-Host "Path for share '$($share.Name)' fixed successfully on $Server." -ForegroundColor Green
        } else {
          Write-Host "Share '$($share.Name)' already exists on $Server with the correct path. Skipping creation." -ForegroundColor Green
          continue
        }
      } else {
        # Create the share if it does not exist
        Write-Host "Creating share '$($share.Name)' on $Server..." -ForegroundColor Cyan

        Invoke-Command -Session $session -ScriptBlock {
          param ($SharePath)
          if (-not (Test-Path -Path $SharePath)) {
            New-Item -ItemType Directory -Path $SharePath -Force
          }
        } -ArgumentList $share.Path | Out-Null

        Invoke-Command -Session $session -ScriptBlock {
          param ($ShareName, $SharePath, $FolderEnumerationMode, $CachingMode)
          New-SmbShare -Name $ShareName -Path $SharePath -FolderEnumerationMode $FolderEnumerationMode -CachingMode $CachingMode
        } -ArgumentList $share.Name, $share.Path, $share.FolderEnumerationMode, $share.CachingMode | Out-Null

        Write-Host "Successfully created share '$($share.Name)' on $Server." -ForegroundColor Green
      }

      # Revoke default permissions and apply the specified permissions
      Invoke-Command -Session $session -ScriptBlock {
        param ($ShareName)
        Revoke-SmbShareAccess -Name $ShareName -AccountName "Everyone" -Force
      } -ArgumentList $share.Name | Out-Null

      foreach ($permission in $share.Permissions) {
        Invoke-Command -Session $session -ScriptBlock {
          param ($ShareName, $Account, $Access)
          Grant-SmbShareAccess -Name $ShareName -AccountName $Account -AccessRight $Access -Force
        } -ArgumentList $share.Name, $permission.Account, $permission.Rights | Out-Null
      }
    } finally {
      Remove-PSSession -Session $session
    }
  }
}

function Copy-ShareData {
  param (
    [array]$Shares,
    [string]$TargetServer
  )

  $logname = "$(Get-Date -Format 'dd-MM-yyyy')_$env:COMPUTERNAME_to_$TargetServer_DataCopy.log"

  foreach ($share in $Shares) {
    $sourcePath = "$($share.Path)"
    $targetPath = "\\$TargetServer\$($share.Name)"
    $currentUser = "$env:USERDOMAIN\$env:USERNAME"

    Write-Host "Granting full control permissions for $currentUser on share '$($share.Name)'..." -ForegroundColor Cyan

    # Grant full control to the current user
    Invoke-Command -ComputerName $TargetServer -ScriptBlock {
      param ($ShareName, $Account)
      Grant-SmbShareAccess -Name $ShareName -AccountName $Account -AccessRight Full -Force
    } -ArgumentList $share.Name, $currentUser | Out-Null

    Write-Host "Copying data from $sourcePath to $targetPath..." -ForegroundColor Cyan

    $robocopy = robocopy.exe $sourcePath $targetPath /MIR /R:3 /W:5 /COPYALL /SECFIX /DCOPY:DAT /LOG+:$logname

    if ($LASTEXITCODE -le 3) {
      Write-Host "Data copied successfully for share '$($share.Name)'." -ForegroundColor Green
    } else {
      Write-Host "Error occurred while copying data for share '$($share.Name)'. Check CopyData.log for details." -ForegroundColor Red
    }

    Write-Host "Removing full control permissions for $currentUser from share '$($share.Name)'..." -ForegroundColor Cyan

    # Remove full control from the current user
    Invoke-Command -ComputerName $TargetServer -ScriptBlock {
      param ($ShareName, $Account)
      Revoke-SmbShareAccess -Name $ShareName -AccountName $Account -Force
    } -ArgumentList $share.Name, $currentUser | Out-Null
  }
}
function Test-DriveExists {
  param (
    [string]$Server,
    [string]$DriveLetter
  )

  Write-Host "Checking target drives on $TargetServer..." -ForegroundColor Cyan

  $session = New-PSSession -ComputerName $Server
  try {
    $driveStatus = Invoke-Command -Session $session -ScriptBlock {
      param ($DriveLetter)
      $volume = Get-Volume -DriveLetter $DriveLetter -ErrorAction SilentlyContinue
      if ($volume) {
        if ($volume.DriveType -eq 'CD-ROM') {
          return "CD-ROM"
        } else {
          return "Exists"
        }
      } else {
        return "NotExists"
      }
    } -ArgumentList $DriveLetter
  } finally {
    Remove-PSSession -Session $session
  }

  return $driveStatus
}

function Confirm-FileServerRole {
  param (
    [string]$Server
  )

  Write-Host "Checking if FS-FileServer role is installed on $Server..." -ForegroundColor Cyan
  $session = New-PSSession -ComputerName $Server
  try {
    $roleInstalled = Invoke-Command -Session $session -ScriptBlock {
      Get-WindowsFeature -Name FS-FileServer | Select-Object -ExpandProperty Installed
    }

    if (-not $roleInstalled) {
      $installRole = Read-Host "FS-FileServer role is not installed on $Server. Do you want to install it? (Y/N)"
      if ($installRole -eq 'Y') {
        Invoke-Command -Session $session -ScriptBlock {
          Install-WindowsFeature -Name FS-FileServer -IncludeManagementTools
        } | Out-Null
        Write-Host "FS-FileServer role installed successfully on $Server." -ForegroundColor Green
      } else {
        Write-Host "FS-FileServer role installation skipped. Exiting script." -ForegroundColor Red
        exit
      }
    } else {
      Write-Host "FS-FileServer role is already installed on $Server." -ForegroundColor Green
    }
  } finally {
    Remove-PSSession -Session $session
  }
}

# Main script
Write-Host "Starting shared folder synchronization..." -ForegroundColor Yellow
$sourceShares = Get-Shares

foreach ($share in $sourceShares) {
  $driveLetter = $share.Path.Substring(0, 1)
  $driveStatus = Test-DriveExists -Server $TargetServer -DriveLetter $driveLetter

  if ($driveStatus -eq "NotExists") {
    Write-Host "Drive $driveLetter does not exist on $TargetServer for share '$($share.Name)' with path '$($share.Path)'.`
    Please check the target server or remove the faulty share from the selection." -ForegroundColor Red
    exit
  } elseif ($driveStatus -eq "CD-ROM") {
    Write-Host "Drive $driveLetter on $TargetServer is a CD-ROM for share '$($share.Name)' with path '$($share.Path)'.`
    Please check the target server or remove the faulty share from the selection." -ForegroundColor Red
    exit
  }
}

Confirm-FileServerRole -Server $TargetServer

New-Shares -Server $TargetServer -Shares $sourceShares

if ($CopyData) {
  Copy-ShareData -Shares $sourceShares -TargetServer $TargetServer
}

Write-Host "Shared folder synchronization completed successfully!" -ForegroundColor Green
