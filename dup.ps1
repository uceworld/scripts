$scriptPath = "C:\AD-MigrationSuite\Backups\Invoke-CM-Wave002-DuplicateProfileCleanup.ps1"; New-Item -Path "C:\AD-MigrationSuite\Backups" -ItemType Directory -Force | Out-Null; @'
[CmdletBinding()]
param(
    [switch]$Execute,
    [switch]$LogoffSessions,
    [string]$OutputRoot = "C:\AD-MigrationSuite\Backups"
)

$ErrorActionPreference = "Stop"

$configPath = "C:\AD-MigrationSuite\Computer-Migration\Config\MigrationAutomationConfig.json"
$config = Get-Content -Path $configPath -Raw | ConvertFrom-Json
$targetCred = Import-Clixml -Path $config.CredentialFiles.TargetDirectoryAdmin

$stamp = Get-Date -Format yyyyMMdd-HHmmss
$resultOut = Join-Path $OutputRoot "CM-Wave002-DuplicateProfileCleanup-$stamp.csv"

$targets = @(
    [pscustomobject]@{ ComputerName="DPRESORT6AWS"; IPAddress="10.254.140.218"; ProfilePath="C:\Users\noltingr.ID"; UserName="noltingr"; Reason="Confirmed duplicate target-domain profile before security translation" },
    [pscustomobject]@{ ComputerName="PMVMG1DSM"; IPAddress="10.14.93.217"; ProfilePath="C:\Users\chauhann_ep.ID"; UserName="chauhann_ep"; Reason="Confirmed duplicate target-domain profile before security translation" },
    [pscustomobject]@{ ComputerName="PMVMG1DSM"; IPAddress="10.14.93.217"; ProfilePath="C:\Users\vavinash_ep.ID"; UserName="vavinash_ep"; Reason="Confirmed duplicate target-domain profile before security translation" },
    [pscustomobject]@{ ComputerName="PPRESORT1AWS"; IPAddress="10.254.140.161"; ProfilePath="C:\Users\noltingr.ID"; UserName="noltingr"; Reason="Confirmed duplicate target-domain profile before security translation" }
)

$remoteCleanup = {
    param(
        [object[]]$ProfileTargets,
        [string]$Stamp,
        [bool]$Execute,
        [bool]$LogoffSessions
    )

    function Get-MatchingUserSessions {
        param([string]$UserName)

        $sessions = @()
        try {
            $raw = @(quser 2>$null)
            foreach ($line in ($raw | Select-Object -Skip 1)) {
                $clean = $line.Trim()
                if ($clean.StartsWith(">")) { $clean = $clean.Substring(1).Trim() }
                if ([string]::IsNullOrWhiteSpace($clean)) { continue }

                $parts = $clean -split "\s+"
                if ($parts.Count -lt 2) { continue }

                $sessionUser = $parts[0]
                $idIndex = -1
                for ($i = 1; $i -lt $parts.Count; $i++) {
                    if ($parts[$i] -match "^\d+$") {
                        $idIndex = $i
                        break
                    }
                }

                if ($idIndex -ge 0 -and $sessionUser -ieq $UserName) {
                    $sessions += [pscustomobject]@{
                        UserName = $sessionUser
                        SessionId = [int]$parts[$idIndex]
                        RawLine = $line
                    }
                }
            }
        }
        catch {
        }

        return $sessions
    }

    function Set-QuarantineAcl {
        param([string]$Path)

        try {
            New-Item -Path $Path -ItemType Directory -Force | Out-Null
            icacls $Path /inheritance:r /grant:r "SYSTEM:(OI)(CI)(F)" "BUILTIN\Administrators:(OI)(CI)(F)" | Out-Null
        }
        catch {
        }
    }

    $computerName = $env:COMPUTERNAME
    $quarantineRoot = "C:\ADMS-ProfileQuarantine\Wave-002-PostJoin-DuplicateProfiles"
    Set-QuarantineAcl -Path $quarantineRoot

    $results = @()

    foreach ($target in $ProfileTargets) {
        $profilePath = [string]$target.ProfilePath
        $userName = [string]$target.UserName
        $folderName = Split-Path $profilePath -Leaf
        $computerRoot = Join-Path $quarantineRoot $computerName
        $snapshotPath = Join-Path $computerRoot ("$folderName-$Stamp")
        $registryExportPath = ""
        $sessionsFound = @()
        $sessionsLoggedOff = @()
        $errors = @()
        $snapshotSucceeded = $false
        $profileDeleteSucceeded = $false
        $movedOriginalSucceeded = $false
        $finalAction = "PlanOnly"

        try {
            New-Item -Path $computerRoot -ItemType Directory -Force | Out-Null
            Set-QuarantineAcl -Path $computerRoot

            $folderExistsBefore = Test-Path -LiteralPath $profilePath
            $profile = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { $_.LocalPath -ieq $profilePath } | Select-Object -First 1
            $sid = if ($profile) { [string]$profile.SID } else { "" }
            $loadedBefore = if ($profile) { [bool]$profile.Loaded } else { $false }

            $sessionsFound = @(Get-MatchingUserSessions -UserName $userName)

            if ($Execute -and $LogoffSessions -and $sessionsFound.Count -gt 0) {
                foreach ($session in $sessionsFound) {
                    try {
                        logoff $session.SessionId /V
                        $sessionsLoggedOff += "$($session.UserName):$($session.SessionId)"
                    }
                    catch {
                        $errors += "Failed to log off session $($session.SessionId) for $userName : $($_.Exception.Message)"
                    }
                }

                Start-Sleep -Seconds 15
                $profile = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { $_.LocalPath -ieq $profilePath } | Select-Object -First 1
            }

            $loadedAfterLogoff = if ($profile) { [bool]$profile.Loaded } else { $false }

            if (-not $folderExistsBefore) {
                $finalAction = "SkippedMissingFolder"
            }
            elseif (-not $Execute) {
                $finalAction = "WouldSnapshotAndRemoveIfUnloaded"
            }
            elseif ($loadedAfterLogoff) {
                $finalAction = "SkippedProfileStillLoaded"
                $errors += "Profile is still loaded after logoff attempt. Cleanup skipped."
            }
            else {
                New-Item -Path $snapshotPath -ItemType Directory -Force | Out-Null
                Set-QuarantineAcl -Path $snapshotPath

                $roboArgs = @($profilePath, $snapshotPath, "/E", "/COPY:DAT", "/DCOPY:DAT", "/R:2", "/W:2", "/XJ", "/NFL", "/NDL", "/NP")
                robocopy @roboArgs | Out-Null
                $roboExit = $LASTEXITCODE

                if ($roboExit -le 7) {
                    $snapshotSucceeded = $true
                }
                else {
                    $errors += "Robocopy snapshot failed with exit code $roboExit"
                }

                if ($snapshotSucceeded -and -not [string]::IsNullOrWhiteSpace($sid)) {
                    $registryExportPath = Join-Path $snapshotPath ("ProfileList-$sid.reg")
                    try {
                        reg export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" $registryExportPath /y | Out-Null
                    }
                    catch {
                        $errors += "ProfileList registry export failed: $($_.Exception.Message)"
                    }
                }

                if ($snapshotSucceeded -and $profile) {
                    try {
                        Invoke-CimMethod -InputObject $profile -MethodName Delete -ErrorAction Stop | Out-Null
                        $profileDeleteSucceeded = $true
                        $finalAction = "ProfileDeletedAfterSnapshot"
                    }
                    catch {
                        $errors += "Win32_UserProfile Delete failed: $($_.Exception.Message)"
                    }
                }

                if ($snapshotSucceeded -and -not $profileDeleteSucceeded -and (Test-Path -LiteralPath $profilePath)) {
                    try {
                        $movedPath = Join-Path $computerRoot ("$folderName-original-moved-out-of-Users-$Stamp")
                        Move-Item -LiteralPath $profilePath -Destination $movedPath -Force -ErrorAction Stop
                        $movedOriginalSucceeded = $true
                        $finalAction = "FolderMovedOutOfUsersAfterSnapshot"
                    }
                    catch {
                        $errors += "Fallback Move-Item out of C:\Users failed: $($_.Exception.Message)"
                        if ($finalAction -eq "PlanOnly") { $finalAction = "CleanupFailedAfterSnapshot" }
                    }
                }

                if ($snapshotSucceeded -and -not (Test-Path -LiteralPath $profilePath)) {
                    if ($finalAction -eq "PlanOnly") { $finalAction = "RemovedAfterSnapshot" }
                }
            }

            $profileAfter = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { $_.LocalPath -ieq $profilePath } | Select-Object -First 1

            $results += [pscustomobject]@{
                ComputerName = $computerName
                ProfilePath = $profilePath
                UserName = $userName
                Reason = [string]$target.Reason
                Execute = $Execute
                LogoffSessions = $LogoffSessions
                FolderExistsBefore = $folderExistsBefore
                Sid = $sid
                LoadedBefore = $loadedBefore
                SessionsFound = (($sessionsFound | ForEach-Object { "$($_.UserName):$($_.SessionId)" }) -join ";")
                SessionsLoggedOff = ($sessionsLoggedOff -join ";")
                LoadedAfterLogoff = $loadedAfterLogoff
                SnapshotPath = $snapshotPath
                SnapshotSucceeded = $snapshotSucceeded
                RegistryExportPath = $registryExportPath
                ProfileDeleteSucceeded = $profileDeleteSucceeded
                MovedOriginalSucceeded = $movedOriginalSucceeded
                FolderExistsAfter = Test-Path -LiteralPath $profilePath
                ProfileRegistryExistsAfter = [bool]($null -ne $profileAfter)
                FinalAction = $finalAction
                Error = ($errors -join " | ")
            }
        }
        catch {
            $results += [pscustomobject]@{
                ComputerName = $computerName
                ProfilePath = $profilePath
                UserName = $userName
                Reason = [string]$target.Reason
                Execute = $Execute
                LogoffSessions = $LogoffSessions
                FolderExistsBefore = ""
                Sid = ""
                LoadedBefore = ""
                SessionsFound = (($sessionsFound | ForEach-Object { "$($_.UserName):$($_.SessionId)" }) -join ";")
                SessionsLoggedOff = ($sessionsLoggedOff -join ";")
                LoadedAfterLogoff = ""
                SnapshotPath = $snapshotPath
                SnapshotSucceeded = $snapshotSucceeded
                RegistryExportPath = $registryExportPath
                ProfileDeleteSucceeded = $profileDeleteSucceeded
                MovedOriginalSucceeded = $movedOriginalSucceeded
                FolderExistsAfter = ""
                ProfileRegistryExistsAfter = ""
                FinalAction = "UnhandledError"
                Error = $_.Exception.Message
            }
        }
    }

    return $results
}

$allResults = @()

foreach ($computer in ($targets | Select-Object ComputerName,IPAddress -Unique)) {
    $profilesForTarget = @($targets | Where-Object { $_.ComputerName -eq $computer.ComputerName })

    Write-Host "Processing $($computer.ComputerName) [$($computer.IPAddress)] ..." -ForegroundColor Cyan

    try {
        $remoteResult = Invoke-Command -ComputerName $computer.IPAddress -Credential $targetCred -Authentication Negotiate -ArgumentList (,$profilesForTarget),$stamp,[bool]$Execute,[bool]$LogoffSessions -ScriptBlock $remoteCleanup -ErrorAction Stop
        $allResults += @($remoteResult)
    }
    catch {
        foreach ($profile in $profilesForTarget) {
            $allResults += [pscustomobject]@{
                ComputerName = $computer.ComputerName
                ProfilePath = $profile.ProfilePath
                UserName = $profile.UserName
                Reason = $profile.Reason
                Execute = [bool]$Execute
                LogoffSessions = [bool]$LogoffSessions
                FolderExistsBefore = ""
                Sid = ""
                LoadedBefore = ""
                SessionsFound = ""
                SessionsLoggedOff = ""
                LoadedAfterLogoff = ""
                SnapshotPath = ""
                SnapshotSucceeded = $false
                RegistryExportPath = ""
                ProfileDeleteSucceeded = $false
                MovedOriginalSucceeded = $false
                FolderExistsAfter = ""
                ProfileRegistryExistsAfter = ""
                FinalAction = "RemoteFailed"
                Error = $_.Exception.Message
            }
        }
    }
}

$allResults | Export-Csv -Path $resultOut -NoTypeInformation -Encoding UTF8
Write-Host ""
Write-Host "Cleanup result written to: $resultOut" -ForegroundColor Green
$allResults | Format-Table ComputerName,ProfilePath,Execute,FolderExistsBefore,LoadedBefore,SessionsFound,SessionsLoggedOff,SnapshotSucceeded,ProfileDeleteSucceeded,MovedOriginalSucceeded,FolderExistsAfter,ProfileRegistryExistsAfter,FinalAction -AutoSize
'@ | Set-Content -Path $scriptPath -Encoding UTF8; try { [scriptblock]::Create((Get-Content -Path $scriptPath -Raw)) | Out-Null; Write-Host "Created and syntax-validated $scriptPath" -ForegroundColor Green } catch { Write-Host "Syntax validation failed: $($_.Exception.Message)" -ForegroundColor Red; throw }
