$scriptPath = "C:\AD-MigrationSuite\Backups\Inspect-CM-16-PostJoinProfiles.ps1"; New-Item -Path "C:\AD-MigrationSuite\Backups" -ItemType Directory -Force | Out-Null; @'
[CmdletBinding()]
param(
    [datetime]$CutoffTime = "2026-05-09T23:00:00",
    [string]$OutputRoot = "C:\AD-MigrationSuite\Backups"
)

$ErrorActionPreference = "Stop"

$configPath = "C:\AD-MigrationSuite\Computer-Migration\Config\MigrationAutomationConfig.json"
$config = Get-Content -Path $configPath -Raw | ConvertFrom-Json

$targetCred = Import-Clixml -Path $config.CredentialFiles.TargetDirectoryAdmin
$localCredBase = Import-Clixml -Path $config.CredentialFiles.LocalAdmin
$localUserOnly = ($localCredBase.UserName -replace '^\.\\','')

$targets = @(
    [pscustomobject]@{Name="DPRESORT6AWS";IP="10.254.140.218"},
    [pscustomobject]@{Name="TPRESORT1AWS";IP="10.254.140.195"},
    [pscustomobject]@{Name="pmvmg1dsm";IP="10.14.93.217"},
    [pscustomobject]@{Name="PSCMS2DSM";IP="10.254.128.46"},
    [pscustomobject]@{Name="plansw1dsm";IP="10.254.129.55"},
    [pscustomobject]@{Name="PPRESORT1AWS";IP="10.254.140.161"},
    [pscustomobject]@{Name="P16SQL6DSM";IP="10.254.129.8"},
    [pscustomobject]@{Name="padcsweb1dsm";IP="10.254.130.4"},
    [pscustomobject]@{Name="PPRESORTLDS1AWS";IP="10.254.140.152"},
    [pscustomobject]@{Name="PFILEMIG2NYC";IP="10.14.93.156"},
    [pscustomobject]@{Name="PSQLFS1AWS";IP="10.254.130.58"},
    [pscustomobject]@{Name="PWSUS1AWS";IP="10.254.128.52"},
    [pscustomobject]@{Name="PWSUS2AWS";IP="10.254.128.26"},
    [pscustomobject]@{Name="PSCHEDULER2AWS";IP="10.254.129.59"},
    [pscustomobject]@{Name="PKMS1AWS";IP="10.254.130.32"},
    [pscustomobject]@{Name="PPS1AWS";IP="10.254.130.50"}
)

$stamp = Get-Date -Format yyyyMMdd-HHmmss
$profileOut = Join-Path $OutputRoot "CM-16-PostJoinProfileScan-$stamp.csv"
$logonOut = Join-Path $OutputRoot "CM-16-RecentLogons-$stamp.csv"
$adminOut = Join-Path $OutputRoot "CM-16-LocalAdmins-$stamp.csv"
$summaryOut = Join-Path $OutputRoot "CM-16-PostJoinProfileSummary-$stamp.csv"

$remoteScan = {
    param([datetime]$CutoffTime)

    $computerName = $env:COMPUTERNAME
    $cs = Get-CimInstance Win32_ComputerSystem
    $secureChannel = try { Test-ComputerSecureChannel -ErrorAction Stop } catch { "FAILED: $($_.Exception.Message)" }

    $userProfileRows = @()
    $profiles = @(Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { $_.LocalPath -like "C:\Users\*" })
    foreach ($profile in $profiles) {
        $folderItem = Get-Item -LiteralPath $profile.LocalPath -Force -ErrorAction SilentlyContinue
        $leaf = Split-Path $profile.LocalPath -Leaf
        $isSystemSid = $profile.SID -in @("S-1-5-18","S-1-5-19","S-1-5-20")
        $isDefaultProfile = $leaf -in @("Default","Default User","Public","All Users","desktop.ini")
        $isMigrationAdminProfile = $leaf -like "*CM-MigrationAdmin*"
        $postCutoffFolder = $false
        if ($folderItem) {
            $postCutoffFolder = ($folderItem.CreationTime -ge $CutoffTime -or $folderItem.LastWriteTime -ge $CutoffTime)
        }

        $userProfileRows += [pscustomobject]@{
            ComputerName = $computerName
            Domain = $cs.Domain
            PartOfDomain = $cs.PartOfDomain
            SecureChannel = $secureChannel
            SID = $profile.SID
            LocalPath = $profile.LocalPath
            FolderName = $leaf
            Loaded = $profile.Loaded
            Special = $profile.Special
            RoamingConfigured = $profile.RoamingConfigured
            LastUseTime = if ($profile.LastUseTime) { $profile.LastUseTime } else { "" }
            FolderCreationTime = if ($folderItem) { $folderItem.CreationTime } else { "" }
            FolderLastWriteTime = if ($folderItem) { $folderItem.LastWriteTime } else { "" }
            FolderLengthMB = try { [math]::Round(((Get-ChildItem -LiteralPath $profile.LocalPath -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum / 1MB),2) } catch { "" }
            IsSystemSid = $isSystemSid
            IsDefaultProfile = $isDefaultProfile
            IsMigrationAdminProfile = $isMigrationAdminProfile
            CreatedOrChangedAfterCutoff = $postCutoffFolder
            SuspiciousPostJoinProfile = (-not $isSystemSid -and -not $isDefaultProfile -and -not $isMigrationAdminProfile -and $postCutoffFolder)
        }
    }

    $logonRows = @()
    try {
        $events = @(Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4624; StartTime=$CutoffTime} -ErrorAction SilentlyContinue)
        foreach ($event in $events) {
            $xml = [xml]$event.ToXml()
            $data = @{}
            foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
            $logonType = $data["LogonType"]
            if ($logonType -in @("2","7","10","11")) {
                $logonRows += [pscustomobject]@{
                    ComputerName = $computerName
                    TimeCreated = $event.TimeCreated
                    LogonType = $logonType
                    TargetDomainName = $data["TargetDomainName"]
                    TargetUserName = $data["TargetUserName"]
                    IpAddress = $data["IpAddress"]
                    WorkstationName = $data["WorkstationName"]
                    AuthenticationPackageName = $data["AuthenticationPackageName"]
                    LogonProcessName = $data["LogonProcessName"]
                }
            }
        }
    }
    catch {
        $logonRows += [pscustomobject]@{
            ComputerName = $computerName
            TimeCreated = ""
            LogonType = ""
            TargetDomainName = ""
            TargetUserName = ""
            IpAddress = ""
            WorkstationName = ""
            AuthenticationPackageName = ""
            LogonProcessName = "FAILED: $($_.Exception.Message)"
        }
    }

    $adminRows = @()
    try {
        $admins = @(Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop)
        foreach ($admin in $admins) {
            $adminRows += [pscustomobject]@{
                ComputerName = $computerName
                AdminName = $admin.Name
                ObjectClass = $admin.ObjectClass
                PrincipalSource = $admin.PrincipalSource
            }
        }
    }
    catch {
        $adminRows += [pscustomobject]@{
            ComputerName = $computerName
            AdminName = "FAILED: $($_.Exception.Message)"
            ObjectClass = ""
            PrincipalSource = ""
        }
    }

    $summary = [pscustomobject]@{
        ComputerName = $computerName
        Domain = $cs.Domain
        PartOfDomain = $cs.PartOfDomain
        SecureChannel = $secureChannel
        ProfileCount = $userProfileRows.Count
        SuspiciousPostJoinProfileCount = @($userProfileRows | Where-Object { $_.SuspiciousPostJoinProfile -eq $true }).Count
        RecentInteractiveLogonCount = @($logonRows).Count
    }

    [pscustomobject]@{
        Summary = $summary
        Profiles = $userProfileRows
        Logons = $logonRows
        Admins = $adminRows
    }
}

$allProfiles = @()
$allLogons = @()
$allAdmins = @()
$allSummary = @()

foreach ($target in $targets) {
    Write-Host "Scanning $($target.Name) [$($target.IP)] ..." -ForegroundColor Cyan

    $result = $null
    $accessUsed = ""

    try {
        $result = Invoke-Command -ComputerName $target.IP -Credential $targetCred -Authentication Negotiate -ArgumentList $CutoffTime -ScriptBlock $remoteScan -ErrorAction Stop
        $accessUsed = "TargetDirectoryAdmin"
    }
    catch {
        Write-Host "TargetDirectoryAdmin failed on $($target.Name): $($_.Exception.Message)" -ForegroundColor Yellow
        try {
            $endpointCred = [pscredential]::new("$($target.Name)\$localUserOnly", $localCredBase.Password)
            $result = Invoke-Command -ComputerName $target.IP -Credential $endpointCred -Authentication Negotiate -ArgumentList $CutoffTime -ScriptBlock $remoteScan -ErrorAction Stop
            $accessUsed = "LocalAdmin"
        }
        catch {
            $allSummary += [pscustomobject]@{
                ComputerName = $target.Name
                Domain = ""
                PartOfDomain = ""
                SecureChannel = ""
                ProfileCount = ""
                SuspiciousPostJoinProfileCount = ""
                RecentInteractiveLogonCount = ""
                AccessUsed = "Failed"
                Error = $_.Exception.Message
            }
            continue
        }
    }

    foreach ($row in @($result.Summary)) {
        $allSummary += [pscustomobject]@{
            ComputerName = $row.ComputerName
            Domain = $row.Domain
            PartOfDomain = $row.PartOfDomain
            SecureChannel = $row.SecureChannel
            ProfileCount = $row.ProfileCount
            SuspiciousPostJoinProfileCount = $row.SuspiciousPostJoinProfileCount
            RecentInteractiveLogonCount = $row.RecentInteractiveLogonCount
            AccessUsed = $accessUsed
            Error = ""
        }
    }

    $allProfiles += @($result.Profiles)
    $allLogons += @($result.Logons)
    $allAdmins += @($result.Admins)
}

$allProfiles | Export-Csv -Path $profileOut -NoTypeInformation -Encoding UTF8
$allLogons | Export-Csv -Path $logonOut -NoTypeInformation -Encoding UTF8
$allAdmins | Export-Csv -Path $adminOut -NoTypeInformation -Encoding UTF8
$allSummary | Export-Csv -Path $summaryOut -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "Profile scan written to: $profileOut" -ForegroundColor Green
Write-Host "Recent logons written to: $logonOut" -ForegroundColor Green
Write-Host "Local admins written to: $adminOut" -ForegroundColor Green
Write-Host "Summary written to: $summaryOut" -ForegroundColor Green
Write-Host ""

$allSummary | Format-Table -AutoSize
Write-Host ""
$allProfiles | Where-Object { $_.SuspiciousPostJoinProfile -eq $true } | Select-Object ComputerName,FolderName,SID,LocalPath,Loaded,LastUseTime,FolderCreationTime,FolderLastWriteTime,FolderLengthMB | Format-Table -AutoSize
'@ | Set-Content -Path $scriptPath -Encoding UTF8; Write-Host "Created $scriptPath"
