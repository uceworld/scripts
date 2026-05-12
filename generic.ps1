$scriptPath = "C:\AD-MigrationSuite\Tools\Compare-PPRESORT1AWSDeepEvidence-WorkflowCreds.ps1"
$text = Get-Content -Path $scriptPath -Raw
$text = $text -replace "`r`n","`n"

function Set-ExactPatch {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$OldText,
        [Parameter(Mandatory)][string]$NewText,
        [Parameter(Mandatory)][string]$PatchName
    )

    if (-not $Text.Contains($OldText)) {
        throw "Patch anchor not found: $PatchName"
    }

    return $Text.Replace($OldText,$NewText)
}

$text = Set-ExactPatch -Text $text -PatchName "Add remote progress helper" -OldText @'
            New-Item -Path $remoteRoot -ItemType Directory -Force | Out-Null

            $scanErrors = New-Object System.Collections.Generic.List[object]
'@ -NewText @'
            New-Item -Path $remoteRoot -ItemType Directory -Force | Out-Null

            function Write-RemoteScanStatus {
                param([Parameter(Mandatory)][string]$Message)
                $remoteTimestamp = Get-Date -Format s
                Write-Host ("{0} [REMOTE:{1}] {2}" -f $remoteTimestamp, $EndpointLabel, $Message) -ForegroundColor Cyan
            }

            Write-RemoteScanStatus -Message "Remote evidence folder prepared: $remoteRoot"

            $scanErrors = New-Object System.Collections.Generic.List[object]
'@

$text = Set-ExactPatch -Text $text -PatchName "Add local remote scan status before Invoke-Command" -OldText @'
    try {
        $remoteResult = Invoke-Command -Session $session -ArgumentList $Label,$ComputerIp,$RunId,$MaxHashMB,$IncludeAllUserProfileMetadata -ScriptBlock {
'@ -NewText @'
    try {
        Write-StatusLine -Message "Remote scan started for $Label. Expect live remote phase messages until the endpoint archive is ready."
        $remoteResult = Invoke-Command -Session $session -ArgumentList $Label,$ComputerIp,$RunId,$MaxHashMB,$IncludeAllUserProfileMetadata -ScriptBlock {
'@

$text = Set-ExactPatch -Text $text -PatchName "Add identity scan phase status" -OldText @'
            $computerSystem = Get-CimInstance Win32_ComputerSystem
            $operatingSystem = Get-CimInstance Win32_OperatingSystem
            $script:computerDomain = [string]$computerSystem.Domain
'@ -NewText @'
            Write-RemoteScanStatus -Message "Collecting identity, network, profile registry, and profile folder evidence"
            $computerSystem = Get-CimInstance Win32_ComputerSystem
            $operatingSystem = Get-CimInstance Win32_OperatingSystem
            $script:computerDomain = [string]$computerSystem.Domain
'@

$text = Set-ExactPatch -Text $text -PatchName "Fix inline if in profile registry rows" -OldText @'
            $profileRegistryRows = @(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" -ErrorAction SilentlyContinue | ForEach-Object {
                $profilePath = [string]$_.ProfileImagePath
                [pscustomobject]@{
'@ -NewText @'
            $profileRegistryRows = @(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" -ErrorAction SilentlyContinue | ForEach-Object {
                $profilePath = [string]$_.ProfileImagePath
                $profileLeafName = ""
                if (-not [string]::IsNullOrWhiteSpace($profilePath)) { $profileLeafName = Split-Path -Path $profilePath -Leaf }
                [pscustomobject]@{
'@

$text = Set-ExactPatch -Text $text -PatchName "Use precomputed profile leaf name" -OldText @'
                    ProfileImagePath = $profilePath
                    ProfileLeafName = if ([string]::IsNullOrWhiteSpace($profilePath)) { "" } else { Split-Path -Path $profilePath -Leaf }
                    State = $_.State
'@ -NewText @'
                    ProfileImagePath = $profilePath
                    ProfileLeafName = $profileLeafName
                    State = $_.State
'@

$text = Set-ExactPatch -Text $text -PatchName "Fix inline try in profile folder rows" -OldText @'
            $profileFolderRows = @(Get-ChildDirectoriesSafe -RootPath "C:\Users" | ForEach-Object {
                $desktopPath = Join-Path $_.FullName "Desktop"
                $documentsPath = Join-Path $_.FullName "Documents"
                $downloadsPath = Join-Path $_.FullName "Downloads"
                $startMenuPath = Join-Path $_.FullName "AppData\Roaming\Microsoft\Windows\Start Menu"
                [pscustomobject]@{
'@ -NewText @'
            $profileFolderRows = @(Get-ChildDirectoriesSafe -RootPath "C:\Users" | ForEach-Object {
                $desktopPath = Join-Path $_.FullName "Desktop"
                $documentsPath = Join-Path $_.FullName "Documents"
                $downloadsPath = Join-Path $_.FullName "Downloads"
                $startMenuPath = Join-Path $_.FullName "AppData\Roaming\Microsoft\Windows\Start Menu"
                $folderOwner = "AclReadError"
                try { $folderOwner = (Get-Acl -LiteralPath $_.FullName -ErrorAction Stop).Owner } catch { $folderOwner = "AclReadError" }
                [pscustomobject]@{
'@

$text = Set-ExactPatch -Text $text -PatchName "Use precomputed folder owner" -OldText @'
                    LastWriteTimeUtc = $_.LastWriteTimeUtc.ToString("o")
                    Owner = try { (Get-Acl -LiteralPath $_.FullName -ErrorAction Stop).Owner } catch { "AclReadError" }
                }
'@ -NewText @'
                    LastWriteTimeUtc = $_.LastWriteTimeUtc.ToString("o")
                    Owner = $folderOwner
                }
'@

$text = Set-ExactPatch -Text $text -PatchName "Add public and user folder progress" -OldText @'
            foreach ($rootPath in $publicShortcutRoots) {
                (Get-FilesFromRoot -RootPath $rootPath -Category "ShortcutSurface" -IncludeExtensions $shortcutExtensions -MaxHashMegabytes $EndpointMaxHashMB) | ForEach-Object { $shortcutRows.Add($_) }
                (Get-FilesFromRoot -RootPath $rootPath -Category "VisibleSurface" -IncludeExtensions @() -MaxHashMegabytes $EndpointMaxHashMB) | ForEach-Object { $visibleFileRows.Add($_) }
            }

            $userFolders = @(Get-ChildDirectoriesSafe -RootPath "C:\Users" | Where-Object { $_.Name -notin @("All Users","Default User") })
            foreach ($userFolder in $userFolders) {
'@ -NewText @'
            Write-RemoteScanStatus -Message "Scanning public Desktop and ProgramData Start Menu shortcut surfaces"
            foreach ($rootPath in $publicShortcutRoots) {
                Write-RemoteScanStatus -Message ("Scanning public surface: {0}" -f $rootPath)
                (Get-FilesFromRoot -RootPath $rootPath -Category "ShortcutSurface" -IncludeExtensions $shortcutExtensions -MaxHashMegabytes $EndpointMaxHashMB) | ForEach-Object { $shortcutRows.Add($_) }
                (Get-FilesFromRoot -RootPath $rootPath -Category "VisibleSurface" -IncludeExtensions @() -MaxHashMegabytes $EndpointMaxHashMB) | ForEach-Object { $visibleFileRows.Add($_) }
            }

            $userFolders = @(Get-ChildDirectoriesSafe -RootPath "C:\Users" | Where-Object { $_.Name -notin @("All Users","Default User") })
            Write-RemoteScanStatus -Message ("Scanning user-visible profile surfaces under C:\Users. Profile folder count: {0}" -f @($userFolders).Count)
            foreach ($userFolder in $userFolders) {
                Write-RemoteScanStatus -Message ("Scanning user folder: {0}" -f $userFolder.FullName)
'@

$text = Set-ExactPatch -Text $text -PatchName "Add quarantine progress and CSV export progress" -OldText @'
            $quarantineRoot = "C:\ADMS-ProfileQuarantine\Wave-002-PostJoin-DuplicateProfiles\PPRESORT1AWS"
            if (Test-Path -LiteralPath $quarantineRoot) {
                (Get-FilesFromRoot -RootPath $quarantineRoot -Category "QuarantineSurface" -IncludeExtensions @() -MaxHashMegabytes $EndpointMaxHashMB) | ForEach-Object { $quarantineRows.Add($_) }
            }

            $identityRows | Export-Csv -Path (Join-Path $remoteRoot "identity.csv") -NoTypeInformation -Encoding UTF8
'@ -NewText @'
            $quarantineRoot = "C:\ADMS-ProfileQuarantine\Wave-002-PostJoin-DuplicateProfiles\PPRESORT1AWS"
            Write-RemoteScanStatus -Message "Scanning ADMS duplicate-profile quarantine folder if present"
            if (Test-Path -LiteralPath $quarantineRoot) {
                Write-RemoteScanStatus -Message "Quarantine folder found; scanning preserved duplicate-profile evidence"
                (Get-FilesFromRoot -RootPath $quarantineRoot -Category "QuarantineSurface" -IncludeExtensions @() -MaxHashMegabytes $EndpointMaxHashMB) | ForEach-Object { $quarantineRows.Add($_) }
            }
            else {
                Write-RemoteScanStatus -Message "Quarantine folder not present on this endpoint"
            }

            Write-RemoteScanStatus -Message "Writing remote CSV evidence files"
            $identityRows | Export-Csv -Path (Join-Path $remoteRoot "identity.csv") -NoTypeInformation -Encoding UTF8
'@

$text = Set-ExactPatch -Text $text -PatchName "Add archive progress" -OldText @'
            Compress-Archive -Path (Join-Path $remoteRoot "*") -DestinationPath $archivePath -Force
            return [pscustomobject]@{
'@ -NewText @'
            Write-RemoteScanStatus -Message "Compressing remote evidence archive"
            Compress-Archive -Path (Join-Path $remoteRoot "*") -DestinationPath $archivePath -Force
            Write-RemoteScanStatus -Message "Remote endpoint scan complete"
            return [pscustomobject]@{
'@

$parseTokens = $null
$parseErrors = $null
[System.Management.Automation.Language.Parser]::ParseInput($text,[ref]$parseTokens,[ref]$parseErrors) | Out-Null
if ($parseErrors -and $parseErrors.Count -gt 0) { $parseErrors | Format-List; throw "Patched script failed syntax validation; original file was not overwritten." }

Set-Content -Path $scriptPath -Value ($text -replace "`n","`r`n") -Encoding UTF8
Write-Host "Patch complete and syntax validated: $scriptPath" -ForegroundColor Green
