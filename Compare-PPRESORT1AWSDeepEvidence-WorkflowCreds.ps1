[CmdletBinding()]
param(
    [string]$MigratedIp = "10.254.140.161",
    [string]$SnapshotIp = "10.254.140.4",
    [string]$ConfigPath = "C:\AD-MigrationSuite\Computer-Migration\Config\MigrationAutomationConfig.json",
    [string]$TargetCredentialPath = "",
    [string]$SourceCredentialPath = "",
    [string]$OutputRoot = "C:\AD-MigrationSuite\Evidence\PPRESORT1AWS-DeepCompare",
    [int]$MaxHashMB = 25,
    [switch]$IncludeAllUserProfileMetadata,
    [switch]$KeepRemoteTemp,
    [switch]$PromptForCredentials
)

$ErrorActionPreference = "Stop"

function New-LocalEvidenceRoot {
    param([Parameter(Mandatory)][string]$Root)
    $runId = Get-Date -Format "yyyyMMdd-HHmmss"
    $path = Join-Path $Root $runId
    New-Item -Path $path -ItemType Directory -Force | Out-Null
    return [pscustomobject]@{ RunId = $runId; Path = $path }
}

function Write-StatusLine {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("INFO","WARN","ERROR","SUCCESS")][string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format s
    $text = "{0} [{1}] {2}" -f $timestamp, $Level, $Message
    if ($Level -eq "ERROR") { Write-Host $text -ForegroundColor Red; return }
    if ($Level -eq "WARN") { Write-Host $text -ForegroundColor Yellow; return }
    if ($Level -eq "SUCCESS") { Write-Host $text -ForegroundColor Green; return }
    Write-Host $text
}

function Assert-WsManReady {
    param([Parameter(Mandatory)][string]$ComputerIp)
    try {
        Test-WSMan -ComputerName $ComputerIp -ErrorAction Stop | Out-Null
        Write-StatusLine -Level SUCCESS -Message "WinRM reachable on $ComputerIp"
    }
    catch {
        throw "WinRM is not reachable on $ComputerIp. Confirm firewall, TrustedHosts, AWS security group, and TCP 5985 from the Jumpbox. Error: $($_.Exception.Message)"
    }
}

function Resolve-WorkflowCredentialPaths {
    param(
        [Parameter(Mandatory)][string]$ResolvedConfigPath,
        [string]$ExplicitTargetCredentialPath,
        [string]$ExplicitSourceCredentialPath
    )

    if (-not (Test-Path -LiteralPath $ResolvedConfigPath)) {
        throw "Config file not found: $ResolvedConfigPath"
    }

    $config = Get-Content -Path $ResolvedConfigPath -Raw | ConvertFrom-Json
    if (-not $config.CredentialFiles) {
        throw "CredentialFiles node is missing from config: $ResolvedConfigPath"
    }

    $targetPath = $ExplicitTargetCredentialPath
    if ([string]::IsNullOrWhiteSpace($targetPath)) {
        if ($config.CredentialFiles.TargetDirectoryAdmin) { $targetPath = [string]$config.CredentialFiles.TargetDirectoryAdmin }
        elseif ($config.CredentialFiles.TargetJoin) { $targetPath = [string]$config.CredentialFiles.TargetJoin }
    }

    $sourcePath = $ExplicitSourceCredentialPath
    if ([string]::IsNullOrWhiteSpace($sourcePath)) {
        if ($config.CredentialFiles.SourceUnjoin) { $sourcePath = [string]$config.CredentialFiles.SourceUnjoin }
        elseif ($config.CredentialFiles.SourceDirectoryRead) { $sourcePath = [string]$config.CredentialFiles.SourceDirectoryRead }
        elseif ($config.CredentialFiles.SourceJoin) { $sourcePath = [string]$config.CredentialFiles.SourceJoin }
    }

    if ([string]::IsNullOrWhiteSpace($targetPath)) {
        throw "Unable to resolve target credential path. Expected CredentialFiles.TargetDirectoryAdmin or CredentialFiles.TargetJoin in $ResolvedConfigPath, or pass -TargetCredentialPath."
    }

    if ([string]::IsNullOrWhiteSpace($sourcePath)) {
        throw "Unable to resolve source credential path. Expected CredentialFiles.SourceUnjoin, CredentialFiles.SourceDirectoryRead, or CredentialFiles.SourceJoin in $ResolvedConfigPath, or pass -SourceCredentialPath."
    }

    return [pscustomobject]@{
        TargetCredentialPath = $targetPath
        SourceCredentialPath = $sourcePath
    }
}

function Import-WorkflowCredential {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "$Description credential file not found: $Path"
    }

    try {
        $credential = Import-Clixml -Path $Path
    }
    catch {
        throw "Failed to import $Description credential from $Path. The CLIXML must be decrypted by the same user/machine context that can use the workflow credentials. Error: $($_.Exception.Message)"
    }

    if ($null -eq $credential -or $credential.GetType().FullName -ne "System.Management.Automation.PSCredential") {
        throw "$Description credential file did not return a PSCredential object: $Path"
    }

    Write-StatusLine -Level SUCCESS -Message "Imported $Description credential from $Path"
    return $credential
}

function Invoke-EndpointScan {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$ComputerIp,
        [Parameter(Mandatory)][pscredential]$Credential,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$EvidenceRoot,
        [Parameter(Mandatory)][int]$MaxHashMB,
        [Parameter(Mandatory)][bool]$IncludeAllUserProfileMetadata,
        [Parameter(Mandatory)][bool]$KeepRemoteTemp
    )

    Write-StatusLine -Message "Opening PowerShell remoting session to $Label at $ComputerIp"
    $session = New-PSSession -ComputerName $ComputerIp -Credential $Credential -Authentication Negotiate

    try {
        $remoteResult = Invoke-Command -Session $session -ArgumentList $Label,$ComputerIp,$RunId,$MaxHashMB,$IncludeAllUserProfileMetadata -ScriptBlock {
            param(
                [string]$EndpointLabel,
                [string]$EndpointIp,
                [string]$EndpointRunId,
                [int]$EndpointMaxHashMB,
                [bool]$EndpointIncludeAllUserProfileMetadata
            )

            $ErrorActionPreference = "Stop"
            $safeLabel = $EndpointLabel -replace '[^A-Za-z0-9_.-]', '_'
            $remoteRoot = Join-Path $env:TEMP ("ADMS-DeepCompare-{0}-{1}" -f $EndpointRunId, $safeLabel)
            $archivePath = "$remoteRoot.zip"
            if (Test-Path -LiteralPath $remoteRoot) { Remove-Item -LiteralPath $remoteRoot -Recurse -Force -ErrorAction SilentlyContinue }
            if (Test-Path -LiteralPath $archivePath) { Remove-Item -LiteralPath $archivePath -Force -ErrorAction SilentlyContinue }
            New-Item -Path $remoteRoot -ItemType Directory -Force | Out-Null

            $scanErrors = New-Object System.Collections.Generic.List[object]

            function Add-ScanError {
                param(
                    [string]$Scope,
                    [string]$Path,
                    [string]$Message
                )
                $script:scanErrors.Add([pscustomobject]@{
                    EndpointLabel = $EndpointLabel
                    EndpointIp = $EndpointIp
                    ComputerName = $env:COMPUTERNAME
                    Scope = $Scope
                    Path = $Path
                    Message = $Message
                    CapturedUtc = (Get-Date).ToUniversalTime().ToString("o")
                })
            }

            function Get-NormalizedEvidenceKey {
                param([string]$Path)
                if ([string]::IsNullOrWhiteSpace($Path)) { return "" }
                $normalized = $Path.Trim() -replace '/', '\'
                $normalized = $normalized -replace '^[A-Za-z]:\\', ''
                return $normalized
            }

            function Get-SafeFileHash {
                param(
                    [string]$Path,
                    [long]$Length,
                    [int]$MaxHashMegabytes
                )
                try {
                    if ($Length -lt 0) { return "" }
                    $maxBytes = [int64]$MaxHashMegabytes * 1024 * 1024
                    if ($Length -le $maxBytes) {
                        return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
                    }
                    return "SkippedOverMaxHashMB"
                }
                catch {
                    Add-ScanError -Scope "Hash" -Path $Path -Message $_.Exception.Message
                    return "HashError"
                }
            }

            function Get-ShortcutInfo {
                param([string]$Path)
                $targetPath = ""
                $arguments = ""
                $workingDirectory = ""
                $iconLocation = ""
                try {
                    $shellObject = New-Object -ComObject WScript.Shell
                    $shortcutObject = $shellObject.CreateShortcut($Path)
                    $targetPath = [string]$shortcutObject.TargetPath
                    $arguments = [string]$shortcutObject.Arguments
                    $workingDirectory = [string]$shortcutObject.WorkingDirectory
                    $iconLocation = [string]$shortcutObject.IconLocation
                }
                catch {
                    Add-ScanError -Scope "ShortcutRead" -Path $Path -Message $_.Exception.Message
                }
                finally {
                    if ($null -ne $shortcutObject) { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($shortcutObject) }
                    if ($null -ne $shellObject) { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($shellObject) }
                }
                return [pscustomobject]@{
                    TargetPath = $targetPath
                    Arguments = $arguments
                    WorkingDirectory = $workingDirectory
                    IconLocation = $iconLocation
                }
            }

            function New-InventoryRow {
                param(
                    [System.IO.FileInfo]$File,
                    [string]$Category,
                    [string]$SourceRoot,
                    [int]$MaxHashMegabytes
                )
                $shortcutExtensions = @(".lnk", ".url", ".rdp", ".ica")
                $shortcut = [pscustomobject]@{ TargetPath = ""; Arguments = ""; WorkingDirectory = ""; IconLocation = "" }
                if ($shortcutExtensions -contains $File.Extension.ToLowerInvariant()) {
                    $shortcut = Get-ShortcutInfo -Path $File.FullName
                }
                $fileHash = Get-SafeFileHash -Path $File.FullName -Length $File.Length -MaxHashMegabytes $MaxHashMegabytes
                $shortcutKey = ""
                if (-not [string]::IsNullOrWhiteSpace($shortcut.TargetPath)) {
                    $shortcutKey = (([string]$File.Name) + "|" + ([string]$shortcut.TargetPath) + "|" + ([string]$shortcut.Arguments)).ToLowerInvariant()
                }
                $contentKey = (([string]$File.Name) + "|" + ([string]$File.Length) + "|" + ([string]$fileHash)).ToLowerInvariant()
                return [pscustomobject]@{
                    EndpointLabel = $EndpointLabel
                    EndpointIp = $EndpointIp
                    ComputerName = $env:COMPUTERNAME
                    Domain = $script:computerDomain
                    Category = $Category
                    SourceRoot = $SourceRoot
                    EvidenceKey = Get-NormalizedEvidenceKey -Path $File.FullName
                    FullName = $File.FullName
                    Name = $File.Name
                    Extension = $File.Extension
                    Length = $File.Length
                    CreationTimeUtc = $File.CreationTimeUtc.ToString("o")
                    LastWriteTimeUtc = $File.LastWriteTimeUtc.ToString("o")
                    Hash = $fileHash
                    ShortcutTargetPath = $shortcut.TargetPath
                    ShortcutArguments = $shortcut.Arguments
                    ShortcutWorkingDirectory = $shortcut.WorkingDirectory
                    ShortcutIconLocation = $shortcut.IconLocation
                    ShortcutNameTargetKey = $shortcutKey
                    ContentNameHashKey = $contentKey
                }
            }

            function Get-FilesFromRoot {
                param(
                    [string]$RootPath,
                    [string]$Category,
                    [string[]]$IncludeExtensions,
                    [int]$MaxHashMegabytes
                )
                $rows = New-Object System.Collections.Generic.List[object]
                if (-not (Test-Path -LiteralPath $RootPath)) { return $rows }
                try {
                    Get-ChildItem -LiteralPath $RootPath -Recurse -Force -File -ErrorAction SilentlyContinue | ForEach-Object {
                        try {
                            $includeFile = $true
                            if ($IncludeExtensions.Count -gt 0) {
                                $includeFile = $IncludeExtensions -contains $_.Extension.ToLowerInvariant()
                            }
                            if ($includeFile) {
                                $rows.Add((New-InventoryRow -File $_ -Category $Category -SourceRoot $RootPath -MaxHashMegabytes $MaxHashMegabytes))
                            }
                        }
                        catch {
                            Add-ScanError -Scope $Category -Path $_.FullName -Message $_.Exception.Message
                        }
                    }
                }
                catch {
                    Add-ScanError -Scope $Category -Path $RootPath -Message $_.Exception.Message
                }
                return $rows
            }

            function Get-ChildDirectoriesSafe {
                param([string]$RootPath)
                try {
                    if (Test-Path -LiteralPath $RootPath) {
                        return @(Get-ChildItem -LiteralPath $RootPath -Force -Directory -ErrorAction SilentlyContinue)
                    }
                }
                catch {
                    Add-ScanError -Scope "DirectoryList" -Path $RootPath -Message $_.Exception.Message
                }
                return @()
            }

            $computerSystem = Get-CimInstance Win32_ComputerSystem
            $operatingSystem = Get-CimInstance Win32_OperatingSystem
            $script:computerDomain = [string]$computerSystem.Domain

            $identityRows = @([pscustomobject]@{
                EndpointLabel = $EndpointLabel
                EndpointIp = $EndpointIp
                ComputerName = $env:COMPUTERNAME
                Domain = $computerSystem.Domain
                PartOfDomain = $computerSystem.PartOfDomain
                Manufacturer = $computerSystem.Manufacturer
                Model = $computerSystem.Model
                OSCaption = $operatingSystem.Caption
                OSVersion = $operatingSystem.Version
                BuildNumber = $operatingSystem.BuildNumber
                InstallDate = $operatingSystem.InstallDate
                LastBootUpTime = $operatingSystem.LastBootUpTime
                ScanUtc = (Get-Date).ToUniversalTime().ToString("o")
            })

            $networkRows = @(Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true } | ForEach-Object {
                [pscustomobject]@{
                    EndpointLabel = $EndpointLabel
                    EndpointIp = $EndpointIp
                    ComputerName = $env:COMPUTERNAME
                    Description = $_.Description
                    DHCPEnabled = $_.DHCPEnabled
                    IPAddress = ($_.IPAddress -join ";")
                    IPSubnet = ($_.IPSubnet -join ";")
                    DefaultIPGateway = ($_.DefaultIPGateway -join ";")
                    DNSServerSearchOrder = ($_.DNSServerSearchOrder -join ";")
                    DNSDomain = $_.DNSDomain
                    MACAddress = $_.MACAddress
                }
            })

            $profileRegistryRows = @(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" -ErrorAction SilentlyContinue | ForEach-Object {
                $profilePath = [string]$_.ProfileImagePath
                [pscustomobject]@{
                    EndpointLabel = $EndpointLabel
                    EndpointIp = $EndpointIp
                    ComputerName = $env:COMPUTERNAME
                    Domain = $computerSystem.Domain
                    Sid = $_.PSChildName
                    ProfileImagePath = $profilePath
                    ProfileLeafName = if ([string]::IsNullOrWhiteSpace($profilePath)) { "" } else { Split-Path -Path $profilePath -Leaf }
                    State = $_.State
                    RefCount = $_.RefCount
                    Flags = $_.Flags
                    RunLogonScriptSync = $_.RunLogonScriptSync
                    CentralProfile = $_.CentralProfile
                    LocalProfileLoadTimeLow = $_.LocalProfileLoadTimeLow
                    LocalProfileLoadTimeHigh = $_.LocalProfileLoadTimeHigh
                }
            })

            $profileFolderRows = @(Get-ChildDirectoriesSafe -RootPath "C:\Users" | ForEach-Object {
                $desktopPath = Join-Path $_.FullName "Desktop"
                $documentsPath = Join-Path $_.FullName "Documents"
                $downloadsPath = Join-Path $_.FullName "Downloads"
                $startMenuPath = Join-Path $_.FullName "AppData\Roaming\Microsoft\Windows\Start Menu"
                [pscustomobject]@{
                    EndpointLabel = $EndpointLabel
                    EndpointIp = $EndpointIp
                    ComputerName = $env:COMPUTERNAME
                    Domain = $computerSystem.Domain
                    FolderName = $_.Name
                    FullName = $_.FullName
                    EvidenceKey = Get-NormalizedEvidenceKey -Path $_.FullName
                    NtUserDatExists = Test-Path -LiteralPath (Join-Path $_.FullName "NTUSER.DAT")
                    DesktopExists = Test-Path -LiteralPath $desktopPath
                    DocumentsExists = Test-Path -LiteralPath $documentsPath
                    DownloadsExists = Test-Path -LiteralPath $downloadsPath
                    StartMenuExists = Test-Path -LiteralPath $startMenuPath
                    DesktopShortcutCount = @(Get-ChildItem -LiteralPath $desktopPath -Recurse -Force -File -Filter "*.lnk" -ErrorAction SilentlyContinue).Count
                    StartMenuShortcutCount = @(Get-ChildItem -LiteralPath $startMenuPath -Recurse -Force -File -Filter "*.lnk" -ErrorAction SilentlyContinue).Count
                    LastWriteTimeUtc = $_.LastWriteTimeUtc.ToString("o")
                    Owner = try { (Get-Acl -LiteralPath $_.FullName -ErrorAction Stop).Owner } catch { "AclReadError" }
                }
            })

            $shortcutExtensions = @(".lnk", ".url", ".rdp", ".ica")
            $shortcutRows = New-Object System.Collections.Generic.List[object]
            $visibleFileRows = New-Object System.Collections.Generic.List[object]
            $quarantineRows = New-Object System.Collections.Generic.List[object]
            $allUserMetadataRows = New-Object System.Collections.Generic.List[object]

            $publicShortcutRoots = @(
                "C:\Users\Public\Desktop",
                "C:\ProgramData\Microsoft\Windows\Start Menu",
                "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
            )

            foreach ($rootPath in $publicShortcutRoots) {
                (Get-FilesFromRoot -RootPath $rootPath -Category "ShortcutSurface" -IncludeExtensions $shortcutExtensions -MaxHashMegabytes $EndpointMaxHashMB) | ForEach-Object { $shortcutRows.Add($_) }
                (Get-FilesFromRoot -RootPath $rootPath -Category "VisibleSurface" -IncludeExtensions @() -MaxHashMegabytes $EndpointMaxHashMB) | ForEach-Object { $visibleFileRows.Add($_) }
            }

            $userFolders = @(Get-ChildDirectoriesSafe -RootPath "C:\Users" | Where-Object { $_.Name -notin @("All Users","Default User") })
            foreach ($userFolder in $userFolders) {
                $userVisibleRoots = @(
                    (Join-Path $userFolder.FullName "Desktop"),
                    (Join-Path $userFolder.FullName "Documents"),
                    (Join-Path $userFolder.FullName "Downloads"),
                    (Join-Path $userFolder.FullName "Favorites"),
                    (Join-Path $userFolder.FullName "Pictures"),
                    (Join-Path $userFolder.FullName "Music"),
                    (Join-Path $userFolder.FullName "Videos"),
                    (Join-Path $userFolder.FullName "AppData\Roaming\Microsoft\Windows\Start Menu"),
                    (Join-Path $userFolder.FullName "AppData\Roaming\Microsoft\Internet Explorer\Quick Launch"),
                    (Join-Path $userFolder.FullName "AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned"),
                    (Join-Path $userFolder.FullName "AppData\Roaming\Microsoft\Windows\Network Shortcuts"),
                    (Join-Path $userFolder.FullName "AppData\Roaming\Microsoft\Windows\Printer Shortcuts")
                )

                $oneDriveFolders = @(Get-ChildDirectoriesSafe -RootPath $userFolder.FullName | Where-Object { $_.Name -like "OneDrive*" })
                foreach ($oneDriveFolder in $oneDriveFolders) { $userVisibleRoots += $oneDriveFolder.FullName }

                foreach ($rootPath in ($userVisibleRoots | Sort-Object -Unique)) {
                    (Get-FilesFromRoot -RootPath $rootPath -Category "ShortcutSurface" -IncludeExtensions $shortcutExtensions -MaxHashMegabytes $EndpointMaxHashMB) | ForEach-Object { $shortcutRows.Add($_) }
                    (Get-FilesFromRoot -RootPath $rootPath -Category "VisibleSurface" -IncludeExtensions @() -MaxHashMegabytes $EndpointMaxHashMB) | ForEach-Object { $visibleFileRows.Add($_) }
                }

                if ($EndpointIncludeAllUserProfileMetadata) {
                    (Get-FilesFromRoot -RootPath $userFolder.FullName -Category "AllUserProfileMetadata" -IncludeExtensions @() -MaxHashMegabytes 0) | ForEach-Object { $allUserMetadataRows.Add($_) }
                }
            }

            $quarantineRoot = "C:\ADMS-ProfileQuarantine\Wave-002-PostJoin-DuplicateProfiles\PPRESORT1AWS"
            if (Test-Path -LiteralPath $quarantineRoot) {
                (Get-FilesFromRoot -RootPath $quarantineRoot -Category "QuarantineSurface" -IncludeExtensions @() -MaxHashMegabytes $EndpointMaxHashMB) | ForEach-Object { $quarantineRows.Add($_) }
            }

            $identityRows | Export-Csv -Path (Join-Path $remoteRoot "identity.csv") -NoTypeInformation -Encoding UTF8
            $networkRows | Export-Csv -Path (Join-Path $remoteRoot "network.csv") -NoTypeInformation -Encoding UTF8
            $profileRegistryRows | Export-Csv -Path (Join-Path $remoteRoot "profile-registry.csv") -NoTypeInformation -Encoding UTF8
            $profileFolderRows | Export-Csv -Path (Join-Path $remoteRoot "profile-folders.csv") -NoTypeInformation -Encoding UTF8
            $shortcutRows | Export-Csv -Path (Join-Path $remoteRoot "shortcuts.csv") -NoTypeInformation -Encoding UTF8
            $visibleFileRows | Export-Csv -Path (Join-Path $remoteRoot "visible-files.csv") -NoTypeInformation -Encoding UTF8
            $quarantineRows | Export-Csv -Path (Join-Path $remoteRoot "quarantine-files.csv") -NoTypeInformation -Encoding UTF8
            $allUserMetadataRows | Export-Csv -Path (Join-Path $remoteRoot "all-user-profile-metadata.csv") -NoTypeInformation -Encoding UTF8
            $scanErrors | Export-Csv -Path (Join-Path $remoteRoot "scan-errors.csv") -NoTypeInformation -Encoding UTF8

            $summaryRows = @(
                [pscustomobject]@{ EndpointLabel = $EndpointLabel; Metric = "ShortcutRows"; Value = @($shortcutRows).Count },
                [pscustomobject]@{ EndpointLabel = $EndpointLabel; Metric = "VisibleFileRows"; Value = @($visibleFileRows).Count },
                [pscustomobject]@{ EndpointLabel = $EndpointLabel; Metric = "QuarantineRows"; Value = @($quarantineRows).Count },
                [pscustomobject]@{ EndpointLabel = $EndpointLabel; Metric = "ProfileRegistryRows"; Value = @($profileRegistryRows).Count },
                [pscustomobject]@{ EndpointLabel = $EndpointLabel; Metric = "ProfileFolderRows"; Value = @($profileFolderRows).Count },
                [pscustomobject]@{ EndpointLabel = $EndpointLabel; Metric = "ScanErrorRows"; Value = @($scanErrors).Count }
            )
            $summaryRows | Export-Csv -Path (Join-Path $remoteRoot "scan-summary.csv") -NoTypeInformation -Encoding UTF8

            Compress-Archive -Path (Join-Path $remoteRoot "*") -DestinationPath $archivePath -Force
            return [pscustomobject]@{
                EndpointLabel = $EndpointLabel
                EndpointIp = $EndpointIp
                ComputerName = $env:COMPUTERNAME
                Domain = $computerSystem.Domain
                RemoteRoot = $remoteRoot
                ArchivePath = $archivePath
            }
        }

        $localEndpointRoot = Join-Path $EvidenceRoot $Label
        New-Item -Path $localEndpointRoot -ItemType Directory -Force | Out-Null
        $localArchive = Join-Path $localEndpointRoot ("{0}.zip" -f $Label)
        Write-StatusLine -Message "Copying evidence archive from $Label"
        Copy-Item -FromSession $session -Path $remoteResult.ArchivePath -Destination $localArchive -Force
        Expand-Archive -Path $localArchive -DestinationPath $localEndpointRoot -Force

        if (-not $KeepRemoteTemp) {
            Invoke-Command -Session $session -ArgumentList $remoteResult.RemoteRoot,$remoteResult.ArchivePath -ScriptBlock {
                param([string]$RemoteRootToRemove,[string]$ArchivePathToRemove)
                Remove-Item -LiteralPath $RemoteRootToRemove -Recurse -Force -ErrorAction SilentlyContinue
                Remove-Item -LiteralPath $ArchivePathToRemove -Force -ErrorAction SilentlyContinue
            }
        }

        return [pscustomobject]@{
            Label = $Label
            Ip = $ComputerIp
            ComputerName = $remoteResult.ComputerName
            Domain = $remoteResult.Domain
            LocalRoot = $localEndpointRoot
        }
    }
    finally {
        if ($null -ne $session) { Remove-PSSession $session }
    }
}

function Compare-InventoryByKey {
    param(
        [Parameter(Mandatory)][string]$LeftCsv,
        [Parameter(Mandatory)][string]$RightCsv,
        [Parameter(Mandatory)][string]$OutCsv,
        [Parameter(Mandatory)][string]$KeyColumn,
        [string[]]$CompareColumns = @("Hash","Length","ShortcutTargetPath","ShortcutArguments")
    )

    $leftRows = @()
    $rightRows = @()
    if (Test-Path -LiteralPath $LeftCsv) { $leftRows = @(Import-Csv -Path $LeftCsv) }
    if (Test-Path -LiteralPath $RightCsv) { $rightRows = @(Import-Csv -Path $RightCsv) }

    $leftMap = @{}
    foreach ($row in $leftRows) {
        $key = [string]$row.$KeyColumn
        if (-not [string]::IsNullOrWhiteSpace($key)) { $leftMap[$key.ToLowerInvariant()] = $row }
    }

    $rightMap = @{}
    foreach ($row in $rightRows) {
        $key = [string]$row.$KeyColumn
        if (-not [string]::IsNullOrWhiteSpace($key)) { $rightMap[$key.ToLowerInvariant()] = $row }
    }

    $allKeys = @($leftMap.Keys + $rightMap.Keys) | Sort-Object -Unique
    $diffRows = New-Object System.Collections.Generic.List[object]

    foreach ($key in $allKeys) {
        $leftExists = $leftMap.ContainsKey($key)
        $rightExists = $rightMap.ContainsKey($key)

        if (-not $leftExists -and $rightExists) {
            $right = $rightMap[$key]
            $diffRows.Add([pscustomobject]@{
                DifferenceType = "OnlyInSnapshot_Source"
                Key = $key
                MigratedPath = ""
                SnapshotPath = $right.FullName
                MigratedHash = ""
                SnapshotHash = $right.Hash
                MigratedLength = ""
                SnapshotLength = $right.Length
                MigratedTarget = ""
                SnapshotTarget = $right.ShortcutTargetPath
            })
            continue
        }

        if ($leftExists -and -not $rightExists) {
            $left = $leftMap[$key]
            $diffRows.Add([pscustomobject]@{
                DifferenceType = "OnlyInMigrated_Target"
                Key = $key
                MigratedPath = $left.FullName
                SnapshotPath = ""
                MigratedHash = $left.Hash
                SnapshotHash = ""
                MigratedLength = $left.Length
                SnapshotLength = ""
                MigratedTarget = $left.ShortcutTargetPath
                SnapshotTarget = ""
            })
            continue
        }

        $leftRow = $leftMap[$key]
        $rightRow = $rightMap[$key]
        $changedColumns = New-Object System.Collections.Generic.List[string]
        foreach ($columnName in $CompareColumns) {
            $leftValue = [string]$leftRow.$columnName
            $rightValue = [string]$rightRow.$columnName
            if ($leftValue -ne $rightValue) { $changedColumns.Add($columnName) }
        }

        if ($changedColumns.Count -gt 0) {
            $diffRows.Add([pscustomobject]@{
                DifferenceType = "DifferentMetadataOrTarget"
                Key = $key
                ChangedColumns = ($changedColumns -join ";")
                MigratedPath = $leftRow.FullName
                SnapshotPath = $rightRow.FullName
                MigratedHash = $leftRow.Hash
                SnapshotHash = $rightRow.Hash
                MigratedLength = $leftRow.Length
                SnapshotLength = $rightRow.Length
                MigratedTarget = $leftRow.ShortcutTargetPath
                SnapshotTarget = $rightRow.ShortcutTargetPath
            })
        }
    }

    $diffRows | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
    return @($diffRows).Count
}

$evidenceContext = New-LocalEvidenceRoot -Root $OutputRoot
$evidenceRoot = $evidenceContext.Path
$runId = $evidenceContext.RunId
$transcriptPath = Join-Path $evidenceRoot "console-transcript.txt"
Start-Transcript -Path $transcriptPath -Force | Out-Null

try {
    Write-StatusLine -Message "Evidence root: $evidenceRoot"
    Write-StatusLine -Message "Using IP-only targets to avoid hostname ambiguity: migrated=$MigratedIp snapshot=$SnapshotIp"

    Assert-WsManReady -ComputerIp $MigratedIp
    Assert-WsManReady -ComputerIp $SnapshotIp

    if ($PromptForCredentials.IsPresent) {
        Write-StatusLine -Level WARN -Message "PromptForCredentials was specified; using interactive credentials instead of workflow CLIXML files."
        $targetCredential = Get-Credential -Message "Target AD admin credential for migrated PPRESORT1AWS $MigratedIp in id.people.inc"
        $sourceCredential = Get-Credential -Message "Source AD admin credential for snapshot PPRESORT1AWS $SnapshotIp in ad.mdp.com"
    }
    else {
        Write-StatusLine -Message "Resolving workflow credentials from config: $ConfigPath"
        $credentialPaths = Resolve-WorkflowCredentialPaths -ResolvedConfigPath $ConfigPath -ExplicitTargetCredentialPath $TargetCredentialPath -ExplicitSourceCredentialPath $SourceCredentialPath
        $targetCredential = Import-WorkflowCredential -Path $credentialPaths.TargetCredentialPath -Description "target AD admin"
        $sourceCredential = Import-WorkflowCredential -Path $credentialPaths.SourceCredentialPath -Description "source AD admin"
    }

    $migrated = Invoke-EndpointScan -Label "Migrated_Target_10.254.140.161" -ComputerIp $MigratedIp -Credential $targetCredential -RunId $runId -EvidenceRoot $evidenceRoot -MaxHashMB $MaxHashMB -IncludeAllUserProfileMetadata ([bool]$IncludeAllUserProfileMetadata.IsPresent) -KeepRemoteTemp ([bool]$KeepRemoteTemp.IsPresent)
    $snapshot = Invoke-EndpointScan -Label "Snapshot_Source_10.254.140.4" -ComputerIp $SnapshotIp -Credential $sourceCredential -RunId $runId -EvidenceRoot $evidenceRoot -MaxHashMB $MaxHashMB -IncludeAllUserProfileMetadata ([bool]$IncludeAllUserProfileMetadata.IsPresent) -KeepRemoteTemp ([bool]$KeepRemoteTemp.IsPresent)

    $diffRoot = Join-Path $evidenceRoot "Diff"
    New-Item -Path $diffRoot -ItemType Directory -Force | Out-Null

    $shortcutDiffCount = Compare-InventoryByKey -LeftCsv (Join-Path $migrated.LocalRoot "shortcuts.csv") -RightCsv (Join-Path $snapshot.LocalRoot "shortcuts.csv") -OutCsv (Join-Path $diffRoot "shortcut-differences-by-path.csv") -KeyColumn "EvidenceKey" -CompareColumns @("Hash","Length","ShortcutTargetPath","ShortcutArguments","ShortcutWorkingDirectory","ShortcutIconLocation")
    $visibleDiffCount = Compare-InventoryByKey -LeftCsv (Join-Path $migrated.LocalRoot "visible-files.csv") -RightCsv (Join-Path $snapshot.LocalRoot "visible-files.csv") -OutCsv (Join-Path $diffRoot "visible-file-differences-by-path.csv") -KeyColumn "EvidenceKey" -CompareColumns @("Hash","Length")
    $shortcutEquivalentDiffCount = Compare-InventoryByKey -LeftCsv (Join-Path $migrated.LocalRoot "shortcuts.csv") -RightCsv (Join-Path $snapshot.LocalRoot "shortcuts.csv") -OutCsv (Join-Path $diffRoot "shortcut-differences-by-name-target.csv") -KeyColumn "ShortcutNameTargetKey" -CompareColumns @("EvidenceKey","Hash","Length")
    $contentEquivalentDiffCount = Compare-InventoryByKey -LeftCsv (Join-Path $migrated.LocalRoot "visible-files.csv") -RightCsv (Join-Path $snapshot.LocalRoot "visible-files.csv") -OutCsv (Join-Path $diffRoot "visible-file-differences-by-name-hash.csv") -KeyColumn "ContentNameHashKey" -CompareColumns @("EvidenceKey")
    $profileFolderDiffCount = Compare-InventoryByKey -LeftCsv (Join-Path $migrated.LocalRoot "profile-folders.csv") -RightCsv (Join-Path $snapshot.LocalRoot "profile-folders.csv") -OutCsv (Join-Path $diffRoot "profile-folder-differences.csv") -KeyColumn "FolderName" -CompareColumns @("NtUserDatExists","DesktopExists","DocumentsExists","DownloadsExists","StartMenuExists","DesktopShortcutCount","StartMenuShortcutCount")
    $profileRegistryDiffCount = Compare-InventoryByKey -LeftCsv (Join-Path $migrated.LocalRoot "profile-registry.csv") -RightCsv (Join-Path $snapshot.LocalRoot "profile-registry.csv") -OutCsv (Join-Path $diffRoot "profile-registry-differences-by-profile-folder.csv") -KeyColumn "ProfileLeafName" -CompareColumns @("ProfileImagePath","State","RefCount","Flags")

    $runSummary = @(
        [pscustomobject]@{ Metric = "EvidenceRoot"; Value = $evidenceRoot },
        [pscustomobject]@{ Metric = "MigratedEndpoint"; Value = "$($migrated.Label) $($migrated.Ip) $($migrated.ComputerName) $($migrated.Domain)" },
        [pscustomobject]@{ Metric = "SnapshotEndpoint"; Value = "$($snapshot.Label) $($snapshot.Ip) $($snapshot.ComputerName) $($snapshot.Domain)" },
        [pscustomobject]@{ Metric = "ShortcutDifferencesByPath"; Value = $shortcutDiffCount },
        [pscustomobject]@{ Metric = "VisibleFileDifferencesByPath"; Value = $visibleDiffCount },
        [pscustomobject]@{ Metric = "ShortcutDifferencesByNameTarget"; Value = $shortcutEquivalentDiffCount },
        [pscustomobject]@{ Metric = "VisibleFileDifferencesByNameHash"; Value = $contentEquivalentDiffCount },
        [pscustomobject]@{ Metric = "ProfileFolderDifferences"; Value = $profileFolderDiffCount },
        [pscustomobject]@{ Metric = "ProfileRegistryDifferencesByProfileFolder"; Value = $profileRegistryDiffCount }
    )

    $runSummary | Export-Csv -Path (Join-Path $evidenceRoot "run-summary.csv") -NoTypeInformation -Encoding UTF8
    $runSummary | Format-Table -AutoSize

    Write-StatusLine -Level SUCCESS -Message "Deep comparison complete. Review $evidenceRoot"
    Write-StatusLine -Message "Most important files: Diff\shortcut-differences-by-path.csv, Diff\visible-file-differences-by-path.csv, Diff\profile-registry-differences-by-profile-folder.csv, Migrated_Target_10.254.140.161\quarantine-files.csv"
}
finally {
    Stop-Transcript | Out-Null
}
