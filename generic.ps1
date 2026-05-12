@'
[CmdletBinding()]
param(
    [string]$EvidenceRoot = "",
    [string]$MigratedLabel = "Migrated_Target_10.254.140.161",
    [string]$SnapshotLabel = "Snapshot_Source_10.254.140.4"
)

$ErrorActionPreference = "Stop"

function Write-LocalStatus {
    param(
        [ValidateSet("INFO","SUCCESS","WARN","ERROR")]
        [string]$Level = "INFO",
        [string]$Message
    )

    $color = switch ($Level) {
        "SUCCESS" { "Green" }
        "WARN" { "Yellow" }
        "ERROR" { "Red" }
        default { "Cyan" }
    }

    Write-Host ("{0} [{1}] {2}" -f (Get-Date -Format s), $Level, $Message) -ForegroundColor $color
}

function Import-SafeCsvRows {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-LocalStatus -Level WARN -Message "CSV not found: $Path"
        return @()
    }

    $rows = @(Import-Csv -Path $Path)

    if ($rows.Count -eq 0) {
        return @()
    }

    if ($rows.Count -eq 1 -and ($rows[0].PSObject.Properties.Name -contains "NoRows")) {
        return @()
    }

    return $rows
}

function Get-RowTextValue {
    param(
        [AllowNull()][object]$Row,
        [Parameter(Mandatory)][string]$PropertyName
    )

    if ($null -eq $Row) {
        return ""
    }

    if ($Row.PSObject.Properties.Name -contains $PropertyName) {
        return [string]$Row.$PropertyName
    }

    return ""
}

function Get-ResolvedKey {
    param(
        [Parameter(Mandatory)][object]$Row,
        [Parameter(Mandatory)][string]$PreferredKeyColumn
    )

    $key = (Get-RowTextValue -Row $Row -PropertyName $PreferredKeyColumn).Trim()

    if (-not [string]::IsNullOrWhiteSpace($key)) {
        return $key.ToLowerInvariant()
    }

    foreach ($fallbackColumn in @("EvidenceKey","RelativeName","FullName","ShortcutNameTargetKey","ContentNameHashKey","FolderName","ProfileLeafName","Name")) {
        $key = (Get-RowTextValue -Row $Row -PropertyName $fallbackColumn).Trim()
        if (-not [string]::IsNullOrWhiteSpace($key)) {
            return $key.ToLowerInvariant()
        }
    }

    return ""
}

function Compare-InventoryByKey {
    param(
        [Parameter(Mandatory)][string]$LeftCsv,
        [Parameter(Mandatory)][string]$RightCsv,
        [Parameter(Mandatory)][string]$OutCsv,
        [Parameter(Mandatory)][string]$KeyColumn,
        [string[]]$CompareColumns = @("Hash","Length","ShortcutTargetPath","ShortcutArguments")
    )

    Write-LocalStatus -Message ("Comparing {0} to {1} by [{2}]" -f $LeftCsv,$RightCsv,$KeyColumn)

    $leftRows = @(Import-SafeCsvRows -Path $LeftCsv)
    $rightRows = @(Import-SafeCsvRows -Path $RightCsv)

    $leftMap = @{}
    foreach ($row in $leftRows) {
        $key = Get-ResolvedKey -Row $row -PreferredKeyColumn $KeyColumn
        if (-not [string]::IsNullOrWhiteSpace($key) -and -not $leftMap.ContainsKey($key)) {
            $leftMap[$key] = $row
        }
    }

    $rightMap = @{}
    foreach ($row in $rightRows) {
        $key = Get-ResolvedKey -Row $row -PreferredKeyColumn $KeyColumn
        if (-not [string]::IsNullOrWhiteSpace($key) -and -not $rightMap.ContainsKey($key)) {
            $rightMap[$key] = $row
        }
    }

    $allKeySet = New-Object "System.Collections.Generic.HashSet[string]"
    foreach ($key in $leftMap.Keys) { [void]$allKeySet.Add([string]$key) }
    foreach ($key in $rightMap.Keys) { [void]$allKeySet.Add([string]$key) }
    $allKeys = @($allKeySet) | Sort-Object

    $diffRows = New-Object System.Collections.Generic.List[object]

    foreach ($key in $allKeys) {
        $leftExists = $leftMap.ContainsKey($key)
        $rightExists = $rightMap.ContainsKey($key)

        if (-not $leftExists -and $rightExists) {
            $right = $rightMap[$key]
            $diffRows.Add([pscustomobject]@{
                DifferenceType = "OnlyInSnapshot_Source"
                Key = $key
                ChangedColumns = ""
                MigratedPath = ""
                SnapshotPath = Get-RowTextValue -Row $right -PropertyName "FullName"
                MigratedHash = ""
                SnapshotHash = Get-RowTextValue -Row $right -PropertyName "Hash"
                MigratedLength = ""
                SnapshotLength = Get-RowTextValue -Row $right -PropertyName "Length"
                MigratedTarget = ""
                SnapshotTarget = Get-RowTextValue -Row $right -PropertyName "ShortcutTargetPath"
            })
            continue
        }

        if ($leftExists -and -not $rightExists) {
            $left = $leftMap[$key]
            $diffRows.Add([pscustomobject]@{
                DifferenceType = "OnlyInMigrated_Target"
                Key = $key
                ChangedColumns = ""
                MigratedPath = Get-RowTextValue -Row $left -PropertyName "FullName"
                SnapshotPath = ""
                MigratedHash = Get-RowTextValue -Row $left -PropertyName "Hash"
                SnapshotHash = ""
                MigratedLength = Get-RowTextValue -Row $left -PropertyName "Length"
                SnapshotLength = ""
                MigratedTarget = Get-RowTextValue -Row $left -PropertyName "ShortcutTargetPath"
                SnapshotTarget = ""
            })
            continue
        }

        $leftRow = $leftMap[$key]
        $rightRow = $rightMap[$key]
        $changedColumns = New-Object System.Collections.Generic.List[string]

        foreach ($columnName in @($CompareColumns)) {
            $leftValue = Get-RowTextValue -Row $leftRow -PropertyName $columnName
            $rightValue = Get-RowTextValue -Row $rightRow -PropertyName $columnName

            if ($leftValue -ne $rightValue) {
                $changedColumns.Add($columnName)
            }
        }

        if ($changedColumns.Count -gt 0) {
            $diffRows.Add([pscustomobject]@{
                DifferenceType = "DifferentMetadataOrTarget"
                Key = $key
                ChangedColumns = ($changedColumns -join ";")
                MigratedPath = Get-RowTextValue -Row $leftRow -PropertyName "FullName"
                SnapshotPath = Get-RowTextValue -Row $rightRow -PropertyName "FullName"
                MigratedHash = Get-RowTextValue -Row $leftRow -PropertyName "Hash"
                SnapshotHash = Get-RowTextValue -Row $rightRow -PropertyName "Hash"
                MigratedLength = Get-RowTextValue -Row $leftRow -PropertyName "Length"
                SnapshotLength = Get-RowTextValue -Row $rightRow -PropertyName "Length"
                MigratedTarget = Get-RowTextValue -Row $leftRow -PropertyName "ShortcutTargetPath"
                SnapshotTarget = Get-RowTextValue -Row $rightRow -PropertyName "ShortcutTargetPath"
            })
        }
    }

    if ($diffRows.Count -gt 0) {
        $diffRows | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
    }
    else {
        "DifferenceType,Key,ChangedColumns,MigratedPath,SnapshotPath,MigratedHash,SnapshotHash,MigratedLength,SnapshotLength,MigratedTarget,SnapshotTarget" | Set-Content -Path $OutCsv -Encoding UTF8
    }

    Write-LocalStatus -Level SUCCESS -Message ("Compare complete: {0} row(s). Output: {1}" -f $diffRows.Count,$OutCsv)
    return [int]$diffRows.Count
}

if ([string]::IsNullOrWhiteSpace($EvidenceRoot)) {
    $EvidenceRoot = (Get-ChildItem "C:\AD-MigrationSuite\Evidence\PPRESORT1AWS-DeepCompare" -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
}

if ([string]::IsNullOrWhiteSpace($EvidenceRoot) -or -not (Test-Path -LiteralPath $EvidenceRoot)) {
    throw "EvidenceRoot not found."
}

$migratedRoot = Join-Path $EvidenceRoot $MigratedLabel
$snapshotRoot = Join-Path $EvidenceRoot $SnapshotLabel
$diffRoot = Join-Path $EvidenceRoot "Diff"

if (-not (Test-Path -LiteralPath $migratedRoot)) {
    throw "Migrated evidence folder not found: $migratedRoot"
}

if (-not (Test-Path -LiteralPath $snapshotRoot)) {
    throw "Snapshot evidence folder not found: $snapshotRoot"
}

New-Item -Path $diffRoot -ItemType Directory -Force | Out-Null

Write-LocalStatus -Message "Using evidence root: $EvidenceRoot"

$shortcutDiffCount = Compare-InventoryByKey -LeftCsv (Join-Path $migratedRoot "shortcuts.csv") -RightCsv (Join-Path $snapshotRoot "shortcuts.csv") -OutCsv (Join-Path $diffRoot "shortcut-differences-by-path.csv") -KeyColumn "EvidenceKey" -CompareColumns @("Hash","Length","ShortcutTargetPath","ShortcutArguments","ShortcutWorkingDirectory","ShortcutIconLocation")
$visibleDiffCount = Compare-InventoryByKey -LeftCsv (Join-Path $migratedRoot "visible-files.csv") -RightCsv (Join-Path $snapshotRoot "visible-files.csv") -OutCsv (Join-Path $diffRoot "visible-file-differences-by-path.csv") -KeyColumn "EvidenceKey" -CompareColumns @("Hash","Length")
$shortcutEquivalentDiffCount = Compare-InventoryByKey -LeftCsv (Join-Path $migratedRoot "shortcuts.csv") -RightCsv (Join-Path $snapshotRoot "shortcuts.csv") -OutCsv (Join-Path $diffRoot "shortcut-differences-by-name-target.csv") -KeyColumn "ShortcutNameTargetKey" -CompareColumns @("EvidenceKey","Hash","Length")
$contentEquivalentDiffCount = Compare-InventoryByKey -LeftCsv (Join-Path $migratedRoot "visible-files.csv") -RightCsv (Join-Path $snapshotRoot "visible-files.csv") -OutCsv (Join-Path $diffRoot "visible-file-differences-by-name-hash.csv") -KeyColumn "ContentNameHashKey" -CompareColumns @("EvidenceKey")
$profileFolderDiffCount = Compare-InventoryByKey -LeftCsv (Join-Path $migratedRoot "profile-folders.csv") -RightCsv (Join-Path $snapshotRoot "profile-folders.csv") -OutCsv (Join-Path $diffRoot "profile-folder-differences.csv") -KeyColumn "FolderName" -CompareColumns @("NtUserDatExists","DesktopExists","DocumentsExists","DownloadsExists","StartMenuExists","DesktopShortcutCount","StartMenuShortcutCount")
$profileRegistryDiffCount = Compare-InventoryByKey -LeftCsv (Join-Path $migratedRoot "profile-registry.csv") -RightCsv (Join-Path $snapshotRoot "profile-registry.csv") -OutCsv (Join-Path $diffRoot "profile-registry-differences-by-profile-folder.csv") -KeyColumn "ProfileLeafName" -CompareColumns @("ProfileImagePath","State","RefCount","Flags")

$runSummary = @(
    [pscustomobject]@{ Metric = "EvidenceRoot"; Value = $EvidenceRoot },
    [pscustomobject]@{ Metric = "ShortcutDifferencesByPath"; Value = $shortcutDiffCount },
    [pscustomobject]@{ Metric = "VisibleFileDifferencesByPath"; Value = $visibleDiffCount },
    [pscustomobject]@{ Metric = "ShortcutDifferencesByNameTarget"; Value = $shortcutEquivalentDiffCount },
    [pscustomobject]@{ Metric = "VisibleFileDifferencesByNameHash"; Value = $contentEquivalentDiffCount },
    [pscustomobject]@{ Metric = "ProfileFolderDifferences"; Value = $profileFolderDiffCount },
    [pscustomobject]@{ Metric = "ProfileRegistryDifferencesByProfileFolder"; Value = $profileRegistryDiffCount }
)

$runSummary | Export-Csv -Path (Join-Path $EvidenceRoot "run-summary.csv") -NoTypeInformation -Encoding UTF8
$runSummary | Format-Table -AutoSize

Get-ChildItem $diffRoot -Filter *.csv | ForEach-Object {
    [pscustomobject]@{
        File = $_.Name
        Rows = @((Import-Csv $_.FullName)).Count
        Path = $_.FullName
    }
} | Format-Table -AutoSize
'@ | Set-Content -Path "C:\AD-MigrationSuite\Tools\Invoke-PPRESORT1AWSLocalDiff.ps1" -Encoding UTF8
