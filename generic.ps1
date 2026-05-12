$scriptPath = "C:\AD-MigrationSuite\Tools\Compare-PPRESORT1AWSDeepEvidence-WorkflowCreds.ps1"; $backupPath = "C:\AD-MigrationSuite\Backups\Compare-PPRESORT1AWSDeepEvidence-WorkflowCreds.ps1.before-compare-function-hardening-$(Get-Date -Format yyyyMMdd-HHmmss).bak"; Copy-Item $scriptPath $backupPath -Force; $text = Get-Content $scriptPath -Raw; $newFunction = @'
function Compare-InventoryByKey {
    param(
        [Parameter(Mandatory)][string]$LeftCsv,
        [Parameter(Mandatory)][string]$RightCsv,
        [Parameter(Mandatory)][string]$OutCsv,
        [Parameter(Mandatory)][string]$KeyColumn,
        [string[]]$CompareColumns = @("Hash","Length","ShortcutTargetPath","ShortcutArguments")
    )

    Write-StatusLine -Message ("Comparing {0} to {1} by key column [{2}]" -f $LeftCsv,$RightCsv,$KeyColumn)

    function Import-SafeCsvRows {
        param([Parameter(Mandatory)][string]$Path)

        if (-not (Test-Path -LiteralPath $Path)) {
            Write-StatusLine -Level WARN -Message "CSV not found for compare: $Path"
            return @()
        }

        $rows = @(Import-Csv -Path $Path)
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

    function Add-DiffRow {
        param(
            [Parameter(Mandatory)][System.Collections.ArrayList]$Rows,
            [Parameter(Mandatory)][object]$Row
        )

        [void]$Rows.Add($Row)
    }

    $leftRows = @(Import-SafeCsvRows -Path $LeftCsv)
    $rightRows = @(Import-SafeCsvRows -Path $RightCsv)

    $leftMap = @{}
    foreach ($row in $leftRows) {
        $key = (Get-RowTextValue -Row $row -PropertyName $KeyColumn).Trim().ToLowerInvariant()
        if (-not [string]::IsNullOrWhiteSpace($key) -and -not $leftMap.ContainsKey($key)) {
            $leftMap[$key] = $row
        }
    }

    $rightMap = @{}
    foreach ($row in $rightRows) {
        $key = (Get-RowTextValue -Row $row -PropertyName $KeyColumn).Trim().ToLowerInvariant()
        if (-not [string]::IsNullOrWhiteSpace($key) -and -not $rightMap.ContainsKey($key)) {
            $rightMap[$key] = $row
        }
    }

    $allKeySet = New-Object "System.Collections.Generic.HashSet[string]"
    foreach ($key in $leftMap.Keys) { [void]$allKeySet.Add([string]$key) }
    foreach ($key in $rightMap.Keys) { [void]$allKeySet.Add([string]$key) }
    $allKeys = @($allKeySet) | Sort-Object

    $diffRows = New-Object System.Collections.ArrayList

    foreach ($key in $allKeys) {
        $leftExists = $leftMap.ContainsKey($key)
        $rightExists = $rightMap.ContainsKey($key)

        if (-not $leftExists -and $rightExists) {
            $right = $rightMap[$key]
            Add-DiffRow -Rows $diffRows -Row ([pscustomobject]@{
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
            Add-DiffRow -Rows $diffRows -Row ([pscustomobject]@{
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
        $changedColumns = New-Object System.Collections.ArrayList

        foreach ($columnName in @($CompareColumns)) {
            $leftValue = Get-RowTextValue -Row $leftRow -PropertyName $columnName
            $rightValue = Get-RowTextValue -Row $rightRow -PropertyName $columnName
            if ($leftValue -ne $rightValue) {
                [void]$changedColumns.Add($columnName)
            }
        }

        if ($changedColumns.Count -gt 0) {
            Add-DiffRow -Rows $diffRows -Row ([pscustomobject]@{
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

    Write-StatusLine -Level SUCCESS -Message ("Compare complete: {0} difference row(s). Output: {1}" -f $diffRows.Count,$OutCsv)
    return [int]$diffRows.Count
}
'@; $pattern = '(?s)function Compare-InventoryByKey \{.*?\r?\n\}\r?\n\r?\n\$evidenceContext ='; if ($text -notmatch $pattern) { throw "Could not locate Compare-InventoryByKey function boundary. No changes written." }; $text = [regex]::Replace($text,$pattern,($newFunction + "`r`n`r`n" + '$evidenceContext ='),1); $tokens = $null; $errors = $null; [System.Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors) | Out-Null; if ($errors.Count -gt 0) { $errors | Format-List; throw "Syntax failed; patch not written." } else { Set-Content -Path $scriptPath -Value $text -Encoding UTF8; Write-Host "Compare function hardened. Backup: $backupPath" -ForegroundColor Green }
