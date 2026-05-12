$scriptPath = "C:\AD-MigrationSuite\Tools\Compare-PPRESORT1AWSDeepEvidence-WorkflowCreds.ps1"; $backupRoot = "C:\AD-MigrationSuite\Backups"; New-Item -Path $backupRoot -ItemType Directory -Force | Out-Null; $stamp = Get-Date -Format "yyyyMMdd-HHmmss"; $backupPath = Join-Path $backupRoot ("Compare-PPRESORT1AWSDeepEvidence-WorkflowCreds.ps1.before-final-hardening-{0}.bak" -f $stamp); Copy-Item -Path $scriptPath -Destination $backupPath -Force; $text = Get-Content -Path $scriptPath -Raw; $text = $text -replace "`r`n","`n"; function Replace-RequiredText { param([string]$CurrentText,[string]$OldText,[string]$NewText,[string]$Name) if (-not $CurrentText.Contains($OldText)) { throw "Patch anchor not found: $Name" } return $CurrentText.Replace($OldText,$NewText) }; if ($text -notmatch "function Export-RemoteEvidenceCsv") { $text = Replace-RequiredText -CurrentText $text -Name "Insert safe CSV export helper" -OldText @'
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

            Write-RemoteScanStatus -Message "Collecting identity, network, profile registry, and profile folder evidence"
'@ -NewText @'
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

            function Export-RemoteEvidenceCsv {
                param(
                    [Parameter(Mandatory)][string]$FileName,
                    [Parameter(Mandatory)][object]$Rows
                )

                $csvPath = Join-Path $remoteRoot $FileName
                Write-RemoteScanStatus -Message ("Exporting CSV: {0}" -f $FileName)

                try {
                    $exportRows = New-Object System.Collections.Generic.List[object]

                    if ($null -ne $Rows) {
                        if (($Rows -is [System.Collections.IEnumerable]) -and (-not ($Rows -is [string]))) {
                            foreach ($row in $Rows) {
                                if ($null -ne $row) {
                                    [void]$exportRows.Add($row)
                                }
                            }
                        }
                        else {
                            [void]$exportRows.Add($Rows)
                        }
                    }

                    if ($exportRows.Count -gt 0) {
                        $exportRows.ToArray() | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
                    }
                    else {
                        [pscustomobject]@{ NoRows = "True" } | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
                    }
                }
                catch {
                    Add-ScanError -Scope "CsvExport" -Path $csvPath -Message $_.Exception.Message
                    throw ("Failed to export {0}: {1}" -f $FileName, $_.Exception.Message)
                }
            }

            Write-RemoteScanStatus -Message "Collecting identity, network, profile registry, and profile folder evidence"
'@ }; $text = $text -replace "\$remoteResult = Invoke-Command -Session \$session -ArgumentList", '$remoteOutputs = Invoke-Command -Session $session -ArgumentList'; $oldExportBlock = @'
            Write-RemoteScanStatus -Message "Writing remote CSV evidence files"
            $identityRows | Export-Csv -Path (Join-Path $remoteRoot "identity.csv") -NoTypeInformation -Encoding UTF8
            $networkRows | Export-Csv -Path (Join-Path $remoteRoot "network.csv") -NoTypeInformation -Encoding UTF8
            $profileRegistryRows | Export-Csv -Path (Join-Path $remoteRoot "profile-registry.csv") -NoTypeInformation -Encoding UTF8
            $profileFolderRows | Export-Csv -Path (Join-Path $remoteRoot "profile-folders.csv") -NoTypeInformation -Encoding UTF8
            $shortcutRows | Export-Csv -Path (Join-Path $remoteRoot "shortcuts.csv") -NoTypeInformation -Encoding UTF8
            $visibleFileRows | Export-Csv -Path (Join-Path $remoteRoot "visible-files.csv") -NoTypeInformation -Encoding UTF8
            $quarantineRows | Export-Csv -Path (Join-Path $remoteRoot "quarantine-files.csv") -NoTypeInformation -Encoding UTF8
            $allUserMetadataRows | Export-Csv -Path (Join-Path $remoteRoot "all-user-profile-metadata.csv") -NoTypeInformation -Encoding UTF8
            $scanErrors | Export-Csv -Path (Join-Path $remoteRoot "scan-errors.csv") -NoTypeInformation -Encoding UTF8
'@; $newExportBlock = @'
            Write-RemoteScanStatus -Message "Writing remote CSV evidence files"
            Export-RemoteEvidenceCsv -FileName "identity.csv" -Rows $identityRows
            Export-RemoteEvidenceCsv -FileName "network.csv" -Rows $networkRows
            Export-RemoteEvidenceCsv -FileName "profile-registry.csv" -Rows $profileRegistryRows
            Export-RemoteEvidenceCsv -FileName "profile-folders.csv" -Rows $profileFolderRows
            Export-RemoteEvidenceCsv -FileName "shortcuts.csv" -Rows $shortcutRows
            Export-RemoteEvidenceCsv -FileName "visible-files.csv" -Rows $visibleFileRows
            Export-RemoteEvidenceCsv -FileName "quarantine-files.csv" -Rows $quarantineRows
            Export-RemoteEvidenceCsv -FileName "all-user-profile-metadata.csv" -Rows $allUserMetadataRows
            Export-RemoteEvidenceCsv -FileName "scan-errors.csv" -Rows $scanErrors
'@; if ($text.Contains($oldExportBlock)) { $text = $text.Replace($oldExportBlock,$newExportBlock) }; $oldSummaryBlock = @'
            $summaryRows = @(
                [pscustomobject]@{ EndpointLabel = $EndpointLabel; Metric = "ShortcutRows"; Value = @($shortcutRows).Count },
                [pscustomobject]@{ EndpointLabel = $EndpointLabel; Metric = "VisibleFileRows"; Value = @($visibleFileRows).Count },
                [pscustomobject]@{ EndpointLabel = $EndpointLabel; Metric = "QuarantineRows"; Value = @($quarantineRows).Count },
                [pscustomobject]@{ EndpointLabel = $EndpointLabel; Metric = "ProfileRegistryRows"; Value = @($profileRegistryRows).Count },
                [pscustomobject]@{ EndpointLabel = $EndpointLabel; Metric = "ProfileFolderRows"; Value = @($profileFolderRows).Count },
                [pscustomobject]@{ EndpointLabel = $EndpointLabel; Metric = "ScanErrorRows"; Value = @($scanErrors).Count }
            )
            $summaryRows | Export-Csv -Path (Join-Path $remoteRoot "scan-summary.csv") -NoTypeInformation -Encoding UTF8
'@; $newSummaryBlock = @'
            $summaryRows = @(
                [pscustomobject]@{ EndpointLabel = $EndpointLabel; Metric = "ShortcutRows"; Value = $shortcutRows.Count },
                [pscustomobject]@{ EndpointLabel = $EndpointLabel; Metric = "VisibleFileRows"; Value = $visibleFileRows.Count },
                [pscustomobject]@{ EndpointLabel = $EndpointLabel; Metric = "QuarantineRows"; Value = $quarantineRows.Count },
                [pscustomobject]@{ EndpointLabel = $EndpointLabel; Metric = "ProfileRegistryRows"; Value = @($profileRegistryRows).Count },
                [pscustomobject]@{ EndpointLabel = $EndpointLabel; Metric = "ProfileFolderRows"; Value = @($profileFolderRows).Count },
                [pscustomobject]@{ EndpointLabel = $EndpointLabel; Metric = "ScanErrorRows"; Value = $scanErrors.Count }
            )
            Export-RemoteEvidenceCsv -FileName "scan-summary.csv" -Rows $summaryRows
'@; if ($text.Contains($oldSummaryBlock)) { $text = $text.Replace($oldSummaryBlock,$newSummaryBlock) }; $oldArchiveBlock = @'
            Write-RemoteScanStatus -Message "Compressing remote evidence archive"
            Compress-Archive -Path (Join-Path $remoteRoot "*") -DestinationPath $archivePath -Force
            Write-RemoteScanStatus -Message "Remote endpoint scan complete"
'@; $newArchiveBlock = @'
            Write-RemoteScanStatus -Message "Compressing remote evidence archive using .NET ZipFile"
            try {
                if (Test-Path -LiteralPath $archivePath) {
                    Remove-Item -LiteralPath $archivePath -Force -ErrorAction SilentlyContinue
                }

                Add-Type -AssemblyName System.IO.Compression.FileSystem
                [System.IO.Compression.ZipFile]::CreateFromDirectory($remoteRoot,$archivePath,[System.IO.Compression.CompressionLevel]::Optimal,$false)
            }
            catch {
                Add-ScanError -Scope "ZipArchive" -Path $archivePath -Message $_.Exception.Message
                Export-RemoteEvidenceCsv -FileName "scan-errors.csv" -Rows $scanErrors
                throw ("Failed to create remote evidence archive {0}: {1}" -f $archivePath, $_.Exception.Message)
            }
            Write-RemoteScanStatus -Message "Remote endpoint scan complete"
'@; if ($text.Contains($oldArchiveBlock)) { $text = $text.Replace($oldArchiveBlock,$newArchiveBlock) }; $oldReturnClose = @'
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
'@; $newReturnClose = @'
            return [pscustomobject]@{
                EndpointLabel = $EndpointLabel
                EndpointIp = $EndpointIp
                ComputerName = $env:COMPUTERNAME
                Domain = $computerSystem.Domain
                RemoteRoot = $remoteRoot
                ArchivePath = $archivePath
            }
        }

        $remoteResult = @($remoteOutputs | Where-Object { $null -ne $_ -and $_.PSObject.Properties.Name -contains "ArchivePath" } | Select-Object -Last 1)
        if ($null -eq $remoteResult -or [string]::IsNullOrWhiteSpace([string]$remoteResult.ArchivePath)) {
            throw "Remote scan for $Label completed without returning a usable ArchivePath. Check the endpoint transcript output above and remote temp folder if -KeepRemoteTemp was used."
        }

        $localEndpointRoot = Join-Path $EvidenceRoot $Label
'@; if ($text.Contains($oldReturnClose)) { $text = $text.Replace($oldReturnClose,$newReturnClose) }; $parseTokens = $null; $parseErrors = $null; [System.Management.Automation.Language.Parser]::ParseInput($text,[ref]$parseTokens,[ref]$parseErrors) | Out-Null; if ($parseErrors -and $parseErrors.Count -gt 0) { $parseErrors | Format-List; throw "Patched script failed syntax validation. Backup preserved at $backupPath. Script was not overwritten." }; Set-Content -Path $scriptPath -Value ($text -replace "`n","`r`n") -Encoding UTF8; Write-Host "Final hardening patch applied and syntax validated." -ForegroundColor Green; Write-Host "Backup: $backupPath" -ForegroundColor Yellow
