$path = "C:\AD-MigrationSuite\Computer-Migration\Scripts\06-Run-AdmtSecurityTranslationBulk.ps1"; $content = Get-Content -Path $path -Raw; $old = @'
    $readinessFile = Join-Path $localRunRoot ("ADMT-Readiness-" + $run.RunId + ".csv")
    $readinessRows | Export-Csv -Path $readinessFile -NoTypeInformation -Encoding UTF8

    $readinessFailures = @($readinessRows | Where-Object { $_.FinalStatus -ne "Ready" })
    if ($readinessFailures.Count -gt 0) {
'@; $new = @'
    $readinessFile = Join-Path $localRunRoot ("ADMT-Readiness-" + $run.RunId + ".csv")
    $readinessRows | Export-Csv -Path $readinessFile -NoTypeInformation -Encoding UTF8

    $readinessFailures = @($readinessRows | Where-Object { $_.FinalStatus -ne "Ready" })
    if ($readinessFailures.Count -gt 0) {
        $repairScript = Join-Path $config.ScriptRoot "06b-Repair-AdmtEndpointReadiness.ps1"
        if (Test-Path $repairScript) {
            $failedComputerNames = @($readinessFailures | Select-Object -ExpandProperty ComputerName)
            Write-AdmtStageLog -Message "ADMT readiness found $($readinessFailures.Count) failed endpoint(s). Invoking endpoint readiness healing once."
            try {
                & $repairScript -ConfigPath $ConfigPath -InventoryPath $MigrationManifestPath -ComputerNames $failedComputerNames -RunId $run.RunId -ResultRoot $localRunRoot
            }
            catch {
                Write-AdmtStageLog -Message "ADMT endpoint readiness healing script returned an error: $($_.Exception.Message)" -Level "WARN"
            }

            Start-Sleep -Seconds 20

            $readinessRows = @()
            foreach ($computerName in $ComputerNames) {
                $ipAddress = if ($manifestMap.ContainsKey($computerName)) { $manifestMap[$computerName] } else { $computerName }
                Write-AdmtStageLog -Message "[$computerName][$ipAddress] Re-running ADMT readiness precheck after healing"

                try {
                    $readiness = Test-AdmtEndpointReadinessFromAdmtServer -ComputerName $computerName -IpAddress $ipAddress -TargetDomainFqdn $config.TargetDomainFqdn -Ports $admtReadinessPorts -TargetCredential $workstationAuth
                    $readinessRows += [pscustomobject]@{
                        ComputerName = $computerName
                        IPAddress = $ipAddress
                        FinalStatus = if ($readiness.Ready) { "Ready" } else { "Failed" }
                        Notes = $readiness.Notes
                    }
                }
                catch {
                    $readinessRows += [pscustomobject]@{
                        ComputerName = $computerName
                        IPAddress = $ipAddress
                        FinalStatus = "Failed"
                        Notes = $_.Exception.Message
                    }
                }
            }

            $readinessFile = Join-Path $localRunRoot ("ADMT-Readiness-PostRepair-" + $run.RunId + ".csv")
            $readinessRows | Export-Csv -Path $readinessFile -NoTypeInformation -Encoding UTF8
            $readinessFailures = @($readinessRows | Where-Object { $_.FinalStatus -ne "Ready" })
        }
        else {
            Write-AdmtStageLog -Message "ADMT endpoint readiness healing script not found: $repairScript" -Level "WARN"
        }
    }

    if ($readinessFailures.Count -gt 0) {
'@; if ($content -notlike "*`$readinessFile = Join-Path `$localRunRoot (`"ADMT-Readiness-`" + `$run.RunId + `".csv`")*") { Write-Host "Expected readiness block not found. No change made." -ForegroundColor Yellow } else { $content = $content.Replace($old,$new); Set-Content -Path $path -Value $content -Encoding UTF8; Write-Host "Patched 06 to invoke ADMT endpoint readiness healing once before failing." -ForegroundColor Green }
