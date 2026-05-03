$path06a = "C:\AD-MigrationSuite\Computer-Migration\Scripts\06a-Run-AdmtSecurityTranslationOnAdmtServer.ps1"; $content = Get-Content -Path $path06a -Raw; if ($content -notmatch "function Clear-RemoteAdmtAgentResidue") { $helper = @'
function Clear-RemoteAdmtAgentResidue {
    param(
        [Parameter(Mandatory)][string[]]$ComputerNames,
        [Parameter(Mandatory)][string]$TargetDomainFqdn,
        [Parameter(Mandatory)][string]$Phase
    )

    foreach ($computerName in $ComputerNames) {
        $targetFqdn = "{0}.{1}" -f $computerName,$TargetDomainFqdn
        Write-RunLog "[$computerName] ADMT endpoint agent cleanup started. Phase=$Phase Target=$targetFqdn"

        try {
            & sc.exe "\\$targetFqdn" stop OnePointDomainAgent 2>&1 | ForEach-Object { Write-RunLog "[$computerName] sc stop OnePointDomainAgent: $_" }
        }
        catch {
            Write-RunLog "[$computerName] OnePointDomainAgent stop attempt warning: $($_.Exception.Message)"
        }

        Start-Sleep -Seconds 5

        foreach ($processName in @("DCTAgentService.exe","DCTAgent.exe","OnePointDomainAgent.exe")) {
            try {
                cmd.exe /c "taskkill /s $targetFqdn /im $processName /f" 2>&1 | ForEach-Object { Write-RunLog "[$computerName] taskkill ${processName}: $_" }
            }
            catch {
                Write-RunLog "[$computerName] taskkill ${processName} warning: $($_.Exception.Message)"
            }
        }

        $driveName = "ADMS" + (Get-Random -Minimum 1000 -Maximum 9999)

        try {
            New-PSDrive -Name $driveName -PSProvider FileSystem -Root "\\$targetFqdn\ADMIN$" -ErrorAction Stop | Out-Null
            $agentPath = "$($driveName):\OnePointDomainAgent"

            if (Test-Path $agentPath) {
                $archivePath = "$($driveName):\OnePointDomainAgent.ADMS-$Phase-$RunId-$((Get-Date).ToString('yyyyMMdd-HHmmss'))"

                try {
                    Rename-Item -Path $agentPath -NewName ([System.IO.Path]::GetFileName($archivePath)) -ErrorAction Stop
                    Write-RunLog "[$computerName] Renamed stale OnePointDomainAgent folder to $archivePath"
                }
                catch {
                    Write-RunLog "[$computerName] Could not rename OnePointDomainAgent folder; leaving in place. Warning: $($_.Exception.Message)"
                }
            }
            else {
                Write-RunLog "[$computerName] No stale OnePointDomainAgent folder found."
            }
        }
        catch {
            Write-RunLog "[$computerName] ADMT endpoint agent cleanup ADMIN$ warning: $($_.Exception.Message)"
        }
        finally {
            Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue
        }

        Write-RunLog "[$computerName] ADMT endpoint agent cleanup completed. Phase=$Phase"
    }
}

'@; $content = $content.Replace('function Get-RelevantMigrationLogs {', $helper + 'function Get-RelevantMigrationLogs {'); $content = $content.Replace('$ReplaceStart = Get-Date', 'Clear-RemoteAdmtAgentResidue -ComputerNames $ComputerNames -TargetDomainFqdn $TargetDomainFqdn -Phase "BeforeReplace"' + "`r`n`r`n" + '$ReplaceStart = Get-Date'); $content = $content.Replace('$RightsStart = Get-Date', 'Clear-RemoteAdmtAgentResidue -ComputerNames $ComputerNames -TargetDomainFqdn $TargetDomainFqdn -Phase "BeforeUserRights"' + "`r`n`r`n" + '$RightsStart = Get-Date'); Set-Content -Path $path06a -Value $content -Encoding UTF8; Write-Host "Patched 06a with best-effort remote ADMT endpoint agent cleanup." -ForegroundColor Green } else { Write-Host "06a agent cleanup already present. No duplicate patch made." -ForegroundColor Yellow }
