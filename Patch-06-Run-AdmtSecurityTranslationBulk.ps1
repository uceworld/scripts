$path06 = "C:\AD-MigrationSuite\Computer-Migration\Scripts\06-Run-AdmtSecurityTranslationBulk.ps1"; $content = Get-Content -Path $path06 -Raw; $content = ($content -split "`r?`n" | Where-Object { $_ -notmatch "DNS-only ADMT readiness failure accepted after hosts-name healing" }) -join "`r`n"; $newFunction = @'
function Test-AdmtEndpointReadinessFromAdmtServer {
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][string]$IpAddress,
        [Parameter(Mandatory)][string]$TargetDomainFqdn,
        [int[]]$Ports = @(135,445),
        [Parameter(Mandatory)][pscredential]$TargetCredential
    )

    $targetFqdn = "{0}.{1}" -f $ComputerName,$TargetDomainFqdn

    Invoke-TrustedRemoteCommand -ComputerName $config.AdmtServerIp -Credential $admtServerAuth -LogPath $logPath -ArgumentList @(
        $ComputerName,
        $IpAddress,
        $targetFqdn,
        $Ports,
        $TargetCredential
    ) -ScriptBlock {
        param(
            [string]$ComputerName,
            [string]$TargetIpAddress,
            [string]$TargetFqdn,
            [int[]]$Ports,
            [pscredential]$TargetCredential
        )

        $notes = New-Object System.Collections.Generic.List[string]

        function Add-ReadinessNote {
            param([string]$Value)
            if (-not [string]::IsNullOrWhiteSpace($Value)) {
                $script:notes.Add($Value) | Out-Null
            }
        }

        $nameResolutionOk = $false
        try {
            [void][System.Net.Dns]::GetHostAddresses($TargetFqdn)
            $nameResolutionOk = $true
        }
        catch {
            Add-ReadinessNote "System name resolution from ADMT server failed: ${TargetFqdn} :: $($_.Exception.Message)"
        }

        $portResults = @()
        foreach ($port in @($Ports | Select-Object -Unique)) {
            $fqdnOk = $false
            $ipOk = $false

            try {
                $fqdnOk = [bool](Test-NetConnection -ComputerName $TargetFqdn -Port $port -WarningAction SilentlyContinue -InformationLevel Quiet)
            }
            catch {
                Add-ReadinessNote "FQDN port $port test threw for ${TargetFqdn}: $($_.Exception.Message)"
            }

            try {
                $ipOk = [bool](Test-NetConnection -ComputerName $TargetIpAddress -Port $port -WarningAction SilentlyContinue -InformationLevel Quiet)
            }
            catch {
                Add-ReadinessNote "IP port $port test threw for ${TargetIpAddress}: $($_.Exception.Message)"
            }

            if (-not $fqdnOk) {
                Add-ReadinessNote "Port $port from ADMT server to ${TargetFqdn} failed"
            }

            $portResults += [pscustomobject]@{
                Port = $port
                FqdnSuccess = $fqdnOk
                IpSuccess = $ipOk
            }
        }

        $adminShareOk = $false
        $adminWriteOk = $false
        $driveName = "ADMS" + (Get-Random -Minimum 1000 -Maximum 9999)

        try {
            New-PSDrive -Name $driveName -PSProvider FileSystem -Root "\\$TargetFqdn\ADMIN$" -Credential $TargetCredential -ErrorAction Stop | Out-Null
            $adminShareOk = Test-Path "$($driveName):\" -ErrorAction Stop
            if ($adminShareOk) {
                $agentPath = "$($driveName):\OnePointDomainAgent"
                New-Item -ItemType Directory -Path $agentPath -Force -ErrorAction Stop | Out-Null
                $testFile = Join-Path $agentPath ("ADMS-readiness-{0}.txt" -f ([guid]::NewGuid().ToString("N")))
                "ADMS readiness test" | Set-Content -Path $testFile -Encoding ASCII -ErrorAction Stop
                Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
                $adminWriteOk = $true
            }
        }
        catch {
            Add-ReadinessNote "ADMIN$ OnePointDomainAgent write/delete check failed via ${TargetFqdn}: $($_.Exception.Message)"
        }
        finally {
            Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue
        }

        function Test-RemoteServiceControl {
            param(
                [Parameter(Mandatory)][string]$Target,
                [Parameter(Mandatory)][string]$ServiceName
            )

            $output = (& sc.exe "\\$Target" query $ServiceName 2>&1 | Out-String).Trim()
            $exitCode = $LASTEXITCODE

            [pscustomobject]@{
                ServiceName = $ServiceName
                Success = ($exitCode -eq 0 -and $output -match "STATE")
                ExitCode = $exitCode
                Output = $output
            }
        }

        $lanman = Test-RemoteServiceControl -Target $TargetFqdn -ServiceName "LanmanServer"
        $netlogon = Test-RemoteServiceControl -Target $TargetFqdn -ServiceName "Netlogon"
        $workstation = Test-RemoteServiceControl -Target $TargetFqdn -ServiceName "LanmanWorkstation"

        if (-not $lanman.Success) {
            Add-ReadinessNote "ADMT service-control check failed for LanmanServer on ${TargetFqdn}: $($lanman.Output)"
        }

        if (-not $netlogon.Success) {
            Add-ReadinessNote "ADMT service-control check failed for Netlogon on ${TargetFqdn}: $($netlogon.Output)"
        }

        if (-not $workstation.Success) {
            Add-ReadinessNote "ADMT service-control check failed for LanmanWorkstation on ${TargetFqdn}: $($workstation.Output)"
        }

        $fqdnPortOk = (@($portResults | Where-Object { -not $_.FqdnSuccess }).Count -eq 0)
        $ready = ($nameResolutionOk -and $fqdnPortOk -and $adminShareOk -and $adminWriteOk -and $lanman.Success -and $netlogon.Success -and $workstation.Success)

        [pscustomobject]@{
            ComputerName = $ComputerName
            TargetFqdn = $TargetFqdn
            TargetIpAddress = $TargetIpAddress
            NameResolutionOk = $nameResolutionOk
            FqdnPortsOk = $fqdnPortOk
            AdminShareOk = $adminShareOk
            AdminWriteOk = $adminWriteOk
            LanmanServerScOk = $lanman.Success
            NetlogonScOk = $netlogon.Success
            LanmanWorkstationScOk = $workstation.Success
            Ready = $ready
            Notes = ($notes | Select-Object -Unique) -join "; "
        }
    }
}
'@; $tokens = $null; $errors = $null; $ast = [System.Management.Automation.Language.Parser]::ParseInput($content,[ref]$tokens,[ref]$errors); if ($errors) { throw "Cannot parse 06 before patch." }; $func = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq "Test-AdmtEndpointReadinessFromAdmtServer" }, $true); if (-not $func) { throw "Function Test-AdmtEndpointReadinessFromAdmtServer not found in 06." }; $content = $content.Remove($func.Extent.StartOffset, $func.Extent.EndOffset - $func.Extent.StartOffset).Insert($func.Extent.StartOffset, $newFunction); Set-Content -Path $path06 -Value $content -Encoding UTF8; $path06b = "C:\AD-MigrationSuite\Computer-Migration\Scripts\06b-Repair-AdmtEndpointReadiness.ps1"; $lines = [System.Collections.Generic.List[string]](Get-Content -Path $path06b); if (-not ($lines -contains '    Set-ServiceReady -Name "RpcSs"')) { $idx = $lines.IndexOf('    Set-ServiceReady -Name "SamSS"'); if ($idx -lt 0) { throw "Could not find SamSS service line in 06b." }; $lines.Insert($idx + 1,'    Set-ServiceReady -Name "RpcSs"'); $lines.Insert($idx + 2,'    Set-ServiceReady -Name "RpcEptMapper"'); $lines.Insert($idx + 3,'    Set-ServiceReady -Name "Netlogon"'); $lines.Insert($idx + 4,'    Set-ServiceReady -Name "RemoteRegistry"') }; Set-Content -Path $path06b -Value $lines -Encoding UTF8; Write-Host "Patched 06 strict ADMT readiness and 06b service enforcement." -ForegroundColor Green
