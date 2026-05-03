$path06 = "C:\AD-MigrationSuite\Computer-Migration\Scripts\06-Run-AdmtSecurityTranslationBulk.ps1"; $content = Get-Content -Path $path06 -Raw; $newFunction = @'
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

        function Set-AdmsHostsEntry {
            param(
                [Parameter(Mandatory)][string]$Name,
                [Parameter(Mandatory)][string]$ShortName,
                [Parameter(Mandatory)][string]$Address
            )

            try {
                $hostsPath = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"
                $entryTag = "# ADMS-ADMT-READINESS:$Name"
                $existing = @(Get-Content -Path $hostsPath -ErrorAction SilentlyContinue | Where-Object { $_ -notmatch [regex]::Escape($entryTag) })
                $entry = "{0}`t{1} {2}`t{3}" -f $Address,$Name,$ShortName,$entryTag
                Set-Content -Path $hostsPath -Value @($existing + $entry) -Encoding ASCII
                Clear-DnsClientCache -ErrorAction SilentlyContinue
                ipconfig /flushdns | Out-Null
            }
            catch {
                Add-ReadinessNote "ADMT server hosts-file update failed for ${Name}: $($_.Exception.Message)"
            }
        }

        Set-AdmsHostsEntry -Name $TargetFqdn -ShortName $ComputerName -Address $TargetIpAddress

        $nameResolutionOk = $false
        try {
            [void][System.Net.Dns]::GetHostAddresses($TargetFqdn)
            $nameResolutionOk = $true
        }
        catch {
            Add-ReadinessNote "System name resolution from ADMT server failed after hosts healing: ${TargetFqdn} :: $($_.Exception.Message)"
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
        $uncRoot = "\\$TargetFqdn\ADMIN$"
        $secretPointer = [IntPtr]::Zero
        $plainPassword = $null

        try {
            $secretPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($TargetCredential.Password)
            $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($secretPointer)

            $deleteArgs = @("use",$uncRoot,"/delete","/y")
            & net.exe @deleteArgs | Out-Null

            $useArgs = @("use",$uncRoot,"/user:$($TargetCredential.UserName)",$plainPassword,"/persistent:no")
            $netUseOutput = @(& net.exe @useArgs 2>&1)
            $netUseExitCode = $LASTEXITCODE

            if ($netUseExitCode -ne 0) {
                throw "net use failed for $uncRoot as $($TargetCredential.UserName). ExitCode=$netUseExitCode Output=$($netUseOutput -join ' | ')"
            }

            $adminShareOk = Test-Path -Path $uncRoot -ErrorAction Stop

            if ($adminShareOk) {
                $agentPath = Join-Path -Path $uncRoot -ChildPath "OnePointDomainAgent"
                New-Item -ItemType Directory -Path $agentPath -Force -ErrorAction Stop | Out-Null
                $testFile = Join-Path -Path $agentPath -ChildPath ("ADMS-readiness-{0}.txt" -f ([guid]::NewGuid().ToString("N")))
                "ADMS readiness test" | Set-Content -Path $testFile -Encoding ASCII -ErrorAction Stop
                Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
                $adminWriteOk = $true
            }
        }
        catch {
            Add-ReadinessNote "ADMIN$ OnePointDomainAgent write/delete check failed via ${TargetFqdn}: $($_.Exception.Message)"
        }
        finally {
            try {
                $deleteArgs = @("use",$uncRoot,"/delete","/y")
                & net.exe @deleteArgs | Out-Null
            }
            catch {
            }

            if ($secretPointer -ne [IntPtr]::Zero) {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($secretPointer)
            }
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
'@; $tokens = $null; $errors = $null; $ast = [System.Management.Automation.Language.Parser]::ParseInput($content,[ref]$tokens,[ref]$errors); if ($errors) { throw "Cannot parse 06 before patch." }; $func = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq "Test-AdmtEndpointReadinessFromAdmtServer" }, $true); if (-not $func) { throw "Function Test-AdmtEndpointReadinessFromAdmtServer not found in 06." }; $content = $content.Remove($func.Extent.StartOffset, $func.Extent.EndOffset - $func.Extent.StartOffset).Insert($func.Extent.StartOffset, $newFunction); Set-Content -Path $path06 -Value $content -Encoding UTF8; Write-Host "Patched 06 ADMT readiness to fix ADMIN$ path duplication and self-heal ADMT server hosts entries." -ForegroundColor Green
