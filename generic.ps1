$repairScriptPath = "C:\AD-MigrationSuite\Computer-Migration\Scripts\06b-Repair-AdmtEndpointReadiness.ps1"; @'
[CmdletBinding()]
param(
    [string]$ConfigPath = "C:\AD-MigrationSuite\Computer-Migration\Config\MigrationAutomationConfig.json",
    [string]$InventoryPath = "C:\AD-MigrationSuite\Computer-Migration\Config\MasterInventory-Merged.csv",
    [string[]]$ComputerNames = @(),
    [string]$Wave = "",
    [string]$RunId = "",
    [string]$ResultRoot = "",
    [switch]$PlanOnly
)

$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$commonModule = Join-Path $scriptRoot "Migration.Common.psm1"

if (-not (Test-Path $commonModule)) {
    throw "Required module not found: $commonModule"
}

Import-Module $commonModule -Force

if (-not (Test-Path $ConfigPath)) {
    throw "Config file not found: $ConfigPath"
}

$config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json

if (-not $config.CredentialFiles.LocalAdmin) {
    throw "CredentialFiles.LocalAdmin is missing from config."
}

if (-not (Test-Path $config.CredentialFiles.LocalAdmin)) {
    throw "Local admin credential file not found: $($config.CredentialFiles.LocalAdmin)"
}

if (-not $config.AdmtServerIp) {
    throw "AdmtServerIp is missing from config."
}

if (-not (Test-Path $InventoryPath)) {
    throw "Inventory file not found: $InventoryPath"
}

$localAdminCredential = Import-Clixml -Path $config.CredentialFiles.LocalAdmin
$inventoryRows = @(Import-Csv -Path $InventoryPath)

if ($ComputerNames -and $ComputerNames.Count -gt 0) {
    $nameSet = @{}
    foreach ($name in $ComputerNames) {
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            $nameSet[$name.ToUpperInvariant()] = $true
        }
    }

    $targetRows = @($inventoryRows | Where-Object { $nameSet.ContainsKey([string]$_.ComputerName.ToUpperInvariant()) })
}
else {
    $targetRows = @($inventoryRows | Where-Object { $_.InScope -eq "True" })
}

if (-not [string]::IsNullOrWhiteSpace($Wave)) {
    $targetRows = @($targetRows | Where-Object { $_.Wave -eq $Wave })
}

if (-not $targetRows -or $targetRows.Count -eq 0) {
    throw "No endpoint rows selected for ADMT endpoint readiness repair."
}

if ([string]::IsNullOrWhiteSpace($RunId)) {
    $RunId = Get-Date -Format "yyyyMMdd-HHmmss"
}

if ([string]::IsNullOrWhiteSpace($ResultRoot)) {
    $ResultRoot = Join-Path (Split-Path -Parent $InventoryPath) "..\Results\AdmtEndpointHealing-$RunId"
    $ResultRoot = [System.IO.Path]::GetFullPath($ResultRoot)
}

New-Item -ItemType Directory -Path $ResultRoot -Force | Out-Null
$resultPath = Join-Path $ResultRoot ("ADMT-EndpointHealing-" + $RunId + ".csv")
$logPath = Join-Path $ResultRoot ("ADMT-EndpointHealing-" + $RunId + ".log")

function Write-HealingLog {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("INFO","WARN","ERROR","SUCCESS")][string]$Level = "INFO"
    )

    $line = "{0} [{1}] {2}" -f (Get-Date -Format s), $Level, $Message
    Add-Content -Path $logPath -Value $line
    Write-Host $line
}

$repairBlock = {
    param(
        [string]$AdmtServerIp,
        [string]$TargetDomainFqdn
    )

    $notes = New-Object System.Collections.Generic.List[string]
    $dnsRegisterAttempted = $false

    function Add-Note {
        param([string]$Value)
        if (-not [string]::IsNullOrWhiteSpace($Value)) {
            $script:notes.Add($Value) | Out-Null
        }
    }

    function Set-ServiceReady {
        param([Parameter(Mandatory)][string]$Name)

        $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($null -eq $service) {
            Add-Note "Service not found: ${Name}"
            return
        }

        try {
            Set-Service -Name $Name -StartupType Automatic -ErrorAction Stop
        }
        catch {
            Add-Note "Failed to set ${Name} startup Automatic: $($_.Exception.Message)"
        }

        try {
            $service.Refresh()
            if ($service.Status -ne "Running") {
                Start-Service -Name $Name -ErrorAction Stop
            }
        }
        catch {
            Add-Note "Failed to start ${Name}: $($_.Exception.Message)"
        }
    }

    try {
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "ServiceDll" -Value "%SystemRoot%\System32\srvsvc.dll" -PropertyType ExpandString -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "ServiceMain" -Value "ServiceMain" -PropertyType String -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name AutoShareServer -Value 1 -Type DWord -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name AutoShareWks -Value 1 -Type DWord -ErrorAction Stop
    }
    catch {
        Add-Note "Failed to repair LanmanServer registry values: $($_.Exception.Message)"
    }

    Set-ServiceReady -Name "LanmanWorkstation"
    Set-ServiceReady -Name "SamSS"
    Set-ServiceReady -Name "LanmanServer"
    Set-ServiceReady -Name "WinRM"

    try {
        Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing" -ErrorAction SilentlyContinue
        Enable-NetFirewallRule -DisplayGroup "Remote Service Management" -ErrorAction SilentlyContinue
        Enable-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)" -ErrorAction SilentlyContinue
    }
    catch {
        Add-Note "Firewall display-group enable issue: $($_.Exception.Message)"
    }

    $ruleNames = @(
        "CM-Allow-ADMT-SMB-445-From-ADMT",
        "CM-Allow-ADMT-RPC-135-From-ADMT",
        "CM-Allow-ADMT-RPC-Dynamic-From-ADMT"
    )

    foreach ($ruleName in $ruleNames) {
        try {
            Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        }
        catch {
            Add-Note "Could not remove existing firewall rule ${ruleName}: $($_.Exception.Message)"
        }
    }

    try {
        New-NetFirewallRule -DisplayName "CM-Allow-ADMT-SMB-445-From-ADMT" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 445 -RemoteAddress $AdmtServerIp -Profile Domain,Private,Public -Description "Enforced by ADMT endpoint readiness healing" -ErrorAction Stop | Out-Null
    }
    catch {
        Add-Note "Failed to create SMB 445 firewall rule: $($_.Exception.Message)"
    }

    try {
        New-NetFirewallRule -DisplayName "CM-Allow-ADMT-RPC-135-From-ADMT" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 135 -RemoteAddress $AdmtServerIp -Profile Domain,Private,Public -Description "Enforced by ADMT endpoint readiness healing" -ErrorAction Stop | Out-Null
    }
    catch {
        Add-Note "Failed to create RPC 135 firewall rule: $($_.Exception.Message)"
    }

    try {
        New-NetFirewallRule -DisplayName "CM-Allow-ADMT-RPC-Dynamic-From-ADMT" -Direction Inbound -Action Allow -Protocol TCP -LocalPort "49152-65535" -RemoteAddress $AdmtServerIp -Profile Domain,Private,Public -Description "Enforced by ADMT endpoint readiness healing" -ErrorAction Stop | Out-Null
    }
    catch {
        Add-Note "Failed to create RPC dynamic firewall rule: $($_.Exception.Message)"
    }

    try {
        ipconfig /registerdns | Out-Null
        $dnsRegisterAttempted = $true
    }
    catch {
        Add-Note "DNS registration attempt failed: $($_.Exception.Message)"
    }

    $computerSystem = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    if ($computerSystem -and $computerSystem.PartOfDomain) {
        try {
            Restart-Service -Name Netlogon -Force -ErrorAction SilentlyContinue
            ipconfig /registerdns | Out-Null
            $dnsRegisterAttempted = $true
        }
        catch {
            Add-Note "Netlogon restart/DNS registration issue: $($_.Exception.Message)"
        }
    }

    Start-Sleep -Seconds 5

    $lanmanServer = Get-Service -Name LanmanServer -ErrorAction SilentlyContinue
    $port445Listening = [bool](Get-NetTCPConnection -LocalPort 445 -State Listen -ErrorAction SilentlyContinue)
    $adminShareExists = [bool](Get-SmbShare -Name "ADMIN$" -ErrorAction SilentlyContinue)
    $firewall445Rule = [bool](Get-NetFirewallRule -DisplayName "CM-Allow-ADMT-SMB-445-From-ADMT" -ErrorAction SilentlyContinue)

    if (-not $lanmanServer -or $lanmanServer.Status -ne "Running") {
        Add-Note "LanmanServer is not running after repair"
    }

    if (-not $port445Listening) {
        Add-Note "Local TCP 445 is not listening after repair"
    }

    if (-not $adminShareExists) {
        Add-Note "ADMIN$ share does not exist after repair"
    }

    if (-not $firewall445Rule) {
        Add-Note "Firewall rule CM-Allow-ADMT-SMB-445-From-ADMT missing after repair"
    }

    $finalStatus = if ($lanmanServer -and $lanmanServer.Status -eq "Running" -and $port445Listening -and $adminShareExists -and $firewall445Rule) { "Repaired" } else { "NeedsAttention" }

    [pscustomobject]@{
        Hostname = hostname
        PartOfDomain = if ($computerSystem) { [bool]$computerSystem.PartOfDomain } else { $false }
        Domain = if ($computerSystem) { [string]$computerSystem.Domain } else { "" }
        LanmanServerStatus = if ($lanmanServer) { [string]$lanmanServer.Status } else { "Missing" }
        Port445Listening = $port445Listening
        AdminShareExists = $adminShareExists
        Firewall445Rule = $firewall445Rule
        DnsRegisterAttempted = $dnsRegisterAttempted
        FinalStatus = $finalStatus
        Notes = ($notes -join "; ")
    }
}

function Invoke-EndpointRepair {
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][pscredential]$Credential,
        [Parameter(Mandatory)][string]$ComputerName
    )

    Invoke-TrustedRemoteCommand -ComputerName $Target -Credential $Credential -LogPath $logPath -ArgumentList @($config.AdmtServerIp, $config.TargetDomainFqdn) -ScriptBlock $repairBlock
}

Write-HealingLog -Message "ADMT endpoint readiness repair started. Selected endpoints: $($targetRows.Count). ADMT server: $($config.AdmtServerIp)"

$results = foreach ($row in $targetRows) {
    $computerName = [string]$row.ComputerName
    $ipAddress = if (-not [string]::IsNullOrWhiteSpace([string]$row.IPAddress)) { [string]$row.IPAddress } else { $computerName }

    Write-HealingLog -Message "[$computerName][$ipAddress] Starting endpoint repair"

    if ($PlanOnly) {
        [pscustomobject]@{
            ComputerName = $computerName
            IPAddress = $ipAddress
            FinalStatus = "PlanOnly"
            Hostname = ""
            PartOfDomain = ""
            Domain = ""
            LanmanServerStatus = ""
            Port445Listening = ""
            AdminShareExists = ""
            Firewall445Rule = ""
            DnsRegisterAttempted = ""
            Notes = "PlanOnly: would repair LanmanServer service registration, ADMIN$, firewall 135/445/RPC dynamic, DNS registration"
        }
        continue
    }

    try {
        $remoteResult = Invoke-EndpointRepair -Target $ipAddress -Credential $localAdminCredential -ComputerName $computerName

        [pscustomobject]@{
            ComputerName = $computerName
            IPAddress = $ipAddress
            FinalStatus = $remoteResult.FinalStatus
            Hostname = $remoteResult.Hostname
            PartOfDomain = $remoteResult.PartOfDomain
            Domain = $remoteResult.Domain
            LanmanServerStatus = $remoteResult.LanmanServerStatus
            Port445Listening = $remoteResult.Port445Listening
            AdminShareExists = $remoteResult.AdminShareExists
            Firewall445Rule = $remoteResult.Firewall445Rule
            DnsRegisterAttempted = $remoteResult.DnsRegisterAttempted
            Notes = $remoteResult.Notes
        }
    }
    catch {
        $firstError = $_.Exception.Message

        if ($localAdminCredential.UserName -like ".\*") {
            $localUserName = $localAdminCredential.UserName.Substring(2)
            $fallbackCredential = [pscredential]::new(("{0}\{1}" -f $computerName,$localUserName), $localAdminCredential.Password)

            try {
                Write-HealingLog -Message "[$computerName][$ipAddress] Primary local credential failed. Retrying with $($fallbackCredential.UserName)." -Level "WARN"
                $remoteResult = Invoke-EndpointRepair -Target $ipAddress -Credential $fallbackCredential -ComputerName $computerName

                [pscustomobject]@{
                    ComputerName = $computerName
                    IPAddress = $ipAddress
                    FinalStatus = $remoteResult.FinalStatus
                    Hostname = $remoteResult.Hostname
                    PartOfDomain = $remoteResult.PartOfDomain
                    Domain = $remoteResult.Domain
                    LanmanServerStatus = $remoteResult.LanmanServerStatus
                    Port445Listening = $remoteResult.Port445Listening
                    AdminShareExists = $remoteResult.AdminShareExists
                    Firewall445Rule = $remoteResult.Firewall445Rule
                    DnsRegisterAttempted = $remoteResult.DnsRegisterAttempted
                    Notes = "Fallback credential used. First error: $firstError :: $($remoteResult.Notes)"
                }

                continue
            }
            catch {
                $firstError = "$firstError | Fallback failed: $($_.Exception.Message)"
            }
        }

        [pscustomobject]@{
            ComputerName = $computerName
            IPAddress = $ipAddress
            FinalStatus = "Failed"
            Hostname = ""
            PartOfDomain = ""
            Domain = ""
            LanmanServerStatus = ""
            Port445Listening = ""
            AdminShareExists = ""
            Firewall445Rule = ""
            DnsRegisterAttempted = ""
            Notes = $firstError
        }
    }
}

$results | Export-Csv -Path $resultPath -NoTypeInformation -Encoding UTF8

$failedRows = @($results | Where-Object { $_.FinalStatus -ne "Repaired" -and $_.FinalStatus -ne "PlanOnly" })
Write-HealingLog -Message "ADMT endpoint readiness repair finished. Result file: $resultPath. Remaining non-repaired endpoints: $($failedRows.Count)"

if ($failedRows.Count -gt 0) {
    $failedRows | Format-Table -AutoSize
    return
}

$results | Format-Table -AutoSize
return
'@ | Set-Content -Path $repairScriptPath -Encoding UTF8; Write-Host "Replaced $repairScriptPath with clean credential-fallback healing version." -ForegroundColor Green
