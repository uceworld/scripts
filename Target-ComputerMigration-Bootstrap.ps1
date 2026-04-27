$ErrorActionPreference = 'Stop'

$PolicyLabel = 'TARGET-LANDING-DELAYED'
$ManagementIps = @(
    '10.34.67.138', # Jumpbox
    '10.254.131.30', # Source DC / source management host
    '10.254.131.40', # Secondary source DC
    '10.38.0.36', # Secondary source DC
    '10.34.67.137' # Target DC / target management host
)

$AdmtServerIps = @(
    '10.34.67.132'
)

$FirewallProfiles = @('Domain', 'Private', 'Public')

$TargetAdminPrincipals = @(
    'ID\Admin'
)

$BaseFolder = 'C:\ProgramData\ComputerMigration'
$ScriptFolder = Join-Path $BaseFolder 'Scripts'
$LogFolder = Join-Path $BaseFolder 'StartupLogs'
$WorkFolder = 'C:\Windows\Temp'

New-Item -Path $BaseFolder -ItemType Directory -Force | Out-Null
New-Item -Path $ScriptFolder -ItemType Directory -Force | Out-Null
New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
New-Item -Path $WorkFolder -ItemType Directory -Force | Out-Null

$LogPath = Join-Path $LogFolder ("{0}-{1}.log" -f $PolicyLabel, (Get-Date -Format 'yyyyMMdd-HHmmss'))

function Write-Log {
    param([Parameter(Mandatory)][string]$Message)
    $line = "{0} {1}" -f (Get-Date -Format s), $Message
    Add-Content -Path $LogPath -Value $line
}

function Set-ServiceAutomaticAndRunning {
    param([Parameter(Mandatory)][string]$Name)

    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        Write-Log "Service not found: $Name"
        return
    }

    try {
        Set-Service -Name $Name -StartupType Automatic -ErrorAction Stop
        Write-Log "Service startup type set to Automatic: $Name"
    }
    catch {
        Write-Log "Could not set startup type for $Name :: $($_.Exception.Message)"
    }

    try {
        $service.Refresh()
        if ($service.Status -ne 'Running') {
            Start-Service -Name $Name -ErrorAction Stop
            Write-Log "Service started: $Name"
        }
        else {
            Write-Log "Service already running: $Name"
        }
    }
    catch {
        Write-Log "Could not start service $Name :: $($_.Exception.Message)"
    }
}

function Set-FirewallRuleState {
    param(
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][ValidateSet('Inbound', 'Outbound')][string]$Direction,
        [Parameter(Mandatory)][ValidateSet('TCP', 'UDP')][string]$Protocol,
        [Parameter(Mandatory)][string]$LocalPort,
        [Parameter(Mandatory)][string[]]$RemoteAddresses,
        [Parameter(Mandatory)][string[]]$Profiles,
        [string]$Description = 'Enforced by Computer Migration delayed bootstrap task'
    )

    try {
        $existing = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Log "Existing firewall rule found. Removing old copies: $DisplayName"
            $existing | Remove-NetFirewallRule -ErrorAction Stop
        }

        New-NetFirewallRule `
            -DisplayName $DisplayName `
            -Direction $Direction `
            -Action Allow `
            -Protocol $Protocol `
            -LocalPort $LocalPort `
            -RemoteAddress $RemoteAddresses `
            -Profile $Profiles `
            -Description $Description `
            -ErrorAction Stop | Out-Null

        $created = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction Stop
        $addr = $created | Get-NetFirewallAddressFilter

        Write-Log "Firewall rule created successfully: $DisplayName"
        Write-Log ("Profiles={0}" -f (($created.Profile | Out-String).Trim()))
        Write-Log ("RemoteAddresses={0}" -f (($addr.RemoteAddress | Out-String).Trim()))
    }
    catch {
        Write-Log "Failed to create firewall rule $DisplayName :: $($_.Exception.Message)"
        throw
    }
}

function Test-SmbServerHealthy {
    $lanmanServer = Get-Service -Name 'LanmanServer' -ErrorAction SilentlyContinue
    $port445Listen = Get-NetTCPConnection -LocalPort 445 -State Listen -ErrorAction SilentlyContinue
    $loopback445 = $false

    try {
        $loopback445 = Test-NetConnection 127.0.0.1 -Port 445 -WarningAction SilentlyContinue -InformationLevel Quiet
    }
    catch {
        $loopback445 = $false
    }

    return ($null -ne $lanmanServer -and $lanmanServer.Status -eq 'Running' -and $null -ne $port445Listen -and $loopback445)
}

function Confirm-SmbServerState {
    Write-Log 'Starting SMB server confirmation'

    try {
        $lanmanServer = Get-Service -Name 'LanmanServer' -ErrorAction SilentlyContinue
        if ($null -ne $lanmanServer) {
            Write-Log "LanmanServer current state :: Status=$($lanmanServer.Status) StartType=$($lanmanServer.StartType)"
        }

        $lanmanParams = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -ErrorAction SilentlyContinue
        if ($null -ne $lanmanParams) {
            Write-Log "LanmanServer Parameters :: ServiceDll=$($lanmanParams.ServiceDll) ServiceMain=$($lanmanParams.ServiceMain)"
        }

        $srvSvcExists = Test-Path 'C:\Windows\System32\srvsvc.dll'
        Write-Log "srvsvc.dll exists :: $srvSvcExists"

        $port445Listen = Get-NetTCPConnection -LocalPort 445 -State Listen -ErrorAction SilentlyContinue
        Write-Log ("Local port 445 listening :: {0}" -f ($null -ne $port445Listen))

        $loopback445 = Test-NetConnection 127.0.0.1 -Port 445 -WarningAction SilentlyContinue -InformationLevel Quiet
        Write-Log ("Loopback 445 test :: {0}" -f $loopback445)

        if (Test-SmbServerHealthy) {
            Write-Log 'SMB server is healthy'
        }
        else {
            Write-Log 'SMB server is not healthy; manual operator repair is required'
        }
    }
    catch {
        Write-Log "SMB confirmation failed :: $($_.Exception.Message)"
    }
}

function Set-LocalWinRmState {
    param(
        [int]$MaxAttempts = 5,
        [int]$DelaySeconds = 5
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            Write-Log "Local WinRM enforcement attempt $attempt starting"

            $quickConfigOutput = cmd /c "cd /d $WorkFolder && winrm quickconfig -quiet" 2>&1 | Out-String
            Write-Log ("winrm quickconfig output :: {0}" -f $quickConfigOutput.Trim())

            Start-Sleep -Seconds 2

            $listenerOutput = cmd /c "cd /d $WorkFolder && winrm enumerate winrm/config/listener" 2>&1 | Out-String
            Write-Log ("WinRM listener output :: {0}" -f $listenerOutput.Trim())

            $netstatOutput = cmd /c 'netstat -ano | findstr /r /c:":5985 .*LISTENING"' 2>&1 | Out-String
            Write-Log ("netstat 5985 output :: {0}" -f $netstatOutput.Trim())

            $hasHttp5985 = $listenerOutput -match 'Transport = HTTP' -and $listenerOutput -match 'Port = 5985'
            $isListening = $netstatOutput -match ':5985'

            if ($hasHttp5985 -and $isListening) {
                Write-Log "Local WinRM enforcement succeeded on attempt $attempt"
                return
            }

            Write-Log "Local WinRM not fully ready yet on attempt $attempt"
        }
        catch {
            Write-Log "Set-LocalWinRmState attempt $attempt failed :: $($_.Exception.Message)"
        }

        Start-Sleep -Seconds $DelaySeconds
    }

    throw 'WinRM never reached a local listening state on 5985.'
}

Write-Log "===== Bootstrap begin [$PolicyLabel] ====="

try {
    Set-Location -Path $WorkFolder
    Write-Log "Working directory set to $WorkFolder"
}
catch {
    Write-Log "Could not set working directory :: $($_.Exception.Message)"
}

try {
    $netProfiles = Get-NetConnectionProfile -ErrorAction SilentlyContinue | Select-Object InterfaceAlias, NetworkCategory, IPv4Connectivity, IPv6Connectivity
    if ($netProfiles) {
        foreach ($netProfile in $netProfiles) {
            Write-Log ("NetworkProfile InterfaceAlias={0} Category={1} IPv4={2} IPv6={3}" -f $netProfile.InterfaceAlias, $netProfile.NetworkCategory, $netProfile.IPv4Connectivity, $netProfile.IPv6Connectivity)
        }
    }
}
catch {
    Write-Log "Network profile inspection failed :: $($_.Exception.Message)"
}

Set-ServiceAutomaticAndRunning -Name 'WinRM'
Set-ServiceAutomaticAndRunning -Name 'LanmanServer'
Set-ServiceAutomaticAndRunning -Name 'LanmanWorkstation'
Set-ServiceAutomaticAndRunning -Name 'Netlogon'

try {
    Enable-NetFirewallRule -DisplayGroup 'Windows Remote Management' -ErrorAction SilentlyContinue
    Enable-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -ErrorAction SilentlyContinue
    Enable-NetFirewallRule -DisplayGroup 'Remote Service Management' -ErrorAction SilentlyContinue
    Enable-NetFirewallRule -DisplayGroup 'Windows Management Instrumentation (WMI)' -ErrorAction SilentlyContinue
    Write-Log 'Enabled standard firewall rule groups'
}
catch {
    Write-Log "Firewall group enable issue :: $($_.Exception.Message)"
}

Set-FirewallRuleState `
    -DisplayName 'CM-Allow-WinRM-5985-From-ManagementHosts' `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort '5985' `
    -RemoteAddresses $ManagementIps `
    -Profiles $FirewallProfiles `
    -Description 'Enforced by delayed bootstrap task for management-host WinRM administration'

Set-FirewallRuleState `
    -DisplayName 'CM-Allow-ADMT-RPC-135-From-ADMT' `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort '135' `
    -RemoteAddresses $AdmtServerIps `
    -Profiles $FirewallProfiles `
    -Description 'Enforced by delayed bootstrap task for ADMT RPC access'

Set-FirewallRuleState `
    -DisplayName 'CM-Allow-ADMT-SMB-445-From-ADMT' `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort '445' `
    -RemoteAddresses $AdmtServerIps `
    -Profiles $FirewallProfiles `
    -Description 'Enforced by delayed bootstrap task for ADMT SMB access'

try {
    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Force | Out-Null
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Write-Log 'Attempted to set LocalAccountTokenFilterPolicy=1'
}
catch {
    Write-Log "Registry set failed for LocalAccountTokenFilterPolicy :: $($_.Exception.Message)"
}

try {
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Force | Out-Null
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'AutoShareWks' -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Write-Log 'Attempted to set AutoShareWks=1'
}
catch {
    Write-Log "Registry set failed for AutoShareWks :: $($_.Exception.Message)"
}

foreach ($member in $TargetAdminPrincipals) {
    try {
        $alreadyThere = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | Where-Object { $_.Name -ieq $member }

        if (-not $alreadyThere) {
            Add-LocalGroupMember -Group 'Administrators' -Member $member -ErrorAction Stop
            Write-Log "Added local admin member: $member"
        }
        else {
            Write-Log "Local admin member already present: $member"
        }
    }
    catch {
        Write-Log "Could not add local admin member $member :: $($_.Exception.Message)"
    }
}

Confirm-SmbServerState
Set-LocalWinRmState

try {
    $winRmService = Get-Service -Name 'WinRM' -ErrorAction Stop
    Write-Log "Final WinRM state :: Status=$($winRmService.Status) StartType=$($winRmService.StartType)"
}
catch {
    Write-Log "Could not read final WinRM state :: $($_.Exception.Message)"
}

try {
    $finalListeners = cmd /c "cd /d $WorkFolder && winrm enumerate winrm/config/listener" 2>&1 | Out-String
    Write-Log ("Final WinRM listeners :: {0}" -f ($finalListeners.Trim()))
}
catch {
    Write-Log "Could not read final WinRM listeners :: $($_.Exception.Message)"
}

Write-Log "===== Bootstrap end [$PolicyLabel] ====="
