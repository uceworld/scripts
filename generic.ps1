$scriptPath = "C:\AD-MigrationSuite\Backups\Test-CM-PostGpoReadiness.ps1"; New-Item -Path "C:\AD-MigrationSuite\Backups" -ItemType Directory -Force | Out-Null; @'
[CmdletBinding()]
param(
    [string]$OutputPath = "C:\AD-MigrationSuite\Backups\CM-PostGpoReadiness-$((Get-Date).ToString('yyyyMMdd-HHmmss')).csv",
    [switch]$PromptForCredential
)

$ErrorActionPreference = "Stop"

$computers = @(
"TNYCTMP2","PADMIG1AWS","PADDC93AWS","POKTA2AWS","PFILEMIG2NYC","PSQLFS1AWS","PWSUS1AWS","PWSUS2AWS","PKMS1AWS","PPS1AWS","PDIRSYNC1AWS","PSQL1AWS","pswin1dsm","PNYCIPTV1","Z8-MXL0261WYS","pvidflashnt2nyc","PFILEMIG1NYC","pstmfmpro2","PSCHEDULER2AWS","Z8-MXL9204P7Z","Z8-MXL0261WYT","PAUE1REVENUEEXC","padmgmt3aws","padmgmt2aws","padmgmt4aws","padmgmt1aws","padmgmt8aws","padmgmt5aws","pvidflashnt1nyc","PNOETIX1AWS","pdsmpsjump1","PCTW1AWS","DNOETIX1AWS","POKTA1AWS","pvidnettest1aws","Z8-MXL0253ZRV","VM-GLOU-TEMP","5420-7P878C3","5420-DGXN9C3","5420-2PT78C3","5570-FCVRFK3","7430-BK1TKN3","5400-FQKMK13","5570-F706GK3","7430-BZPRKN3","padcsweb2dsm","PIPCAM1DSM","psmsv1nyc","PSTSCN1DSM","ppascd3dsm","wdatest1aws","dsmon1dsm","pbcvm1dsm","p19sql1nyc","p19sql2nyc","5300-6FY6F63","DMATRIX1NYC","DPRESORT6AWS","TPRESORT1AWS","d19sql1nyc","t19sql1nyc","pmvmg1dsm","PSCMS2DSM","pmatrix1nyc","plansw1dsm","PPRESORT1AWS","P16SQL6DSM","padcsweb1dsm","PPRESORTLDS1AWS","E7470-5NH6J72","7490-DT260X2","5040-B2MLJH2","Z8-MXL1143CSL","Z8-MXL11547XS","5420-DPDX7C3","5420-DHRX7C3","pcert1dsm","padcsi1dsm","tjira3aws"
)

$managementIps = @("10.34.67.138","10.254.131.30","10.254.131.40","10.38.0.36","10.34.67.137")
$admtServerIps = @("10.34.67.132")
$localUserName = "CM-MigrationAdmin"
$targetAdminPrincipal = "ID\Admin"
$policyLabel = "TARGET-LANDING-DELAYED"

$credential = $null
if ($PromptForCredential.IsPresent) {
    $credential = Get-Credential -Message "Enter a domain/admin credential that can query the 79 source computers remotely"
}

$remoteCheck = {
    param(
        [string]$LocalUserName,
        [string]$TargetAdminPrincipal,
        [string]$PolicyLabel,
        [string[]]$ManagementIps,
        [string[]]$AdmtServerIps
    )

    $adminMembers = @()
    try {
        $adminMembers = @(Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop)
    }
    catch {
        $adminMembers = @()
    }

    $localUser = Get-LocalUser -Name $LocalUserName -ErrorAction SilentlyContinue

    $serviceNames = @("WinRM","LanmanServer","LanmanWorkstation","Netlogon")
    $serviceMap = @{}
    foreach ($serviceName in $serviceNames) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -ne $service) {
            $serviceMap[$serviceName] = "$($service.Status)/$($service.StartType)"
        }
        else {
            $serviceMap[$serviceName] = "Missing"
        }
    }

    $winRmListeners = @(Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction SilentlyContinue)
    $hasWinRmHttp5985 = $false
    foreach ($listener in $winRmListeners) {
        $transport = ""
        $port = ""
        try { $transport = [string](Get-Item -Path (Join-Path $listener.PSPath "Transport") -ErrorAction SilentlyContinue).Value } catch {}
        try { $port = [string](Get-Item -Path (Join-Path $listener.PSPath "Port") -ErrorAction SilentlyContinue).Value } catch {}
        if ($transport -eq "HTTP" -and $port -eq "5985") {
            $hasWinRmHttp5985 = $true
        }
    }

    $firewallRuleNames = @("CM-Allow-WinRM-5985-From-ManagementHosts","CM-Allow-ADMT-RPC-135-From-ADMT","CM-Allow-ADMT-SMB-445-From-ADMT")
    $firewallResults = @{}
    foreach ($ruleName in $firewallRuleNames) {
        $rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if ($null -eq $rule) {
            $firewallResults[$ruleName] = "Missing"
        }
        else {
            $addressFilter = $rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
            $firewallResults[$ruleName] = "Present Enabled=$($rule.Enabled) Profile=$($rule.Profile) Remote=$($addressFilter.RemoteAddress -join ';')"
        }
    }

    $latfp = ""
    try { $latfp = [string](Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -ErrorAction Stop) } catch { $latfp = "Missing" }

    $autoShareWks = ""
    try { $autoShareWks = [string](Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -ErrorAction Stop) } catch { $autoShareWks = "Missing" }

    $adminShareExists = $false
    try { $adminShareExists = Test-Path "\\localhost\Admin$" } catch { $adminShareExists = $false }

    $latestLog = $null
    try {
        $latestLog = Get-ChildItem -Path "C:\ProgramData\ComputerMigration\StartupLogs" -Filter "$PolicyLabel-*.log" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    }
    catch {
        $latestLog = $null
    }

    $scheduledTasks = @()
    try {
        $scheduledTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like "*ComputerMigration*" -or $_.TaskName -like "*Migration*" -or $_.TaskPath -like "*ComputerMigration*" })
    }
    catch {
        $scheduledTasks = @()
    }

    $localAdminMember = $false
    foreach ($member in $adminMembers) {
        if ($member.Name -ieq $LocalUserName -or $member.Name -like "*\$LocalUserName") {
            $localAdminMember = $true
        }
    }

    $targetAdminMember = $false
    foreach ($member in $adminMembers) {
        if ($member.Name -ieq $TargetAdminPrincipal) {
            $targetAdminMember = $true
        }
    }

    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        RemoteQuery = "Success"
        LocalUserExists = [bool]($null -ne $localUser)
        LocalUserEnabled = if ($null -ne $localUser) { [bool]$localUser.Enabled } else { $false }
        LocalUserPasswordNeverExpires = if ($null -ne $localUser) { [bool]$localUser.PasswordNeverExpires } else { $false }
        LocalUserMayChangePassword = if ($null -ne $localUser) { [bool]$localUser.UserMayChangePassword } else { $false }
        LocalUserIsAdministrator = $localAdminMember
        TargetAdminIsAdministrator = $targetAdminMember
        WinRM = $serviceMap["WinRM"]
        LanmanServer = $serviceMap["LanmanServer"]
        LanmanWorkstation = $serviceMap["LanmanWorkstation"]
        Netlogon = $serviceMap["Netlogon"]
        WinRmHttp5985Listener = $hasWinRmHttp5985
        LocalAccountTokenFilterPolicy = $latfp
        AutoShareWks = $autoShareWks
        AdminShareExists = $adminShareExists
        FirewallWinRM5985 = $firewallResults["CM-Allow-WinRM-5985-From-ManagementHosts"]
        FirewallAdmtRpc135 = $firewallResults["CM-Allow-ADMT-RPC-135-From-ADMT"]
        FirewallAdmtSmb445 = $firewallResults["CM-Allow-ADMT-SMB-445-From-ADMT"]
        BootstrapLogFound = [bool]($null -ne $latestLog)
        BootstrapLogPath = if ($null -ne $latestLog) { $latestLog.FullName } else { "" }
        BootstrapLogLastWriteTime = if ($null -ne $latestLog) { $latestLog.LastWriteTime } else { "" }
        MatchingScheduledTasks = ($scheduledTasks.TaskName -join ";")
    }
}

$results = foreach ($computer in $computers) {
    Write-Host "Checking $computer ..." -ForegroundColor Cyan

    $dnsResolved = $false
    $resolvedIp = ""
    try {
        $dnsRecord = Resolve-DnsName -Name "$computer.ad.mdp.com" -ErrorAction Stop | Where-Object { $_.Type -eq "A" } | Select-Object -First 1
        if ($null -ne $dnsRecord) {
            $dnsResolved = $true
            $resolvedIp = [string]$dnsRecord.IPAddress
        }
    }
    catch {
        $dnsResolved = $false
    }

    $icmpOk = $false
    try { $icmpOk = Test-Connection -ComputerName $computer -Count 1 -Quiet -ErrorAction SilentlyContinue } catch { $icmpOk = $false }

    $port5985 = $false
    try { $port5985 = Test-NetConnection -ComputerName $computer -Port 5985 -InformationLevel Quiet -WarningAction SilentlyContinue } catch { $port5985 = $false }

    $port445 = $false
    try { $port445 = Test-NetConnection -ComputerName $computer -Port 445 -InformationLevel Quiet -WarningAction SilentlyContinue } catch { $port445 = $false }

    if (-not $port5985) {
        [pscustomobject]@{
            ComputerName = $computer
            DnsResolved = $dnsResolved
            ResolvedIp = $resolvedIp
            Ping = $icmpOk
            Port5985FromJumpbox = $port5985
            Port445FromJumpbox = $port445
            RemoteQuery = "Skipped: WinRM 5985 not reachable from Jumpbox"
            LocalUserExists = $false
            LocalUserEnabled = $false
            LocalUserPasswordNeverExpires = $false
            LocalUserMayChangePassword = ""
            LocalUserIsAdministrator = $false
            TargetAdminIsAdministrator = $false
            WinRM = ""
            LanmanServer = ""
            LanmanWorkstation = ""
            Netlogon = ""
            WinRmHttp5985Listener = ""
            LocalAccountTokenFilterPolicy = ""
            AutoShareWks = ""
            AdminShareExists = ""
            FirewallWinRM5985 = ""
            FirewallAdmtRpc135 = ""
            FirewallAdmtSmb445 = ""
            BootstrapLogFound = $false
            BootstrapLogPath = ""
            BootstrapLogLastWriteTime = ""
            MatchingScheduledTasks = ""
            OverallReady = $false
            FailureSummary = "WinRM 5985 not reachable"
        }
        continue
    }

    try {
        $invokeParams = @{
            ComputerName = $computer
            ScriptBlock = $remoteCheck
            ArgumentList = @($localUserName,$targetAdminPrincipal,$policyLabel,$managementIps,$admtServerIps)
            ErrorAction = "Stop"
        }

        if ($null -ne $credential) {
            $invokeParams.Credential = $credential
        }

        $remoteResult = Invoke-Command @invokeParams

        $checks = @()
        if (-not $dnsResolved) { $checks += "DNS failed" }
        if (-not $port5985) { $checks += "Port 5985 closed" }
        if (-not $port445) { $checks += "Port 445 closed" }
        if (-not $remoteResult.LocalUserExists) { $checks += "CM-MigrationAdmin missing" }
        if (-not $remoteResult.LocalUserEnabled) { $checks += "CM-MigrationAdmin disabled" }
        if (-not $remoteResult.LocalUserPasswordNeverExpires) { $checks += "PasswordNeverExpires not true" }
        if ($remoteResult.LocalUserMayChangePassword -ne $false) { $checks += "UserMayChangePassword not false" }
        if (-not $remoteResult.LocalUserIsAdministrator) { $checks += "CM-MigrationAdmin not local admin" }
        if (-not $remoteResult.TargetAdminIsAdministrator) { $checks += "ID\Admin not local admin" }
        if ($remoteResult.WinRM -notlike "Running/*") { $checks += "WinRM not running" }
        if ($remoteResult.LanmanServer -notlike "Running/*") { $checks += "LanmanServer not running" }
        if ($remoteResult.LanmanWorkstation -notlike "Running/*") { $checks += "LanmanWorkstation not running" }
        if ($remoteResult.Netlogon -notlike "Running/*") { $checks += "Netlogon not running" }
        if (-not $remoteResult.WinRmHttp5985Listener) { $checks += "WinRM HTTP 5985 listener missing" }
        if ($remoteResult.LocalAccountTokenFilterPolicy -ne "1") { $checks += "LocalAccountTokenFilterPolicy not 1" }
        if ($remoteResult.AutoShareWks -ne "1") { $checks += "AutoShareWks not 1" }
        if (-not $remoteResult.AdminShareExists) { $checks += "Admin$ share missing" }
        if ($remoteResult.FirewallWinRM5985 -like "Missing*") { $checks += "WinRM firewall rule missing" }
        if ($remoteResult.FirewallAdmtRpc135 -like "Missing*") { $checks += "ADMT RPC firewall rule missing" }
        if ($remoteResult.FirewallAdmtSmb445 -like "Missing*") { $checks += "ADMT SMB firewall rule missing" }
        if (-not $remoteResult.BootstrapLogFound) { $checks += "Bootstrap log missing" }

        [pscustomobject]@{
            ComputerName = $computer
            DnsResolved = $dnsResolved
            ResolvedIp = $resolvedIp
            Ping = $icmpOk
            Port5985FromJumpbox = $port5985
            Port445FromJumpbox = $port445
            RemoteQuery = $remoteResult.RemoteQuery
            LocalUserExists = $remoteResult.LocalUserExists
            LocalUserEnabled = $remoteResult.LocalUserEnabled
            LocalUserPasswordNeverExpires = $remoteResult.LocalUserPasswordNeverExpires
            LocalUserMayChangePassword = $remoteResult.LocalUserMayChangePassword
            LocalUserIsAdministrator = $remoteResult.LocalUserIsAdministrator
            TargetAdminIsAdministrator = $remoteResult.TargetAdminIsAdministrator
            WinRM = $remoteResult.WinRM
            LanmanServer = $remoteResult.LanmanServer
            LanmanWorkstation = $remoteResult.LanmanWorkstation
            Netlogon = $remoteResult.Netlogon
            WinRmHttp5985Listener = $remoteResult.WinRmHttp5985Listener
            LocalAccountTokenFilterPolicy = $remoteResult.LocalAccountTokenFilterPolicy
            AutoShareWks = $remoteResult.AutoShareWks
            AdminShareExists = $remoteResult.AdminShareExists
            FirewallWinRM5985 = $remoteResult.FirewallWinRM5985
            FirewallAdmtRpc135 = $remoteResult.FirewallAdmtRpc135
            FirewallAdmtSmb445 = $remoteResult.FirewallAdmtSmb445
            BootstrapLogFound = $remoteResult.BootstrapLogFound
            BootstrapLogPath = $remoteResult.BootstrapLogPath
            BootstrapLogLastWriteTime = $remoteResult.BootstrapLogLastWriteTime
            MatchingScheduledTasks = $remoteResult.MatchingScheduledTasks
            OverallReady = ($checks.Count -eq 0)
            FailureSummary = ($checks -join "; ")
        }
    }
    catch {
        [pscustomobject]@{
            ComputerName = $computer
            DnsResolved = $dnsResolved
            ResolvedIp = $resolvedIp
            Ping = $icmpOk
            Port5985FromJumpbox = $port5985
            Port445FromJumpbox = $port445
            RemoteQuery = "Failed: $($_.Exception.Message)"
            LocalUserExists = ""
            LocalUserEnabled = ""
            LocalUserPasswordNeverExpires = ""
            LocalUserMayChangePassword = ""
            LocalUserIsAdministrator = ""
            TargetAdminIsAdministrator = ""
            WinRM = ""
            LanmanServer = ""
            LanmanWorkstation = ""
            Netlogon = ""
            WinRmHttp5985Listener = ""
            LocalAccountTokenFilterPolicy = ""
            AutoShareWks = ""
            AdminShareExists = ""
            FirewallWinRM5985 = ""
            FirewallAdmtRpc135 = ""
            FirewallAdmtSmb445 = ""
            BootstrapLogFound = ""
            BootstrapLogPath = ""
            BootstrapLogLastWriteTime = ""
            MatchingScheduledTasks = ""
            OverallReady = $false
            FailureSummary = "Remote query failed: $($_.Exception.Message)"
        }
    }
}

$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "Readiness report written to: $OutputPath" -ForegroundColor Green
Write-Host ""
$results | Group-Object OverallReady | Select-Object Name,Count | Format-Table -AutoSize
Write-Host ""
$results | Where-Object { $_.OverallReady -ne $true } | Select-Object ComputerName,ResolvedIp,Port5985FromJumpbox,Port445FromJumpbox,FailureSummary | Format-Table -AutoSize
'@ | Set-Content -Path $scriptPath -Encoding UTF8; Write-Host "Created $scriptPath"
