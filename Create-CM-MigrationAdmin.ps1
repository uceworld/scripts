# Create-CM-MigrationAdmin.ps1
# Purpose:
#   Create or enforce a reusable local migration admin account.
#   Safe to rerun.
#   On every run:
#     - Creates the local user if missing
#     - Enables the user
#     - Enforces the configured password
#     - Enforces password/account settings
#     - Adds the user to local Administrators if missing

[CmdletBinding()]
param ()

$ErrorActionPreference = 'Stop'

$LocalUserName = 'CM-MigrationAdmin'
$PlainTextPassword = 'TStrongPassword!123'
$Description = 'Temporary migration admin account'
$AdministratorsGroup = 'Administrators'

function Write-Info {
    param (
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-Host "[INFO] $Message"
}

function Write-Success {
    param (
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-Host "[SUCCESS] $Message"
}

function Get-CmLocalUser {
    param (
        [Parameter(Mandatory)]
        [string]$UserName
    )

    Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
}

function Test-CmLocalAdministratorMembership {
    param (
        [Parameter(Mandatory)]
        [string]$UserName,

        [Parameter(Mandatory)]
        [string]$GroupName
    )

    $adminMembers = Get-LocalGroupMember -Group $GroupName -ErrorAction Stop

    foreach ($member in $adminMembers) {
        if ($member.Name -eq $UserName) {
            return $true
        }

        if ($member.Name -like "*\$UserName") {
            return $true
        }
    }

    return $false
}

try {
    Write-Info "Starting local migration admin account enforcement."

    if ($Description.Length -gt 48) {
        throw "Description is $($Description.Length) characters. Local user description must be 48 characters or fewer."
    }

    $securePassword = ConvertTo-SecureString $PlainTextPassword -AsPlainText -Force
    $existingUser = Get-CmLocalUser -UserName $LocalUserName

    if ($null -eq $existingUser) {
        Write-Info "Local user '$LocalUserName' does not exist. Creating account."

        New-LocalUser -Name $LocalUserName -Password $securePassword -Description $Description -PasswordNeverExpires -UserMayNotChangePassword -ErrorAction Stop | Out-Null

        Write-Info "Local user '$LocalUserName' was created successfully."
    }
    else {
        Write-Info "Local user '$LocalUserName' already exists. Enforcing password and account settings."

        Set-LocalUser -Name $LocalUserName -Password $securePassword -Description $Description -PasswordNeverExpires $true -UserMayChangePassword $false -ErrorAction Stop
    }

    Enable-LocalUser -Name $LocalUserName -ErrorAction Stop

    Write-Info "Local user '$LocalUserName' is enabled."

    $isLocalAdmin = Test-CmLocalAdministratorMembership -UserName $LocalUserName -GroupName $AdministratorsGroup

    if ($isLocalAdmin) {
        Write-Success "Local user '$LocalUserName' is already a member of the local '$AdministratorsGroup' group. No membership change required."
    }
    else {
        Write-Info "Local user '$LocalUserName' is not a member of '$AdministratorsGroup'. Adding membership now."

        Add-LocalGroupMember -Group $AdministratorsGroup -Member $LocalUserName -ErrorAction Stop

        Write-Success "Local user '$LocalUserName' has been added to the local '$AdministratorsGroup' group."
    }

    Write-Success "Local migration admin account '$LocalUserName' is fully enforced."
    exit 0
}
catch {
    Write-Error "Failed to enforce local migration admin account '$LocalUserName'. Error: $($_.Exception.Message)"
    exit 1
}
