<#
.SYNOPSIS
  Post-clone hardening script for an ISOLATED lab DC cloned from production.

  Steps (interactive, with verification):

    1. Remove all other DC server objects from AD Sites & Services (recursive),
       and verify only this DC remains. This is a HARD PRE-REQUISITE.
    2. Rename Domain Controller (Requires Reboot).
    3. Update Sites and Subnets (Add/Remove Sites/Subnets, assign DC to Site).
    4. Ensure current DC holds ALL FSMO Roles (seize if missing).
    5. Add new UPN suffix (e.g. 'lab.local') at forest level.
    6. Update all enabled user UPNs to 'samAccountName@<new_suffix>'.
    7. Rotate KRBTGT password twice (random values).
    8. Reset passwords for all enabled users (except current, krbtgt, Guest)
       to a lab default and set ChangePasswordAtLogon = $true.
    9. Create or repair 'labadmin' Domain Admin with a random password.

  WARNING:
    - FOR ISOLATED LAB USE ONLY.
    - DO NOT run in production.
#>

# region Initialization & Helper Functions

# Set standard window title
$Host.UI.RawUI.WindowTitle = "Cloned ADDS Lab Builder"
# Optional: Clear-Host to start fresh
# Clear-Host

# State Management Configuration
$StateFilePath = "$env:SystemDrive\LabClone_State.json"

# ---------------------------------------------------------
# Console Helper Functions (UX Polish)
# ---------------------------------------------------------

function Write-Header {
    param([string]$Title)
    Write-Host ""
    Write-Host ("==== {0} ====" -f $Title) -ForegroundColor Cyan
}

function Write-Step {
    param(
        [int]$Number,
        [string]$Description
    )
    Write-Host ""
    Write-Host ("[{0}] {1}" -f "Step $Number", $Description) -ForegroundColor Cyan
    Update-HUD -Step "Step $Number/9"
}

function Update-HUD {
    param([string]$Step)
    
    # 1. Update Window Title
    $Host.UI.RawUI.WindowTitle = "Cloned ADDS Lab Builder - $Step"

    # 2. Draw visual overlay (3-line box)
    try {
        if ([System.Console]::BufferWidth -gt 0) {
            $origX = [System.Console]::CursorLeft
            $origY = [System.Console]::CursorTop
            $origFg = [System.Console]::ForegroundColor
            $origBg = [System.Console]::BackgroundColor
            
            $winTop = [System.Console]::WindowTop
            $winWidth = [System.Console]::WindowWidth
            
            # Content
            $content = " $Step ".ToUpper()
            $boxWidth = $content.Length + 2
            $x = $winWidth - $boxWidth - 2
            $y = $winTop
            
            if ($x -gt 0 -and ($y + 2) -lt [System.Console]::BufferHeight) {
                # Colors: Cyan border, White text, DarkBlue background
                $borderColor = [System.ConsoleColor]::Cyan
                $textColor   = [System.ConsoleColor]::White
                $bgColor     = [System.ConsoleColor]::DarkBlue
                
                [System.Console]::BackgroundColor = $bgColor
                
                # Top Line
                [System.Console]::SetCursorPosition($x, $y)
                [System.Console]::ForegroundColor = $borderColor
                [System.Console]::Write("╔" + ('═' * ($boxWidth - 2)) + "╗")
                
                # Middle Line
                [System.Console]::SetCursorPosition($x, $y + 1)
                [System.Console]::Write("║")
                [System.Console]::ForegroundColor = $textColor
                [System.Console]::Write($content)
                [System.Console]::ForegroundColor = $borderColor
                [System.Console]::Write("║")
                
                # Bottom Line
                [System.Console]::SetCursorPosition($x, $y + 2)
                [System.Console]::Write("╚" + ('═' * ($boxWidth - 2)) + "╝")
            }
            
            # Restore Original State
            [System.Console]::ForegroundColor = $origFg
            [System.Console]::BackgroundColor = $origBg
            [System.Console]::SetCursorPosition($origX, $origY)
        }
    } catch {
        # Silently ignore errors
    }
}

function Get-LabState {
    if (Test-Path $StateFilePath) {
        try {
            $json = Get-Content $StateFilePath -Raw | ConvertFrom-Json
            # Convert PSObject to Hashtable for easier manipulation
            $state = @{}
            $json.PSObject.Properties | ForEach-Object { $state[$_.Name] = $_.Value }
            return $state
        } catch {
            Write-Warn "Failed to load state file. Starting fresh."
            return @{}
        }
    }
    return @{}
}

function Save-LabState {
    param([hashtable]$State)
    try {
        $State | ConvertTo-Json | Set-Content $StateFilePath -Force
    } catch {
        Write-Warn "Failed to save state file: $($_.Exception.Message)"
    }
}

function Write-Info {
    param([string]$Message)
    Write-Host ("[*] {0}" -f $Message)
}

function Write-Warn {
    param([string]$Message)
    Write-Host ("[!] {0}" -f $Message) -ForegroundColor Yellow
}

function Write-Success {
    param([string]$Message)
    Write-Host ("[+] {0}" -f $Message) -ForegroundColor Green
}

function Write-ErrorLine {
    param([string]$Message)
    Write-Host ("[X] {0}" -f $Message) -ForegroundColor Red
}

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    if ($script:LogFile) {
        Add-Content -Path $script:LogFile -Value $logMessage
    }
    
    # Also write to console with appropriate color mapping
    switch ($Level) {
        "ERROR"   { Write-ErrorLine $Message }
        "WARN"    { Write-Warn $Message }
        "SUCCESS" { Write-Success $Message }
        default   { Write-Info $Message }
    }
}

function Ask-YesNo {
    param([string]$Prompt)
    while ($true) {
        $resp = Read-Host "$Prompt (Y/N)"
        switch ($resp.ToUpper()) {
            'Y' { return $true }
            'N' { return $false }
            default { Write-Warn "Please answer Y or N." }
        }
    }
}

function Get-NextCIDR {
    param([string]$CurrentCIDR)
    try {
        if ($CurrentCIDR -match '^(?<ip>[\d\.]+)/(?<bits>\d+)$') {
            $ipStr = $matches['ip']
            $bits = [int]$matches['bits']
            $ipAddr = [System.Net.IPAddress]::Parse($ipStr)
            $bytes = $ipAddr.GetAddressBytes()
            
            # Convert bytes to Int64 to avoid overflow/sign issues
            $val = [long]0
            foreach ($b in $bytes) {
                $val = ($val -shl 8) + $b
            }
            
            # Calculate increment: 2^(32-bits)
            if ($bits -lt 0 -or $bits -gt 32) { return $null }
            $increment = [long][Math]::Pow(2, 32 - $bits)
            
            # Add increment
            $newVal = $val + $increment
            
            # Check for 32-bit overflow ( > 255.255.255.255 )
            if ($newVal -gt 4294967295) { return $null }

            # Convert back to bytes
            $newBytes = New-Object byte[] 4
            for ($i = 3; $i -ge 0; $i--) {
                $newBytes[$i] = ($newVal -band 0xFF)
                $newVal = ($newVal -shr 8)
            }
            
            $newIp = [System.Net.IPAddress]::new($newBytes)
            return "$($newIp.IPAddressToString)/$bits"
        }
    } catch {
        return $null
    }
    return $null
}

function Read-InputWithEscape {
    param(
        [string]$Prompt,
        [string]$Default
    )
    
    $msg = "$Prompt"
    if (-not [string]::IsNullOrEmpty($Default)) {
        $msg += " [Default: $Default]"
    }
    $msg += " (ESC to finish): "
    
    Write-Host -NoNewline $msg
    
    try {
        $inputStr = ""
        
        while ($true) {
            if ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)
                
                if ($key.Key -eq 'Escape') {
                    Write-Host "" # Newline
                    return $null
                }
                elseif ($key.Key -eq 'Enter') {
                    Write-Host "" # Newline
                    if ($inputStr.Length -eq 0 -and -not [string]::IsNullOrEmpty($Default)) {
                        return $Default
                    }
                    return $inputStr
                }
                elseif ($key.Key -eq 'Backspace') {
                    if ($inputStr.Length -gt 0) {
                        $inputStr = $inputStr.Substring(0, $inputStr.Length - 1)
                        # Move cursor back, write space, move back
                        Write-Host -NoNewline "`b `b"
                    }
                }
                elseif ($key.KeyChar -ge 32 -and $key.KeyChar -le 126) {
                    $inputStr += $key.KeyChar
                    Write-Host -NoNewline $key.KeyChar
                }
            }
            else {
                Start-Sleep -Milliseconds 50
            }
        }
    }
    catch {
        # Fallback if Console::ReadKey fails (e.g. ISE)
        Write-Host "" 
        Write-Warn "Console input not fully supported, falling back to Read-Host. (Enter 'EXIT' to finish)"
        $res = Read-Host "Input"
        if ($res -eq 'EXIT') { return $null }
        if ($res -eq '' -and $Default) { return $Default }
        return $res
    }
}

function Invoke-IfNotDryRun {
    param(
        [string]$Description,
        [scriptblock]$Action
    )
    if ($script:DryRun) {
        Write-Host ("[DRY RUN] {0}" -f $Description) -ForegroundColor Yellow
        return $true
    } else {
        Write-Host ("[APPLY]  {0}" -f $Description)
        try {
            & $Action
            return $true
        }
        catch {
            $msg = "ERROR during '$Description': $($_.Exception.Message)"
            Write-ErrorLine $msg
            $script:Errors += $msg
            return $false
        }
    }
}

function New-StrongPassword {
    param(
        [int]$Length = 24
    )
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@$%^&*()-_=+[]{}'
    -join ((1..$Length) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
}

function Force-DeleteADObjectRecursive {
    param(
        [string]$Identity,
        [string]$Description = "Force Remove Object"
    )
    
    # Get Current User SID for permission modification
    $currentUserSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User

    try {
        Write-Log "Starting force removal for: $Identity"
        Write-Info "Gathering all child objects for force removal..."
        # 1. Find all descendant objects (Subtree) plus the object itself
        # Sort by DistinguishedName length DESCENDING to delete children before parents
        $allObjects = Get-ADObject -SearchBase $Identity -Filter * -SearchScope Subtree -ErrorAction Stop | 
                      Sort-Object -Property @{Expression={$_.DistinguishedName.Length}; Descending=$true}
        
        $count = $allObjects.Count
        Write-Log "Found $count object(s) to remove (including self) under $Identity"
        Write-Info "Found $count object(s) to remove."
        
        $i = 0
        foreach ($obj in $allObjects) {
            $i++
            Write-Progress -Activity "Force Removing Objects" -Status "Deleting $($obj.Name)" -PercentComplete (($i / $count) * 100)
            
            Write-Log "[$i/$count] Processing object: '$($obj.Name)' ($($obj.DistinguishedName))"
            
            try {
                # Disable accidental deletion protection
                Write-Log "  -> Disabling accidental deletion protection..."
                Set-ADObject -Identity $obj.DistinguishedName -ProtectedFromAccidentalDeletion $false -ErrorAction SilentlyContinue
                
                # Attempt to grant Full Control to current user (to fix Access Denied on system containers)
                if (-not $script:DryRun) {
                    try {
                        Write-Log "  -> Attempting to grant Full Control to current user..."
                        $drivePath = "AD:\" + $obj.DistinguishedName
                        $acl = Get-Acl -Path $drivePath
                        
                        # Create Access Rule: Allow, Current User, GenericAll (Full Control)
                        $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                            $currentUserSid,
                            [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
                            [System.Security.AccessControl.AccessControlType]::Allow
                        )
                        
                        $acl.AddAccessRule($rule)
                        Set-Acl -Path $drivePath -AclObject $acl -ErrorAction Stop
                        Write-Log "  -> Permissions updated successfully."
                    } catch {
                         Write-Log "  -> Warning: Failed to update permissions: $($_.Exception.Message). Attempting delete anyway." -Level "WARN"
                    }
                }

                # Delete the object explicitly
                Write-Log "  -> Removing object..."
                Remove-ADObject -Identity $obj.DistinguishedName -Recursive:$false -Confirm:$false -ErrorAction Stop
                Write-Log "  -> Success."
            } catch {
                # Ignore "doesn't exist" errors (in case it was deleted by a side effect)
                if ($_.Exception.Message -match "could not be found" -or $_.CategoryInfo.Reason -eq "ADIdentityNotFoundException") {
                     Write-Log "  -> Object not found (already deleted). Skipping." -Level "WARN"
                } else {
                    Write-Log "  -> ERROR: Failed to delete '$($obj.Name)': $($_.Exception.Message)" -Level "ERROR"
                    Write-Warn "Failed to delete '$($obj.Name)': $($_.Exception.Message)"
                    throw $_
                }
            }
        }
        Write-Progress -Activity "Force Removing Objects" -Completed
        Write-Log "Force removal COMPLETED for: $Identity"
        return $true
    } catch {
        Write-Log "Force removal CRITICAL FAILURE for '$Identity': $($_.Exception.Message)" -Level "ERROR"
        Write-Warn "Force removal failed for '$Identity': $($_.Exception.Message)"
        return $false
    }
}

function Remove-ADObjectSafe {
    param(
        [string]$Identity,
        [string]$Description
    )
    Write-Log "Requesting safe removal: $Description (DN: $Identity)"
    Invoke-IfNotDryRun -Description $Description -Action {
        Write-Log "Executing Remove-ADObject -Identity $Identity -Recursive"
        Remove-ADObject -Identity $Identity -Recursive -Confirm:$false
    } | Out-Null
}

function Test-IPInSubnet {
    param([string]$IP, [string]$CIDR)
    try {
        $IPObj = [System.Net.IPAddress]::Parse($IP)
        $CIDRParts = $CIDR.Split('/')
        if ($CIDRParts.Length -lt 2) { return $false }
        $NetObj = [System.Net.IPAddress]::Parse($CIDRParts[0])
        $Bits = [int]$CIDRParts[1]

        $IPBytes = $IPObj.GetAddressBytes()
        $NetBytes = $NetObj.GetAddressBytes()

        if ($IPBytes.Length -ne $NetBytes.Length) { return $false }

        $ByteIndex = 0
        while ($Bits -ge 8) {
            if ($IPBytes[$ByteIndex] -ne $NetBytes[$ByteIndex]) { return $false }
            $ByteIndex++
            $Bits -= 8
        }
        if ($Bits -gt 0) {
            $Mask = [byte](255 -shl (8 - $Bits))
            if (($IPBytes[$ByteIndex] -band $Mask) -ne ($NetBytes[$ByteIndex] -band $Mask)) { return $false }
        }
        return $true
    } catch { return $false }
}

function Select-FromList {
    param(
        [array]$InputObject,
        [string]$Property = "Name",
        [string]$Title = "Select items"
    )
    if ($null -eq $InputObject -or $InputObject.Count -eq 0) {
        Write-Warn "No items to select."
        return @()
    }

    Write-Host ""
    Write-Host ("--- {0} ---" -f $Title) -ForegroundColor Cyan
    $index = 1
    foreach ($item in $InputObject) {
        $val = $item.$Property
        Write-Host ("[{0,2}] {1}" -f $index, $val)
        $index++
    }
    
    $selection = Read-Host "Enter ID(s) to select (comma-separated, e.g. '1,3', or 'all', or enter to skip)"
    
    if ([string]::IsNullOrWhiteSpace($selection)) {
        return @()
    }
    
    if ($selection -eq 'all') {
        return $InputObject
    }

    $selectedItems = @()
    $indices = $selection -split ','
    foreach ($i in $indices) {
        $i = $i.Trim()
        if ($i -match '^\d+$' -and [int]$i -ge 1 -and [int]$i -le $InputObject.Count) {
            $selectedItems += $InputObject[[int]$i - 1]
        }
    }
    
    return $selectedItems
}

function Test-DCSrvRecords {
    param([string]$DomainName)
    
    Write-Info "Verifying key SRV records for domain '$DomainName'..."
    $srvRecords = @("_ldap._tcp.dc._msdcs.$DomainName", "_kerberos._tcp.dc._msdcs.$DomainName")
    $allGood = $true

    foreach ($rec in $srvRecords) {
        try {
            $result = Resolve-DnsName -Name $rec -Type SRV -ErrorAction Stop
            if ($result) {
                Write-Success "SRV Record found: $rec"
                # Optional: Check if it points to THIS DC
                $localHost = $env:COMPUTERNAME
                $match = $result | Where-Object { $_.NameTarget -like "*$localHost*" }
                if ($match) {
                    Write-Success "  -> Points to local DC ($($match.NameTarget))"
                } else {
                    Write-Warn "  -> WARNING: Does not appear to point to local DC ($localHost). Target: $($result.NameTarget)"
                }
            }
        } catch {
            Write-ErrorLine "SRV Record MISSING or lookup failed: $rec"
            $allGood = $false
        }
    }
    return $allGood
}

function Export-PasswordCSV {
    param(
        [array]$Records,
        [string]$FilePath
    )
    if ($Records.Count -eq 0) {
        Write-Log "No password records to export." -Level "WARN"
        return
    }
    
    try {
        $Records | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
        Write-Log "Password CSV exported to: $FilePath" -Level "SUCCESS"
        Write-Warn "This CSV contains sensitive passwords. Store securely and delete when no longer needed."
    } catch {
        $msg = "Failed to export password CSV: $($_.Exception.Message)"
        Write-Log $msg -Level "ERROR"
        $script:Errors += $msg
    }
}

# endregion

# ---------------------------------------------------------
# SAFETY CHECK - CRITICAL WARNING
# ---------------------------------------------------------

Clear-Host
Write-Host "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor Red -BackgroundColor Black
Write-Host "!!!                       CRITICAL WARNING                            !!!" -ForegroundColor Red -BackgroundColor Black
Write-Host "!!!                                                                   !!!" -ForegroundColor Red -BackgroundColor Black
Write-Host "!!!  THIS SCRIPT IS DESTRUCTIVE AND INTENDED FOR ISOLATED LABS ONLY.  !!!" -ForegroundColor Red -BackgroundColor Black
Write-Host "!!!                                                                   !!!" -ForegroundColor Red -BackgroundColor Black
Write-Host "!!!  DO NOT RUN THIS IN A PRODUCTION ENVIRONMENT.                     !!!" -ForegroundColor Red -BackgroundColor Black
Write-Host "!!!                                                                   !!!" -ForegroundColor Red -BackgroundColor Black
Write-Host "!!!  IT WILL SEIZE ROLES, DELETE DOMAIN CONTROLLERS, AND RESET        !!!" -ForegroundColor Red -BackgroundColor Black
Write-Host "!!!  PASSWORDS ACROSS THE DOMAIN.                                     !!!" -ForegroundColor Red -BackgroundColor Black
Write-Host "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor Red -BackgroundColor Black
Write-Host ""
Write-Host "To confirm you are running this in an ISOLATED LAB environment," -ForegroundColor Yellow
Write-Host "type 'PROCEED' (all caps) and press Enter." -ForegroundColor Yellow
Write-Host ""

$confirmation = Read-Host "Confirmation"
if ($confirmation -ne "PROCEED") {
    Write-Host "Confirmation failed. Exiting." -ForegroundColor Red
    exit
}
Write-Host "Confirmation received. Proceeding..." -ForegroundColor Green
Start-Sleep -Seconds 2

# ---------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------

# Load State
$LabState = Get-LabState
if ($LabState.Count -gt 0) {
    Write-Info "Found previous session state."
}

Write-Header "Pre-flight checks"

# Check for ActiveDirectory module
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-ErrorLine "ActiveDirectory module is not available. This script requires RSAT-AD-PowerShell."
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

# Test DC connectivity
try {
    $null = Get-ADDomainController -ErrorAction Stop
    Write-Success "Pre-flight check: Successfully connected to domain controller."
} catch {
    Write-ErrorLine "Cannot connect to domain controller. $($_.Exception.Message)"
    exit 1
}

# ---------------------------------------------------------
# Initialize script variables
# ---------------------------------------------------------

$script:Errors = @()
$script:PasswordRecords = @()  # For CSV export
$script:LogFile = $null

# Initialize summary tracking
$JobSummary = @()

# Initialize UPN suffix (used in multiple steps)
$UpnSuffix = 'lab.local'

# ---------------------------------------------------------
# Gather initial context
# ---------------------------------------------------------

Write-Header "Initial context"

$domain  = Get-ADDomain
$rootDSE = Get-ADRootDSE
$configNC = $rootDSE.ConfigurationNamingContext

$localDC = Get-ADDomainController -Identity $env:COMPUTERNAME -ErrorAction Stop

Write-Info ("Current DC (env):        {0}" -f $env:COMPUTERNAME)
Write-Info ("Current DC (AD name):    {0}" -f $localDC.Name)
Write-Info ("Current DC HostName:     {0}" -f $localDC.HostName)
Write-Info ("Domain DNS name:         {0}" -f $domain.DNSRoot)
Write-Info ("Domain DN:               {0}" -f $domain.DistinguishedName)
Write-Info ("Sites & Services search: {0}" -f "CN=Sites,$configNC")

# Setup log file
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
# Use script root if available, otherwise use current directory
$scriptBasePath = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$script:LogFile = Join-Path $scriptBasePath "lab-clone-$timestamp.log"
Write-Log "Script execution started. Log file: $script:LogFile"

# Ask for dry-run mode
$script:DryRun = Ask-YesNo "Run in DRY RUN mode (no changes)"
Write-Log "DryRun mode: $script:DryRun"

if ($script:DryRun) {
    Write-Warn "DryRun mode ENABLED – no changes will be written to AD."
} else {
    Write-Success "DryRun mode DISABLED – changes WILL be written to AD."
}

# ---------------------------------------------------------
# Step 1 – Remove other DCs from Sites & Services (HARD PRE-REQ)
# ---------------------------------------------------------

Write-Step 1 "Remove other DCs from Sites & Services (pre-requisite)"

if ($LabState['Step1'] -eq 'Completed') {
    Write-Success "Step 1 previously completed. Skipping."
    $step1Result = "OK"
} else {
    $runStep1 = Ask-YesNo "Proceed with Step 1 (remove other DC server objects recursively)?"
    $step1Result = "SKIPPED"

    if ($runStep1) {

    $serverSearchBase = "CN=Sites,$configNC"
    $servers = @(Get-ADObject -SearchBase $serverSearchBase -LDAPFilter "(objectClass=server)" -Properties distinguishedName,name)

    if (-not $servers) {
            Write-Success "No server objects found under Sites. Nothing to do."
            # Condition already satisfied - no other servers exist
            $step1Result = "OK"
        } else {
            Write-Info ("Found {0} server object(s) under Sites." -f $servers.Count)
            $otherServers = $servers | Where-Object { $_.Name -ne $localDC.Name }

            if (-not $otherServers) {
                Write-Success "No other DC server objects found. Only this DC exists in Sites."
                # Condition already satisfied - no other servers exist
                $step1Result = "OK"
            } else {
                Write-Info ("Other DC server objects to remove: {0}" -f $otherServers.Count)

                foreach ($srv in $otherServers) {
                    Write-Host ""
                    Write-Info "Processing server object: $($srv.Name)"
                    Write-Info "  DN: $($srv.DistinguishedName)"
                    Remove-ADObjectSafe -Identity $srv.DistinguishedName -Description "Remove server object (recursive)"
                }

                if (-not $script:DryRun) {
                    # Verification – re-query servers
                    $serversAfter = Get-ADObject -SearchBase $serverSearchBase -LDAPFilter "(objectClass=server)" -Properties name
                    $otherAfter = $serversAfter | Where-Object { $_.Name -ne $localDC.Name }

                    if (-not $otherAfter) {
                        Write-Success "Verification: Only this DC's server object remains in Sites & Services."
                        $step1Result = "OK"
                    } else {
                        Write-ErrorLine "Verification FAILED: Additional server objects still present:"
                        $otherAfter | ForEach-Object { Write-ErrorLine "  $_" }
                        $script:Errors += "Step 1 verification failed: extra server objects remain under Sites."
                        $step1Result = "FAIL"
                    }
                } else {
                    Write-Warn "Dry run – server objects would be removed. Pre-requisite condition would be satisfied."
                    # In dry run, we assume success if we would remove the servers
                    $step1Result = "OK (DryRun)"
                }
            }
        }
    } else {
        Write-Warn "Step 1 skipped by user. Pre-requisite NOT satisfied."
        $step1Result = "SKIPPED"
    }

    if ($step1Result -eq "OK") {
        $LabState['Step1'] = 'Completed'
        Save-LabState -State $LabState
    }
}

$JobSummary += [PSCustomObject]@{ Step = "1. Remove other DCs"; Status = $step1Result }

# Hard gate: if pre-req not completed/skipped (unless already clean), skip remaining steps.
# Note: If it was OK (DryRun), we consider that passing for the sake of script flow, but warn.
if ($step1Result -eq "FAIL" -or $step1Result -eq "SKIPPED") {
    Write-Header "Aborting"
    Write-ErrorLine "Pre-requisite (Step 1) not completed successfully. Remaining steps will be skipped."
    Write-Log "Step 1 pre-requisite not met. Aborting remaining steps." -Level "ERROR"
} else {

    # ---------------------------------------------------------
    # Step 2 – Rename Domain Controller
    # ---------------------------------------------------------

    Write-Step 2 "Rename Domain Controller (Optional)"

    if ($LabState['Step2'] -eq 'Completed') {
        Write-Success "Step 2 previously completed (DC Renamed). Skipping."
        $step2Result = "OK"
    } elseif ($LabState['Step2'] -eq 'PendingReboot') {
        $targetName = $LabState['TargetName']
        if ($env:COMPUTERNAME -eq $targetName) {
            Write-Success "DC Rename verification successful. Current name matches target '$targetName'."
            $LabState['Step2'] = 'Completed'
            Save-LabState -State $LabState
            $step2Result = "OK"
        } else {
            Write-ErrorLine "DC Rename verification FAILED. Current: '$env:COMPUTERNAME', Target: '$targetName'."
            Write-Warn "A reboot may still be pending or the rename failed."
            $step2Result = "FAIL"
        }
    } else {
        $runStep2 = Ask-YesNo "Proceed with Step 2 (Rename DC and REBOOT if changed)?"
        if ($runStep2) {
            $currentName = $env:COMPUTERNAME
            $newName = Read-Host "Enter new name for Domain Controller (Current: $currentName)"
            
            if (-not [string]::IsNullOrWhiteSpace($newName) -and $newName -ne $currentName) {
                Invoke-IfNotDryRun -Description "Rename Computer from '$currentName' to '$newName'" -Action {
                    Rename-Computer -NewName $newName -Force -ErrorAction Stop
                }
                
                if (-not $script:DryRun) {
                    $LabState['Step2'] = 'PendingReboot'
                    $LabState['TargetName'] = $newName
                    Save-LabState -State $LabState
                    
                    Write-Warn "Computer renamed. A REBOOT IS REQUIRED immediately to continue."
                    Write-Success "Progress has been saved. After rebooting, run this script again to continue where you left off."
                    
                    if (Ask-YesNo "Reboot now to apply changes and continue later?") {
                        Restart-Computer -Force
                        exit
                    } else {
                        Write-Warn "You must reboot manually before running this script again to complete the rename."
                        exit
                    }
                }
                $step2Result = "OK (DryRun)"
            } else {
                Write-Info "Name unchanged or empty. Skipping rename."
                $step2Result = "SKIPPED"
            }
        } else {
            Write-Info "Step 2 skipped by user."
            $step2Result = "SKIPPED"
        }
    }
    $JobSummary += [PSCustomObject]@{ Step = "2. Rename DC"; Status = $step2Result }

    # ---------------------------------------------------------
    # Step 3 – Update Sites and Subnets
    # ---------------------------------------------------------

    Write-Step 3 "Update Sites and Subnets"

    $runStep3 = Ask-YesNo "Proceed with Step 3 (configure Sites, Subnets, and DC location)?"
    $step3Result = "SKIPPED"

    if ($runStep3) {
        # --- Add Sites and Subnets ---
        while ($true) {
            Write-Host ""
            if (-not (Ask-YesNo "Do you want to add a NEW Site?")) { break }
            
            $newSiteName = Read-Host "Enter new Site Name"
            if ([string]::IsNullOrWhiteSpace($newSiteName)) { continue }

            Invoke-IfNotDryRun -Description "Create Site '$newSiteName'" -Action {
                New-ADReplicationSite -Name $newSiteName -ErrorAction Stop
            } | Out-Null
            
            # Subnets for this site
            $nextCidrSuggestion = $null
            while ($true) {
                Write-Host ""
                Write-Host "Add a Subnet to Site '$newSiteName'" -ForegroundColor Cyan
                
                # Assume user wants to add, allow Escape to finish
                $newCidr = Read-InputWithEscape -Prompt "Enter Subnet CIDR" -Default $nextCidrSuggestion
                
                if ($null -eq $newCidr) {
                    # Escape pressed
                    break
                }
                
                if ([string]::IsNullOrWhiteSpace($newCidr)) {
                    continue
                }

                Invoke-IfNotDryRun -Description "Create Subnet '$newCidr' in Site '$newSiteName'" -Action {
                    New-ADReplicationSubnet -Name $newCidr -Site $newSiteName -ErrorAction Stop
                } | Out-Null
                
                # Calculate next default
                $nextCidrSuggestion = Get-NextCIDR -CurrentCIDR $newCidr
            }
        }

        # Check for immediate move after creating new sites/subnets
        $dcIp = $localDC.IPv4Address
        $allSubnets = Get-ADReplicationSubnet -Filter *
        $matchedSubnet = $null
        foreach ($sub in $allSubnets) {
            if (Test-IPInSubnet -IP $dcIp -CIDR $sub.Name) {
                $matchedSubnet = $sub
                break
            }
        }
        
        # If the DC is now in a subnet that maps to a specific site, offer to move it NOW
        # This prevents issues where the user tries to delete the old site while the DC is still technically there
        if ($matchedSubnet) {
            $currentServerObj = Get-ADObject -SearchBase "CN=Sites,$configNC" -LDAPFilter "(&(objectClass=server)(name=$($localDC.Name)))"
            $currentSiteDn = $currentServerObj.DistinguishedName -replace "^CN=.*?CN=Servers,"
            
            # Extract simple name from DN
            $currentSiteName = if ($currentSiteDn -match "CN=([^,]+)") { $matches[1] } else { $currentSiteDn }
            $targetSiteName = $matchedSubnet.Site
            if ($targetSiteName -match "CN=([^,]+)") { $targetSiteName = $matches[1] }

            if ($currentSiteName -ne $targetSiteName) {
                Write-Host ""
                Write-Warn ("DC is currently in site '{0}' but IP matches subnet '{1}' in site '{2}'." -f $currentSiteName, $matchedSubnet.Name, $targetSiteName)
                if (Ask-YesNo "Move DC to site '$targetSiteName' now (RECOMMENDED before removing old sites)?") {
                    Invoke-IfNotDryRun -Description "Move DC '$($localDC.Name)' to Site '$targetSiteName'" -Action {
                        Move-ADObject -Identity $currentServerObj.DistinguishedName -TargetPath "CN=Servers,CN=$targetSiteName,CN=Sites,$configNC"
                    } | Out-Null
                    # Refresh localDC object location reference for later checks
                    $localDC = Get-ADDomainController -Identity $env:COMPUTERNAME
                }
            }
        }

        # --- Remove Sites and Subnets ---
        while ($true) {
            Write-Host ""
            if (-not (Ask-YesNo "Do you want to REMOVE existing Sites or Subnets?")) { break }

            $remType = Read-Host "Remove (S)ites or su(B)nets? (S/B)"
            
            if ($remType -eq 'S') {
                $allSites = Get-ADReplicationSite -Filter * | Sort-Object Name
                $selectedSites = @(Select-FromList -InputObject $allSites -Property "Name" -Title "Available Sites")
                
                # Progress bar for removing sites if multiple
                $i = 0
                foreach ($site in $selectedSites) {
                    $i++
                    Write-Progress -Activity "Removing Sites" -Status "Processing $($site.Name)" -PercentComplete (($i / $selectedSites.Count) * 100)

                    # Safety check: Is the local DC in this site?
                    $serverInSite = Get-ADObject -SearchBase $site.DistinguishedName -LDAPFilter "(&(objectClass=server)(name=$($localDC.Name)))"
                    if ($serverInSite) {
                        Write-ErrorLine ("Cannot remove site '{0}' because the current DC is located in it." -f $site.Name)
                        Write-Warn "Please move the DC to another site before deleting this one."
                        continue
                    }

                    Write-Info "Checking site '$($site.Name)' for subnets..."
                    $siteDn = $site.DistinguishedName
                    $assocSubnets = Get-ADReplicationSubnet -Filter {Site -eq $siteDn}
                    
                    if ($assocSubnets) {
                        Write-Warn ("Site '{0}' has {1} associated subnet(s):" -f $site.Name, $assocSubnets.Count)
                        $assocSubnets | ForEach-Object { Write-Warn "  - $($_.Name)" }
                        
                        if (Ask-YesNo "Do you want to DELETE these subnets and then the site?") {
                            foreach ($sub in $assocSubnets) {
                                Invoke-IfNotDryRun -Description "Remove Subnet '$($sub.Name)'" -Action {
                                    Remove-ADReplicationSubnet -Identity $sub.DistinguishedName -Confirm:$false -ErrorAction Stop
                                } | Out-Null
                            }
                            
                            # Check for and remove Site Links referencing this site
                            $siteLinks = Get-ADObject -SearchBase "CN=Inter-Site Transports,CN=Sites,$configNC" -LDAPFilter "(&(objectClass=siteLink)(siteList=$($site.DistinguishedName)))"
                            if ($siteLinks) {
                                Write-Warn ("Site '{0}' is referenced by {1} Site Link(s). Removing references..." -f $site.Name, $siteLinks.Count)
                                foreach ($link in $siteLinks) {
                                    if ($link.Name -eq "DEFAULTIPSITELINK") {
                                        Write-Warn "Skipping deletion of default site link 'DEFAULTIPSITELINK' to prevent errors."
                                        continue
                                    }
                                    Invoke-IfNotDryRun -Description "Remove Site Link '$($link.Name)'" -Action {
                                        Remove-ADObject -Identity $link.DistinguishedName -Recursive -Confirm:$false -ErrorAction Stop
                                    } | Out-Null
                                }
                            }

                            # Now delete site
                            # Use Remove-ADObject -Recursive (Generic) instead of Remove-ADReplicationSite
                            # This matches the "old script" behavior for object removal and handles children better
                            Invoke-IfNotDryRun -Description "Remove Site '$($site.Name)'" -Action {
                                try {
                                    Write-Log "Attempting standard recursive removal of site: $($site.DistinguishedName)"
                                    Remove-ADObject -Identity $site.DistinguishedName -Recursive -Confirm:$false -ErrorAction Stop
                                    Write-Log "Standard removal succeeded for: $($site.DistinguishedName)"
                                } catch {
                                    $ex = $_.Exception
                                    Write-Log "Standard recursive removal failed: $($ex.Message)" -Level "WARN"
                                    Write-Warn "Standard recursive removal failed: $($ex.Message)"
                                    
                                    if ($ex.Message -match "Access is denied" -or $ex.Message -match "privileges") {
                                        Write-Log "Access denied error detected. Initiating FORCE removal sequence for site: $($site.Name)"
                                        Write-Info "Access denied. Attempting FORCE removal (unprotecting all children)..."
                                        
                                        # Use the force helper to unprotect everything in the site and nuke it
                                        $res = Force-DeleteADObjectRecursive -Identity $site.DistinguishedName
                                        
                                        if (-not $res) {
                                            Write-Log "Force removal returned failure for site: $($site.Name)" -Level "ERROR"
                                            throw "Force removal also failed. Please check permissions manually on '$($site.DistinguishedName)'."
                                        }
                                    } else {
                                        Write-Log "Non-access-denied error encountered. Re-throwing." -Level "ERROR"
                                        throw $_
                                    }
                                }
                            } | Out-Null
                        } else {
                            Write-Warn "Skipping removal of site '$($site.Name)'."
                        }
                    } else {
                        # No subnets, just delete
                        Invoke-IfNotDryRun -Description "Remove Site '$($site.Name)'" -Action {
                             try {
                                Write-Log "Attempting standard recursive removal of site (no subnets): $($site.DistinguishedName)"
                                Remove-ADObject -Identity $site.DistinguishedName -Recursive -Confirm:$false -ErrorAction Stop
                                Write-Log "Standard removal succeeded for: $($site.DistinguishedName)"
                            } catch {
                                $ex = $_.Exception
                                Write-Log "Standard removal failed: $($ex.Message)" -Level "WARN"
                                Write-Warn "Standard removal failed: $($ex.Message)"
                                if ($ex.Message -match "Access is denied" -or $ex.Message -match "privileges") {
                                    Write-Log "Access denied error detected. Initiating FORCE removal sequence for site: $($site.Name)"
                                    Write-Info "Access denied. Attempting FORCE removal (unprotecting all children)..."
                                        
                                    # Use the force helper to unprotect everything in the site and nuke it
                                    $res = Force-DeleteADObjectRecursive -Identity $site.DistinguishedName
                                    
                                    if (-not $res) {
                                        Write-Log "Force removal returned failure for site: $($site.Name)" -Level "ERROR"
                                        throw "Force removal also failed. Please check permissions manually on '$($site.DistinguishedName)'."
                                    }
                                } else {
                                    Write-Log "Non-access-denied error encountered. Re-throwing." -Level "ERROR"
                                    throw $_
                                }
                            }
                        } | Out-Null
                    }
                }
                Write-Progress -Activity "Removing Sites" -Completed

            } elseif ($remType -eq 'B') {
                $allSubnets = Get-ADReplicationSubnet -Filter * | Sort-Object Name
                # Create wrapper objects for display with Site Name extracted from DN
                $displayList = $allSubnets | Select-Object @{N="Label";E={
                    $siteName = if ($_.Site -match "CN=([^,]+)") { $matches[1] } else { $_.Site }
                    "$($_.Name) (Site: $siteName)"
                }}, @{N="Object";E={$_}}
                
                $selectedWrappers = @(Select-FromList -InputObject $displayList -Property "Label" -Title "Available Subnets")
                
                $j = 0
                foreach ($wrap in $selectedWrappers) {
                    $j++
                    Write-Progress -Activity "Removing Subnets" -Status "Processing $($wrap.Object.Name)" -PercentComplete (($j / $selectedWrappers.Count) * 100)
                    
                    $sub = $wrap.Object
                    Invoke-IfNotDryRun -Description "Remove Subnet '$($sub.Name)'" -Action {
                        Remove-ADReplicationSubnet -Identity $sub.DistinguishedName -Confirm:$false -ErrorAction Stop
                    } | Out-Null
                }
                Write-Progress -Activity "Removing Subnets" -Completed
            }
        }

        # --- Final Assign DC to Site check (in case not done above) ---
        Write-Host ""
        Write-Info "Checking DC Site assignment..."

        $dcIp = $localDC.IPv4Address
        Write-Info "Current DC IP: $dcIp"

        # Find matching subnet
        $allSubnets = Get-ADReplicationSubnet -Filter *
        $matchedSubnet = $null
        foreach ($sub in $allSubnets) {
            if (Test-IPInSubnet -IP $dcIp -CIDR $sub.Name) {
                $matchedSubnet = $sub
                break
            }
        }

        $suggestedSite = if ($matchedSubnet) { $matchedSubnet.Site } else { "Default-First-Site-Name" }
        # Clean up suggested site if it's a DN
        if ($suggestedSite -match "CN=([^,]+)") { $suggestedSite = $matches[1] }
        
        if ($matchedSubnet) {
            Write-Success "DC IP falls within subnet '$($matchedSubnet.Name)'."
        } else {
            Write-Warn "DC IP does not match any known AD subnet."
        }

        $targetSite = Read-Host "Enter Site Name for this DC (Default: '$suggestedSite')"
        if ([string]::IsNullOrWhiteSpace($targetSite)) {
            $targetSite = $suggestedSite
        }

        # Verify site exists
        $siteExists = $false
        if ($script:DryRun) { $siteExists = $true } # Assume exist
        else {
            try { $null = Get-ADReplicationSite -Identity $targetSite -ErrorAction Stop; $siteExists = $true }
            catch { Write-ErrorLine "Site '$targetSite' does not exist!" }
        }

        if ($siteExists) {
            # Move DC Server Object
            # Find the server object first
            $serverObj = Get-ADObject -SearchBase "CN=Sites,$configNC" -LDAPFilter "(&(objectClass=server)(name=$($localDC.Name)))"
            
            if ($serverObj) {
                # Check if already in correct site
                if ($serverObj.DistinguishedName -like "*CN=$targetSite,CN=Sites,*") {
                    Write-Success "DC is already in site '$targetSite'."
                } else {
                    $descMove = "Move DC '$($localDC.Name)' to Site '$targetSite'"
                    Invoke-IfNotDryRun -Description $descMove -Action {
                        Move-ADObject -Identity $serverObj.DistinguishedName -TargetPath "CN=Servers,CN=$targetSite,CN=Sites,$configNC"
                    } | Out-Null
                }
            } else {
                Write-ErrorLine "ERROR: Could not locate DC server object in Sites container."
            }
        }

        $step3Result = "OK"

        # --- DNS / SRV Verification ---
        if (-not $script:DryRun) {
            Write-Host ""
            if (Ask-YesNo "Perform DNS/SRV record validation check?") {
                Write-Info "Running DNS checks..."
                Test-DCSrvRecords -DomainName $domain.DNSRoot
            }
        }

    } else {
        Write-Info "Step 3 skipped by user."
    }

    $JobSummary += [PSCustomObject]@{ Step = "3. Update Sites/Subnets"; Status = $step3Result }

    # ---------------------------------------------------------
    # Step 4 – Ensure this DC holds ALL FSMO Roles
    # ---------------------------------------------------------

    Write-Step 4 "Ensure current DC holds all FSMO roles"

    $runStep4 = Ask-YesNo "Proceed with Step 4 (verify / seize all FSMO roles)?"
    $step4Result = "SKIPPED"

    if ($runStep4) {
        $domain = Get-ADDomain
        $forest = Get-ADForest
        
        $fsmoRoles = @(
            @{ Name = "SchemaMaster";           GetHolder = { (Get-ADForest).SchemaMaster } },
            @{ Name = "DomainNamingMaster";     GetHolder = { (Get-ADForest).DomainNamingMaster } },
            @{ Name = "PDCEmulator";            GetHolder = { (Get-ADDomain).PDCEmulator } },
            @{ Name = "RIDMaster";              GetHolder = { (Get-ADDomain).RIDMaster } },
            @{ Name = "InfrastructureMaster";   GetHolder = { (Get-ADDomain).InfrastructureMaster } }
        )

        Write-Info "Local DC: $($localDC.Name) ($($localDC.HostName))"
        Write-Host ""
        
        $allRolesOk = $true
        $rIndex = 0

        foreach ($role in $fsmoRoles) {
            $rIndex++
            $roleName = $role.Name
            
            # Since FSMO checks are quick, progress bar might be overkill but consistent
            Write-Progress -Activity "Checking FSMO Roles" -Status "Checking $roleName" -PercentComplete (($rIndex / $fsmoRoles.Count) * 100)

            $currentHolder = & $role.GetHolder
            
            Write-Info "Checking $roleName..."
            Write-Info "  Current Holder: $currentHolder"

            $isOnLocal = ($currentHolder -eq $localDC.HostName) -or 
                         ($currentHolder -eq $localDC.Name) -or 
                         ($currentHolder -eq $localDC.NTDSSettingsObjectDN)

            if ($isOnLocal) {
                Write-Success "  Status: OK (Already on local DC)"
            } else {
                Write-Warn "  Status: MISSING (Needs seizure)"
                
                $desc = "Seize $roleName FSMO role to $($localDC.Name)"
                $ok = Invoke-IfNotDryRun -Description $desc -Action {
                    Move-ADDirectoryServerOperationMasterRole -Identity $localDC `
                        -OperationMasterRole $roleName `
                        -Force `
                        -Confirm:$false
                }

                if ($ok -and -not $script:DryRun) {
                    # Verify
                    $newHolder = & $role.GetHolder
                    
                    $verified = ($newHolder -eq $localDC.HostName) -or 
                                ($newHolder -eq $localDC.Name) -or 
                                ($newHolder -eq $localDC.NTDSSettingsObjectDN)
                                
                    if ($verified) {
                        Write-Success "  Verification: $roleName successfully seized."
                    } else {
                        Write-ErrorLine "  Verification FAILED: $roleName not held by local DC."
                        $script:Errors += "Step 4 verification failed: $roleName could not be seized."
                        $allRolesOk = $false
                    }
                } elseif ($script:DryRun) {
                    # Assume success in dry run
                } else {
                     $allRolesOk = $false
                }
            }
            Write-Host ""
        }
        Write-Progress -Activity "Checking FSMO Roles" -Completed
        
        if ($allRolesOk) {
            $step4Result = "OK"
            Write-Success "All FSMO roles are held by this DC."
            Write-Log "Step 4: All FSMO roles verified/seized successfully." -Level "SUCCESS"
        } else {
             $step4Result = "WARN"
             Write-Warn "WARNING: One or more FSMO roles could not be seized."
             Write-Log "Step 4: One or more FSMO roles missing." -Level "WARN"
        }

    } else {
        Write-Info "Step 4 skipped by user."
    }

    $JobSummary += [PSCustomObject]@{ Step = "4. FSMO Roles"; Status = $step4Result }

    # Dependency check: Step 4 should succeed (ideally) but we don't hard stop the script
    if ($step4Result -eq "FAIL" -or $step4Result -eq "WARN") {
        Write-Host ""
        Write-Warn "Step 4 (FSMO Roles) did not complete successfully. Continuing anyway, but this may cause issues."
        Write-Log "Step 4 did not complete successfully, but continuing with remaining steps." -Level "WARN"
    }

    # ---------------------------------------------------------
    # Step 5 – Add UPN suffix (and remove others)
    # ---------------------------------------------------------
    
    $defaultUpnSuffix = 'lab.local'
    Write-Step 5 "Configure forest UPN suffixes"

    $runStep5 = Ask-YesNo "Proceed with Step 5 (configure UPN suffix and remove others)?"
    $step5Result = "SKIPPED"

    if ($runStep5) {
        
        # Prompt for UPN suffix
        $inputSuffix = Read-Host "Enter the desired UPN suffix (default: '$defaultUpnSuffix')"
        if (-not [string]::IsNullOrWhiteSpace($inputSuffix)) {
            $UpnSuffix = $inputSuffix
        }
        Write-Info "Using UPN suffix: $UpnSuffix"

        $forest = Get-ADForest
        
        # 1. Add the desired suffix if missing
        if ($forest.UPNSuffixes -contains $UpnSuffix) {
            Write-Success "UPN suffix '$UpnSuffix' already present on forest '$($forest.Name)'. No add required."
        } else {
            $desc = "Add UPN suffix '$UpnSuffix' to forest '$($forest.Name)'"
            Invoke-IfNotDryRun -Description $desc -Action {
                Set-ADForest -Identity $forest.Name -UPNSuffixes @{ Add = $UpnSuffix }
            } | Out-Null
        }

        # 2. Remove other suffixes (INTERACTIVE)
        $forest = Get-ADForest # Refresh forest object
        $suffixesToRemove = $forest.UPNSuffixes | Where-Object { $_ -ne $UpnSuffix }
        
        if ($suffixesToRemove) {
             Write-Warn "Found extraneous UPN suffixes: $($suffixesToRemove -join ', ')"
             
             $removeAll = $false
             $askRemoval = Read-Host "Remove these extraneous suffixes? (Y)es / (N)o / (A)ll"
             
             if ($askRemoval -eq 'A') { $removeAll = $true }
             
             if ($askRemoval -eq 'Y' -or $askRemoval -eq 'A') {
                 foreach ($remSuffix in $suffixesToRemove) {
                    $doRemove = $removeAll
                    if (-not $doRemove) {
                        $doRemove = Ask-YesNo "Remove suffix '$remSuffix'?"
                    }
                    
                    if ($doRemove) {
                        $descRemove = "Remove extraneous UPN suffix '$remSuffix' from forest"
                        Invoke-IfNotDryRun -Description $descRemove -Action {
                            Set-ADForest -Identity $forest.Name -UPNSuffixes @{ Remove = $remSuffix }
                        } | Out-Null
                    }
                 }
             }
        } else {
            Write-Success "No extraneous UPN suffixes found."
        }

        # Verification
        if (-not $script:DryRun) {
            $forestAfter = Get-ADForest
            $hasTarget = $forestAfter.UPNSuffixes -contains $UpnSuffix
            
            if ($hasTarget) {
                Write-Success "Verification: Forest has '$UpnSuffix'."
                $step5Result = "OK"
            } else {
                Write-ErrorLine "Verification FAILED: Target suffix '$UpnSuffix' missing."
                $step5Result = "FAIL"
            }
        } else {
            $step5Result = "OK"
        }

    } else {
        Write-Info "Step 5 skipped by user."
    }

    $JobSummary += [PSCustomObject]@{ Step = "5. UPN Suffixes"; Status = $step5Result }

    # ---------------------------------------------------------
    # Step 6 – Update all enabled users' UPNs
    # ---------------------------------------------------------

    Write-Step 6 "Update enabled users' UPNs to '$UpnSuffix'"

    $runStep6 = Ask-YesNo "Proceed with Step 6 (update UserPrincipalName for enabled users)?"
    $step6Result = "SKIPPED"

    if ($runStep6) {
        $domain = Get-ADDomain
        $domainDN = $domain.DistinguishedName

        # Enabled person-user objects
        $allUsers = Get-ADUser -SearchBase $domainDN -SearchScope Subtree `
            -LDAPFilter "(&(objectCategory=person)(objectClass=user))" `
            -Properties SamAccountName, UserPrincipalName, Enabled

        $enabledUsers = @($allUsers | Where-Object { $_.Enabled -eq $true })

        Write-Info ("Found {0} enabled user object(s)." -f $enabledUsers.Count)

        $changedCount = 0
        $i = 0
        foreach ($u in $enabledUsers) {
            $i++
            Write-Progress -Activity "Updating User UPNs" -Status "Processing $($u.SamAccountName)" -PercentComplete (($i / $enabledUsers.Count) * 100)

            $newUpn = "$($u.SamAccountName)@$UpnSuffix"
            if ($u.UserPrincipalName -eq $newUpn) {
                continue
            }

            $changedCount++
            $desc = "Set UPN for '$($u.SamAccountName)' to '$newUpn'"
            Invoke-IfNotDryRun -Description $desc -Action {
                Set-ADUser -Identity $u.SamAccountName -UserPrincipalName $newUpn
            } | Out-Null
        }
        Write-Progress -Activity "Updating User UPNs" -Completed

        Write-Info ("Accounts needing UPN change: {0}" -f $changedCount)

        if (-not $script:DryRun) {
            # Verification: any enabled user not using the desired suffix?
            $postUsers = Get-ADUser -SearchBase $domainDN -SearchScope Subtree `
                -LDAPFilter "(&(objectCategory=person)(objectClass=user))" `
                -Properties UserPrincipalName, Enabled

            $badUpn = $postUsers | Where-Object {
                $_.Enabled -eq $true -and
                ($_.UserPrincipalName -notlike "*@$UpnSuffix")
            }

            if (-not $badUpn) {
                Write-Success "Verification: All enabled users now have UPN suffix '$UpnSuffix'."
                $step6Result = "OK"
            } else {
                Write-Warn "Verification WARNING: Some enabled users do NOT have the '$UpnSuffix' suffix:"
                $badUpn | Select-Object -First 20 SamAccountName,UserPrincipalName | Format-Table -AutoSize
                $script:Errors += "Step 6: Some enabled users still lack UPN suffix '$UpnSuffix'."
                $step6Result = "WARN"
            }
        } else {
            $step6Result = "OK"
        }
    } else {
        Write-Info "Step 6 skipped by user."
    }

    $JobSummary += [PSCustomObject]@{ Step = "6. Update UPNs"; Status = $step6Result }

    # ---------------------------------------------------------
    # Step 7 – Rotate KRBTGT twice
    # ---------------------------------------------------------

    Write-Step 7 "Rotate KRBTGT password twice"

    $runStep7 = Ask-YesNo "Proceed with Step 7 (KRBTGT x2 rotation)?"
    $step7Result = "SKIPPED"

    if ($runStep7) {
        $krb = Get-ADUser -Identity 'krbtgt' -Properties pwdLastSet
        $pwdBefore = $krb.pwdLastSet

        if ($script:DryRun) {
            Write-Warn "[DRY RUN] Would rotate KRBTGT password twice with random values."
            $step7Result = "OK"
        } else {
            # First rotation
            $pwd1 = New-StrongPassword -Length 32
            $sec1 = ConvertTo-SecureString $pwd1 -AsPlainText -Force
            $ok1 = Invoke-IfNotDryRun -Description "KRBTGT rotation #1" -Action {
                Set-ADAccountPassword -Identity 'krbtgt' -NewPassword $sec1 -Reset
                Set-ADUser -Identity 'krbtgt' -ChangePasswordAtLogon $false
            }

            # Second rotation
            $pwd2 = New-StrongPassword -Length 32
            $sec2 = ConvertTo-SecureString $pwd2 -AsPlainText -Force
            $ok2 = Invoke-IfNotDryRun -Description "KRBTGT rotation #2" -Action {
                Set-ADAccountPassword -Identity 'krbtgt' -NewPassword $sec2 -Reset
                Set-ADUser -Identity 'krbtgt' -ChangePasswordAtLogon $false
            }

            if ($ok1 -and $ok2) {
                $krbAfter = Get-ADUser -Identity 'krbtgt' -Properties pwdLastSet
                $pwdAfter = $krbAfter.pwdLastSet
                if ($pwdAfter -gt $pwdBefore) {
                    Write-Success "Verification: KRBTGT pwdLastSet moved forward (rotated)."
                    $step7Result = "OK"
                } else {
                    Write-ErrorLine "Verification FAILED: KRBTGT pwdLastSet did not advance."
                    $script:Errors += "Step 7 verification failed: KRBTGT pwdLastSet unchanged."
                    $step7Result = "FAIL"
                }
            } else {
                $step7Result = "FAIL"
            }
        }
    } else {
        Write-Info "Step 7 skipped by user."
    }

    $JobSummary += [PSCustomObject]@{ Step = "7. Rotate KRBTGT"; Status = $step7Result }

    # ---------------------------------------------------------
    # Step 8 – Reset passwords for enabled users (except exclusions)
    # ---------------------------------------------------------

    Write-Step 8 "Reset passwords for all enabled users (with exclusions)"

    $runStep8 = Ask-YesNo "Proceed with Step 8 (bulk password reset with unique passwords per account)?"
    $step8Result = "SKIPPED"

    if ($runStep8) {
        # Identify current user to exclude
        $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $CurrentDomain, $CurrentSam = $currentIdentity.Split('\', 2)

        $ExcludeSamAccounts = @('krbtgt', 'Guest')
        if ($ExcludeSamAccounts -notcontains $CurrentSam) {
            $ExcludeSamAccounts += $CurrentSam
        }

        $domainDN = (Get-ADDomain).DistinguishedName

        $allUsers = Get-ADUser -SearchBase $domainDN -SearchScope Subtree `
            -LDAPFilter "(&(objectCategory=person)(objectClass=user))" `
            -Properties SamAccountName, Enabled, DistinguishedName, PasswordNeverExpires

        $targets = @($allUsers | Where-Object {
            $_.Enabled -eq $true -and
            ($ExcludeSamAccounts -notcontains $_.SamAccountName)
        })

        Write-Info ("Enabled users to reset (excluding {0}): {1}" -f ($ExcludeSamAccounts -join ', '), $targets.Count)
        Write-Log "Step 8: Processing $($targets.Count) user accounts for password reset"

        $failures = @()
        $processedCount = 0
        $i = 0
        
        foreach ($u in $targets) {
            $i++
            Write-Progress -Activity "Resetting Passwords" -Status "User: $($u.SamAccountName)" -PercentComplete (($i / $targets.Count) * 100)

            # Generate unique password for each account
            $uniquePassword = New-StrongPassword -Length 24
            $securePassword = ConvertTo-SecureString $uniquePassword -AsPlainText -Force
            
            $descPwd = "Reset password for '$($u.SamAccountName)' with unique password"
            
            $ok = Invoke-IfNotDryRun -Description $descPwd -Action {
                $maxRetries = 3
                $retryDelay = 2
                $attempt = 0
                $success = $false
                $lastError = $null

                while (-not $success -and $attempt -lt $maxRetries) {
                    $attempt++
                    try {
                        Set-ADAccountPassword -Identity $u.SamAccountName -NewPassword $securePassword -Reset
                        
                        # Handle PasswordNeverExpires conflict
                        if ($u.PasswordNeverExpires) {
                            # Must disable PasswordNeverExpires to set ChangePasswordAtLogon
                            Set-ADUser -Identity $u.SamAccountName -ChangePasswordAtLogon $true -PasswordNeverExpires $false
                        } else {
                            Set-ADUser -Identity $u.SamAccountName -ChangePasswordAtLogon $true
                        }
                        $success = $true
                    } catch {
                        $lastError = $_
                        if ($attempt -lt $maxRetries) {
                            Write-Warn "    > Attempt $attempt failed. Retrying in $retryDelay seconds... ($($_.Exception.Message))"
                            Start-Sleep -Seconds $retryDelay
                        }
                    }
                }
                
                if (-not $success) {
                    throw $lastError
                }
            }
            
            if ($ok) {
                # Record password for CSV export
                $script:PasswordRecords += [PSCustomObject]@{
                    SamAccountName = $u.SamAccountName
                    DistinguishedName = $u.DistinguishedName
                    Password = $uniquePassword
                    ChangePasswordAtLogon = $true
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
                $processedCount++
            } else {
                $msg = "Password reset FAILED for $($u.SamAccountName)"
                $failures += $msg
                $script:Errors += $msg
            }
        }
        Write-Progress -Activity "Resetting Passwords" -Completed

        if ($script:DryRun) {
            Write-Warn "Dry run – no passwords actually changed. Would process $processedCount accounts."
            $step8Result = "OK"
        } else {
            if ($failures.Count -eq 0) {
                Write-Success "Verification: Password reset completed for $processedCount targeted accounts."
                Write-Log "Step 8: Successfully reset passwords for $processedCount accounts" -Level "SUCCESS"
                $step8Result = "OK"
            } else {
                Write-Warn "Verification WARNING: Some password resets failed. See errors above."
                Write-Log "Step 8: Completed with $($failures.Count) failures" -Level "WARN"
                $step8Result = "WARN"
            }
        }
    } else {
        Write-Info "Step 8 skipped by user."
    }

    $JobSummary += [PSCustomObject]@{ Step = "8. Reset User Pwds"; Status = $step8Result }

    # ---------------------------------------------------------
    # Step 9 – Create / repair 'labadmin' Domain Admin
    # ---------------------------------------------------------

    Write-Step 9 "Create or repair Lab Admin account"

    $runStep9 = Ask-YesNo "Proceed with Step 9 (create/repair Lab Admin and output password)?"
    $step9Result = "SKIPPED"

    if ($runStep9) {

        $defaultUser = 'labadmin'
        $LabAdminSam = Read-Host "Enter username for Lab Admin (default: '$defaultUser')"
        if ([string]::IsNullOrWhiteSpace($LabAdminSam)) {
            $LabAdminSam = $defaultUser
        }
        $LabAdminDisplayName = "Lab Admin ($LabAdminSam)"

        $labAdminPasswordPlain = New-StrongPassword -Length 24
        $labAdminPassword = ConvertTo-SecureString $labAdminPasswordPlain -AsPlainText -Force

        $existingLabAdmin = Get-ADUser -Filter "SamAccountName -eq '$LabAdminSam'" -ErrorAction SilentlyContinue

        if ($script:DryRun) {
            if ($existingLabAdmin) {
                Write-Warn "[DRY RUN] Would reset password for existing '$LabAdminSam' and ensure Domain Admins membership."
            } else {
                Write-Warn "[DRY RUN] Would create '$LabAdminSam' in 'CN=Users,$($domain.DistinguishedName)' and add to Domain Admins."
            }
            $step9Result = "OK"
            Write-Warn "Generated example password for '$LabAdminSam' (NOT applied in dry run): $labAdminPasswordPlain"
        } else {
            try {
                if ($existingLabAdmin) {
                    Write-Info "User '$LabAdminSam' already exists. Resetting password and ensuring Domain Admins membership."
                    Set-ADAccountPassword -Identity $existingLabAdmin.DistinguishedName -NewPassword $labAdminPassword -Reset
                    Add-ADGroupMember -Identity 'Domain Admins' -Members $existingLabAdmin -ErrorAction SilentlyContinue
                } else {
                    $userPath = "CN=Users,$($domain.DistinguishedName)"
                    Write-Info "Creating user '$LabAdminSam' in $userPath ..."
                    New-ADUser -Name $LabAdminDisplayName `
                               -SamAccountName $LabAdminSam `
                               -UserPrincipalName ("{0}@{1}" -f $LabAdminSam, $UpnSuffix) `
                               -AccountPassword $labAdminPassword `
                               -Enabled $true `
                               -PasswordNeverExpires $true `
                               -ChangePasswordAtLogon $false `
                               -Path $userPath

                    Add-ADGroupMember -Identity 'Domain Admins' -Members $LabAdminSam -ErrorAction Stop
                }
                
                # Add labadmin to password records for CSV export
                $labAdminDN = (Get-ADUser -Identity $LabAdminSam).DistinguishedName
                $script:PasswordRecords += [PSCustomObject]@{
                    SamAccountName = $LabAdminSam
                    DistinguishedName = $labAdminDN
                    Password = $labAdminPasswordPlain
                    ChangePasswordAtLogon = $false
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }

                # Verification
                $labAdmin = Get-ADUser -Identity $LabAdminSam -Properties MemberOf
                $groups = $labAdmin.MemberOf | ForEach-Object { (Get-ADGroup $_).Name }

                if ($groups -contains 'Domain Admins') {
                    Write-Success "Verification: '$LabAdminSam' is a member of 'Domain Admins'."
                    $step9Result = "OK"
                } else {
                    $msg = "Step 9 verification failed: '$LabAdminSam' is NOT in Domain Admins. Current groups: $($groups -join ', ')"
                    Write-ErrorLine $msg
                    $script:Errors += $msg
                    $step9Result = "FAIL"
                }

                Write-Host ""
                Write-Host "***************************************************" -ForegroundColor Cyan
                Write-Host "  User:     $LabAdminSam" -ForegroundColor Cyan
                Write-Host "  Password: $labAdminPasswordPlain" -ForegroundColor Cyan
                Write-Host "***************************************************" -ForegroundColor Cyan
                Write-Host ""
                Write-Warn "Password for '$LabAdminSam' will also be included in CSV export."
            }
            catch {
                $msg = "Step 9 failed: $($_.Exception.Message)"
                Write-ErrorLine $msg
                $script:Errors += $msg
                $step9Result = "FAIL"

                if ($_.Exception.Message -like "*unable to allocate a relative identifier*") {
                    Write-Warn "RID allocation appears to be failing (8208). Run 'dcdiag /test:ridmanager /v' and check RID Manager state."
                }
            }
        }
    } else {
        Write-Info "Step 9 skipped by user."
    }

    $JobSummary += [PSCustomObject]@{ Step = "9. Lab Admin"; Status = $step9Result }

}  # End of else block for Step 1 pre-requisite check

# ---------------------------------------------------------
# Export password CSV
# ---------------------------------------------------------

if ($script:PasswordRecords.Count -gt 0) {
    Write-Header "Export Password CSV"
    
    $csvFileName = "lab-passwords-$timestamp.csv"
    # Use script root if available, otherwise use current directory
    $csvBasePath = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $csvPath = Join-Path $csvBasePath $csvFileName
    
    Write-Info ("Exporting {0} password record(s) to CSV..." -f $script:PasswordRecords.Count)
    Export-PasswordCSV -Records $script:PasswordRecords -FilePath $csvPath
    
    Write-Host ""
    Write-Host ("CSV file location: {0}" -f $csvPath) -ForegroundColor Cyan
}

# ---------------------------------------------------------
# Clear Event Logs
# ---------------------------------------------------------

Write-Header "Clear Event Logs"
$runClearLogs = Ask-YesNo "Do you want to clear ALL Windows Event Logs (fresh start)?"

if ($runClearLogs) {
    if ($script:DryRun) {
         Write-Warn "[DRY RUN] Would clear all event logs."
    } else {
        try {
            $logs = Get-EventLog -List
            $lIndex = 0
            foreach ($log in $logs) {
                $lIndex++
                Write-Progress -Activity "Clearing Event Logs" -Status "Log: $($log.Log)" -PercentComplete (($lIndex / $logs.Count) * 100)
                
                $desc = "Clear event log '$($log.Log)'"
                # We do this directly in try/catch rather than Invoke-IfNotDryRun loop to keep it simple
                # as clearing logs can sometimes be noisy
                Write-Info "Clearing log: $($log.Log) ..."
                Clear-EventLog -LogName $log.Log -ErrorAction SilentlyContinue
            }
            Write-Progress -Activity "Clearing Event Logs" -Completed

            Write-Success "All event logs cleared successfully."
            Write-Log "All event logs cleared." -Level "SUCCESS"
        } catch {
            Write-ErrorLine "Error clearing event logs: $($_.Exception.Message)"
            Write-Log "Error clearing event logs: $($_.Exception.Message)" -Level "ERROR"
        }
    }
} else {
    Write-Info "Event logs kept intact."
}

# ---------------------------------------------------------
# Summary
# ---------------------------------------------------------

Write-Header "Summary"

Write-Info ("DryRun mode: {0}" -f $script:DryRun)
if ($script:PasswordRecords.Count -gt 0) {
    Write-Info ("Password records generated:        {0}" -f $script:PasswordRecords.Count)
}
Write-Host ""

# Render Job Summary Table
if ($JobSummary) {
    # Add icons for display
    $displaySummary = $JobSummary | Select-Object Step, @{
        Name = "Status"
        Expression = {
            switch ($_.Status) {
                "OK"      { "✓ OK" }
                "WARN"    { "! WARN" }
                "FAIL"    { "✗ FAIL" }
                "SKIPPED" { "- SKIP" }
                default   { $_.Status }
            }
        }
    }
    $displaySummary | Format-Table -AutoSize
}

Write-Host ""
Write-Host ("Log file: {0}" -f $script:LogFile) -ForegroundColor Cyan

if ($script:Errors.Count -gt 0) {
    Write-Host ""
    Write-Warn "One or more issues were detected during execution:"
    $script:Errors | ForEach-Object { Write-Warn " - $_" }
    Write-Log "Script completed with $($script:Errors.Count) error(s)" -Level "ERROR"
} else {
    Write-Host ""
    Write-Success "No errors recorded by the script. Review log/output for any unexpected warnings."
    Write-Log "Script completed successfully" -Level "SUCCESS"
}

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Red
Write-Host "                      SECURITY REMINDER                               " -ForegroundColor Red
Write-Host "======================================================================" -ForegroundColor Red
Write-Host ""
Write-Host "You are responsible for cleaning up sensitive data generated during" -ForegroundColor Yellow
Write-Host "the lab creation process." -ForegroundColor Yellow
Write-Host ""
Write-Host "1. Delete any BACKUPS or SNAPSHOTS taken of the production system" -ForegroundColor White
Write-Host "   on your hypervisor or intermediary storage." -ForegroundColor White
Write-Host "2. Securely delete the ORIGINAL IMPORTED DISK IMAGES (VHDX/VMDK)." -ForegroundColor White
Write-Host "3. Delete the Password CSV file generated by this script once" -ForegroundColor White
Write-Host "   you have safely stored the credentials." -ForegroundColor White
Write-Host ""
Write-Host "Leaving these artifacts exposes production hashes and sensitive data." -ForegroundColor Red
Write-Host "======================================================================" -ForegroundColor Red
Write-Host ""

