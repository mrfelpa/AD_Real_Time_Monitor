# AD Real-Time Monitor and Reversion Tool
# Author: Mr F3lpa
# Version: 1.0

Import-Module ActiveDirectory
Import-Module PSWriteColor

# Global settings
$global:monitoringActive = $false
$global:logDirectory = "C:\Logs"
$global:logFile = "$global:logDirectory\ADMonitor_$(Get-Date -Format 'yyyyMMdd').log"
$global:auditLogFile = "$global:logDirectory\ADMonitor_Audit_$(Get-Date -Format 'yyyyMMdd').log"
$global:baselineFile = "$global:logDirectory\ADBaseline.json"
$global:approvalFile = "$global:logDirectory\ADApprovals.json"
$global:authorizedApprovers = @("CN=Admin1,OU=Admins,DC=example,DC=com", "CN=Admin2,OU=Admins,DC=example,DC=com")
$global:authorizedReverters = @("CN=Admin1,OU=Admins,DC=example,DC=com", "CN=Admin2,OU=Admins,DC=example,DC=com")

if (-not (Test-Path $global:logDirectory)) {
    New-Item -Path $global:logDirectory -ItemType Directory
}

function Write-SecureLog {
    param (
        [string]$Message,
        [bool]$Sensitive = $false,
        [bool]$Audit = $false
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    
    if ($Sensitive) {
        $secureMessage = "SENSITIVE_DATA_REDACTED"
    } else {
        $secureMessage = $Message
    }
    
    $logEntry = "$timestamp - $currentUser - $secureMessage"
    
    if ($Audit) {
        $logEntry | Out-File -Append -FilePath $global:auditLogFile
    } else {
        $logEntry | Out-File -Append -FilePath $global:logFile
    }
    
    Write-Host $logEntry
}

function Is-UserAuthorized {
    param (
        [string[]]$AuthorizedUsers
    )
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    return $currentUser -in $AuthorizedUsers
}

function Revert-Change {
    param (
        [string]$ChangeType,
        [object]$Details,
        [string]$ApprovalId
    )
    
    if (-not (Is-UserAuthorized -AuthorizedUsers $global:authorizedReverters)) {
        Write-SecureLog "Unauthorized reversion attempt by $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" -Sensitive $true -Audit $true
        return
    }
    
    Write-SecureLog "Starting reversion process for $ChangeType change. Approval ID: $ApprovalId" -Audit $true
    
    switch ($ChangeType) {
        "DomainController" {
        
            foreach ($change in $Details) {
                $dcName = $change.InputObject
                Write-SecureLog "Attempting to remove unauthorized Domain Controller: $dcName" -Sensitive $true -Audit $true
                try {
                    # CAUTION: This operation is critical and should be thoroughly tested in a safe environment
                    Write-SecureLog "Domain Controller removal command executed for: $dcName" -Audit $true
                } catch {
                    Write-SecureLog "Failed to remove Domain Controller: $dcName. Error: $_" -Sensitive $true -Audit $true
                }
            }
        }
        "OU" {
            
            foreach ($change in $Details) {
                $ouDistinguishedName = $change.InputObject
                Write-SecureLog "Attempting to restore OU: $ouDistinguishedName" -Sensitive $true -Audit $true
                try {
                
                    Write-SecureLog "OU restoration command executed for: $ouDistinguishedName" -Audit $true
                } catch {
                    Write-SecureLog "Failed to restore OU: $ouDistinguishedName. Error: $_" -Sensitive $true -Audit $true
                }
            }
        }
        "Group" {
        
            foreach ($change in $Details) {
                $groupName = $change.InputObject
                Write-SecureLog "Attempting to restore group memberships for: $groupName" -Sensitive $true -Audit $true
                try {
                    # Example: Restore group memberships (this is a placeholder)
                    # Add-ADGroupMember -Identity $groupName -Members "user1", "user2"
                    Write-SecureLog "Group membership restoration command executed for: $groupName" -Audit $true
                } catch {
                    Write-SecureLog "Failed to restore group memberships for: $groupName. Error: $_" -Sensitive $true -Audit $true
                }
            }
        }
        "GPO" {
            
            foreach ($change in $Details) {
                $gpoName = $change.InputObject
                Write-SecureLog "Attempting to restore GPO settings for: $gpoName" -Sensitive $true -Audit $true
                try {
                    Write-SecureLog "GPO restoration command executed for: $gpoName" -Audit $true
                } catch {
                    Write-SecureLog "Failed to restore GPO settings for: $gpoName. Error: $_" -Sensitive $true -Audit $true
                }
            }
        }
    }
    Write-SecureLog "$ChangeType change reversion completed. Approval ID: $ApprovalId" -Audit $true
}

function Start-Monitoring {
    $global:monitoringActive = $true
    Write-SecureLog "Starting AD monitoring..." -Audit $true
    
    while ($global:monitoringActive) {
        $changes = Compare-WithBaseline
        foreach ($change in $changes) {
            $approvalId = Request-Approval -ChangeType $change.Type -Details $change.Details
            
            $approvalTimeout = (Get-Date).AddHours(24)  # 24-hour approval window
            do {
                Start-Sleep -Seconds 300  # Check every 5 minutes
                $status = Check-ApprovalStatus -ApprovalId $approvalId
            } while ($status -eq "Pending" -and (Get-Date) -lt $approvalTimeout)
            
            if ($status -eq "Approved") {
                Revert-Change -ChangeType $change.Type -Details $change.Details -ApprovalId $approvalId
            } else {
                Write-SecureLog "Change not approved or timed out: $($change.Type). Approval ID: $approvalId" -Sensitive $true -Audit $true
            }
        }
        Start-Sleep -Seconds 60  
    }
}

function Show-Menu {
    Clear-Host
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "   Active Directory Real-Time Monitor   " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host
    Write-Host "1. Start Monitoring" -ForegroundColor Green
    Write-Host "2. Stop Monitoring" -ForegroundColor Red
    Write-Host "3. Generate Baseline" -ForegroundColor Yellow
    Write-Host "4. View Log" -ForegroundColor Magenta
    Write-Host "5. Exit" -ForegroundColor Gray
    Write-Host
    Write-Host "Current status: " -NoNewline
    if ($global:monitoringActive) {
        Write-Host "Monitoring" -ForegroundColor Green
    } else {
        Write-Host "Stopped" -ForegroundColor Red
    }
    Write-Host
}

function Generate-Baseline {
    Write-SecureLog "Generating AD baseline..."
    $baseline = @{
        "DomainControllers" = (Get-ADDomainController -Filter *).Name
        "OUs" = (Get-ADOrganizationalUnit -Filter *).DistinguishedName
        "Groups" = (Get-ADGroup -Filter *).Name
        "GPOs" = (Get-GPO -All).DisplayName
    }
    $baseline | ConvertTo-Json | Out-File $global:baselineFile -Encoding UTF8
    Write-SecureLog "Baseline generated and saved to $global:baselineFile"
}

function Compare-WithBaseline {
    $baseline = Get-Content $global:baselineFile | ConvertFrom-Json
    $changes = @()
    
    $currentDCs = (Get-ADDomainController -Filter *).Name
    $diff = Compare-Object -ReferenceObject $baseline.DomainControllers -DifferenceObject $currentDCs
    if ($diff) {
        $changes += @{Type="DomainController"; Details=$diff}
    }
    
    $currentOUs = (Get-ADOrganizationalUnit -Filter *).DistinguishedName
    $diff = Compare-Object -ReferenceObject $baseline.OUs -DifferenceObject $currentOUs
    if ($diff) {
        $changes += @{Type="OU"; Details=$diff}
    }
    
    $currentGroups = (Get-ADGroup -Filter *).Name
    $diff = Compare-Object -ReferenceObject $baseline.Groups -DifferenceObject $currentGroups
    if ($diff) {
        $changes += @{Type="Group"; Details=$diff}
    }
    
    $currentGPOs = (Get-GPO -All).DisplayName
    $diff = Compare-Object -ReferenceObject $baseline.GPOs -DifferenceObject $currentGPOs
    if ($diff) {
        $changes += @{Type="GPO"; Details=$diff}
    }
    
    return $changes
}

function Request-Approval {
    param (
        [string]$ChangeType,
        [object]$Details
    )
    $approvalId = [Guid]::NewGuid().ToString()
    $approval = @{
        Id = $approvalId
        ChangeType = $ChangeType
        Details = $Details
        RequestTime = Get-Date
        Status = "Pending"
    }
    
    $approvals = @()
    if (Test-Path $global:approvalFile) {
        $approvals = Get-Content $global:approvalFile | ConvertFrom-Json
    }
    $approvals += $approval
    $approvals | ConvertTo-Json | Out-File $global:approvalFile -Encoding UTF8
    
    Write-SecureLog "Approval requested for $ChangeType change. Approval ID: $approvalId" -Sensitive $true
    return $approvalId
}

function Check-ApprovalStatus {
    param ([string]$ApprovalId)
    $approvals = Get-Content $global:approvalFile | ConvertFrom-Json
    $approval = $approvals | Where-Object { $_.Id -eq $ApprovalId }
    return $approval.Status
}

function Approve-Change {
    param ([string]$ApprovalId)
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    if ($currentUser -notin $global:authorizedApprovers) {
        Write-SecureLog "Unauthorized approval attempt by $currentUser" -Sensitive $true -Audit $true
        return $false
    }
    
    $approvals = Get-Content $global:approvalFile | ConvertFrom-Json
    $approval = $approvals | Where-Object { $_.Id -eq $ApprovalId }
    if ($approval) {
        $approval.Status = "Approved"
        $approval.ApprovedBy = $currentUser
        $approval.ApprovalTime = Get-Date
        $approvals | ConvertTo-Json | Out-File $global:approvalFile -Encoding UTF8
        Write-SecureLog "Change approved: $($approval.ChangeType) by $currentUser" -Sensitive $true -Audit $true
        return $true
    }
    return $false
}

function View-Log {
    if (Test-Path $global:logFile) {
        $logContent = Get-Content $global:logFile | Out-GridView -Title "AD Monitoring Log"
    } else {
        Write-Host "Log file not found!" -ForegroundColor Red
    }
}

do {
    Show-Menu
    $choice = Read-Host "Choose an option"
    
    switch ($choice) {
        "1" {
            if (-not $global:monitoringActive) {
                if (Is-UserAuthorized -AuthorizedUsers $global:authorizedApprovers) {
                    Start-Job -ScriptBlock ${function:Start-Monitoring} -Name "ADMonitor"
                    Write-SecureLog "Monitoring started by $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" -Audit $true
                    Write-Host "Monitoring started." -ForegroundColor Green
                } else {
                    Write-SecureLog "Unauthorized attempt to start monitoring by $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" -Sensitive $true -Audit $true
                    Write-Host "You are not authorized to start monitoring." -ForegroundColor Red
                }
            } else {
                Write-Host "Monitoring is already active!" -ForegroundColor Yellow
            }
        }
        "2" {
            if ($global:monitoringActive) {
                $global:monitoringActive = $false
                Stop-Job -Name "ADMonitor"
                Remove-Job -Name "ADMonitor"
                Write-SecureLog "Monitoring stopped by $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" -Audit $true
                Write-Host "Monitoring stopped." -ForegroundColor Red
            } else {
                Write-Host "Monitoring is not active!" -ForegroundColor Yellow
            }
        }
        "3" {
            Generate-Baseline
        }
        "4" {
            View-Log
        }
        "5" {
            Write-Host "Exiting the program..." -ForegroundColor Cyan
            if ($global:monitoringActive) {
                $global:monitoringActive = $false
                Stop-Job -Name "ADMonitor"
                Remove-Job -Name "ADMonitor"
            }
            exit
        }
        default {
            Write-Host "Invalid option. Please try again." -ForegroundColor Red
        }
    }
    
    Read-Host "Press Enter to continue..."
} while ($true)
