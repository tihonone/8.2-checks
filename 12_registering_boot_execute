# BootExecute registry modification — lab-only, interactive reversible telemetry test
# WARNING: BootExecute is processed by Session Manager during system startup.
# Run only on a disposable lab VM as Administrator.
#
# Every stage requires an explicit YES confirmation:
#   1. Prerequisite validation
#   2. Session Manager registry export
#   3. Original BootExecute read
#   4. Temporary marker write
#   5. Temporary value verification
#   6. Restoration
#   7. Restoration verification
#   8. Backup deletion after successful verification
#
# Do not reboot, log off, restart services, or run system maintenance tools
# while the test is running.

$ErrorActionPreference = 'Stop'

$SessionManagerPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
$SessionManagerRegPath = 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager'
$ValueName = 'BootExecute'
$TestMarker = 'EDR_SAFE_BOOTEXECUTE_SIMULATION_DO_NOT_REBOOT'
$BackupFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath 'EDR_BootExecute_Backup.reg'
$RegExe = Join-Path -Path $env:WINDIR -ChildPath 'System32\reg.exe'

$OriginalBootExecute = $null
$BackupCreated = $false
$TemporaryValueWritten = $false
$RestorationVerified = $false
$TestAborted = $false

function Test-IsAdministrator {
    $CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal($CurrentIdentity)

    return $CurrentPrincipal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Confirm-Step {
    param(
        [Parameter(Mandatory = $true)]
        [string]$StepName,

        [Parameter(Mandatory = $true)]
        [string]$Details
    )

    Write-Host ''
    Write-Host '================================================================' -ForegroundColor Yellow
    Write-Host "Step: $StepName" -ForegroundColor Yellow
    Write-Host $Details -ForegroundColor Yellow
    Write-Host 'Enter YES to continue. Any other input cancels the test.' -ForegroundColor Yellow
    Write-Host '================================================================' -ForegroundColor Yellow

    $Response = Read-Host -Prompt 'Confirmation'

    if ($Response -cne 'YES') {
        Write-Warning "Step was not approved: $StepName"
        return $false
    }

    return $true
}

function Get-BootExecuteValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    # Force an array even if the REG_MULTI_SZ contains one string only.
    return [string[]]@(
        Get-ItemPropertyValue `
            -LiteralPath $Path `
            -Name $Name `
            -ErrorAction Stop
    )
}

function Write-RegistryMultiStringEntries {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Entries,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    Write-Host ''
    Write-Host $Label -ForegroundColor Cyan

    foreach ($Entry in $Entries) {
        Write-Host "  [$Entry]"
    }
}

function Stop-TestSafely {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Reason
    )

    $script:TestAborted = $true
    throw "Test was cancelled: $Reason"
}

try {
    if (-not (Confirm-Step `
        -StepName 'Prerequisite validation' `
        -Details 'This will validate elevated privileges and required system paths. No registry values will be changed.')) {
        Stop-TestSafely -Reason 'Prerequisite validation was not approved.'
    }

    if (-not (Test-IsAdministrator)) {
        throw 'Administrator privileges are required. Start PowerShell with Run as administrator.'
    }

    if (-not (Test-Path -LiteralPath $RegExe -PathType Leaf)) {
        throw "reg.exe was not found: $RegExe"
    }

    Write-Host 'Prerequisite validation completed successfully.' -ForegroundColor Green

    if (-not (Confirm-Step `
        -StepName 'Session Manager backup export' `
        -Details "This will export the current key to: $BackupFile")) {
        Stop-TestSafely -Reason 'Registry backup export was not approved.'
    }

    & $RegExe export $SessionManagerRegPath $BackupFile /y | Out-Null

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to export the Session Manager registry key. Exit code: ${LASTEXITCODE}"
    }

    if (-not (Test-Path -LiteralPath $BackupFile -PathType Leaf)) {
        throw "Registry backup file was not created: $BackupFile"
    }

    $BackupCreated = $true
    Write-Host "Registry backup created: $BackupFile" -ForegroundColor Green

    if (-not (Confirm-Step `
        -StepName 'Read original BootExecute value' `
        -Details 'This will read the current BootExecute REG_MULTI_SZ value. No registry values will be changed.')) {
        Stop-TestSafely -Reason 'Original BootExecute read was not approved.'
    }

    $OriginalBootExecute = Get-BootExecuteValue `
        -Path $SessionManagerPath `
        -Name $ValueName

    if ($null -eq $OriginalBootExecute -or $OriginalBootExecute.Count -eq 0) {
        throw 'BootExecute has no entries. The test will not continue.'
    }

    if (@($OriginalBootExecute | Where-Object { $_ -eq $TestMarker }).Count -gt 0) {
        throw 'The test marker already exists in BootExecute. Manual review is required.'
    }

    Write-RegistryMultiStringEntries `
        -Entries $OriginalBootExecute `
        -Label 'Original BootExecute entries captured. Do not reboot during this test.'

    if (-not (Confirm-Step `
        -StepName 'Write temporary BootExecute marker' `
        -Details "This will temporarily add the following REG_MULTI_SZ entry to the real BootExecute value: $TestMarker`nDo not reboot until the original value is restored and verified.")) {
        Stop-TestSafely -Reason 'Temporary BootExecute marker write was not approved.'
    }

    $TemporaryBootExecute = [string[]]@(
        $OriginalBootExecute
        $TestMarker
    )

    Set-ItemProperty `
        -LiteralPath $SessionManagerPath `
        -Name $ValueName `
        -Type MultiString `
        -Value $TemporaryBootExecute `
        -ErrorAction Stop

    $TemporaryValueWritten = $true
    Write-Host 'Temporary BootExecute marker was written.' -ForegroundColor Green

    if (-not (Confirm-Step `
        -StepName 'Verify temporary BootExecute marker' `
        -Details 'This will read the real BootExecute value and verify that the temporary marker is present. No registry values will be changed.')) {
        Stop-TestSafely -Reason 'Temporary marker verification was not approved.'
    }

    $CurrentBootExecute = Get-BootExecuteValue `
        -Path $SessionManagerPath `
        -Name $ValueName

    Write-RegistryMultiStringEntries `
        -Entries $CurrentBootExecute `
        -Label 'Temporary BootExecute entries after registry write:'

    $MarkerPresent = @(
        $CurrentBootExecute |
            Where-Object { $_ -eq $TestMarker }
    ).Count -gt 0

    if (-not $MarkerPresent) {
        throw 'The temporary test marker was not found after the registry write.'
    }

    Write-Host 'Temporary marker validation completed successfully.' -ForegroundColor Green
}
catch {
    Write-Error "Test encountered an error: $($_.Exception.Message)"
}
finally {
    # Restoration is mandatory once the original value has been captured.
    # The script allows cancellation only before a real registry write.
    if ($null -ne $OriginalBootExecute -and $OriginalBootExecute.Count -gt 0) {
        if ($TemporaryValueWritten) {
            $RestorationApproved = Confirm-Step `
                -StepName 'Restore original BootExecute value' `
                -Details 'This will immediately restore the exact original BootExecute REG_MULTI_SZ value. Approve this step before closing PowerShell or restarting the computer.'

            if (-not $RestorationApproved) {
                Write-Warning 'Restoration was not approved interactively, but restoration is mandatory for safety.'
                Write-Warning 'The script will restore the original BootExecute value automatically.'
            }
        }
        else {
            Write-Host 'No temporary BootExecute value was written. Restoration is not required.' -ForegroundColor Green
        }

        try {
            # Restore the exact original REG_MULTI_SZ array.
            Set-ItemProperty `
                -LiteralPath $SessionManagerPath `
                -Name $ValueName `
                -Type MultiString `
                -Value ([string[]]$OriginalBootExecute) `
                -ErrorAction Stop

            Write-Host 'Original BootExecute value restoration command completed.' -ForegroundColor Green

            $VerificationApproved = Confirm-Step `
                -StepName 'Verify BootExecute restoration' `
                -Details 'This will read BootExecute and compare it with the original captured value. No registry values will be changed.'

            if (-not $VerificationApproved) {
                Write-Warning 'Restoration verification was not approved. The registry backup will be retained.'
            }
            else {
                $RestoredBootExecute = Get-BootExecuteValue `
                    -Path $SessionManagerPath `
                    -Name $ValueName

                Write-RegistryMultiStringEntries `
                    -Entries $RestoredBootExecute `
                    -Label 'BootExecute entries after restoration:'

                $Differences = @(
                    Compare-Object `
                        -ReferenceObject ([string[]]$OriginalBootExecute) `
                        -DifferenceObject ([string[]]$RestoredBootExecute)
                )

                if ($Differences.Count -eq 0) {
                    $RestorationVerified = $true
                    Write-Host 'Cleanup completed: the original BootExecute value was restored and verified.' -ForegroundColor Green
                }
                else {
                    Write-Error 'Cleanup failed: the restored BootExecute value differs from the original value.'
                    $Differences | Format-Table -AutoSize | Out-String | Write-Host
                }
            }
        }
        catch {
            Write-Error "Cleanup failed: $($_.Exception.Message)"
        }
    }
    else {
        Write-Warning 'Original BootExecute value was not captured. No restoration action was attempted.'
    }

    if ($BackupCreated -and $RestorationVerified) {
        $BackupRemovalApproved = Confirm-Step `
            -StepName 'Delete verified registry backup' `
            -Details "Restoration was verified. This will remove the backup file: $BackupFile"

        if ($BackupRemovalApproved) {
            Remove-Item -LiteralPath $BackupFile -Force -ErrorAction SilentlyContinue

            if (Test-Path -LiteralPath $BackupFile) {
                Write-Warning "Backup file could not be removed: $BackupFile"
            }
            else {
                Write-Host 'Backup file removed after successful restoration verification.' -ForegroundColor Green
            }
        }
        else {
            Write-Host "Backup file was retained by user choice: $BackupFile" -ForegroundColor Yellow
        }
    }
    elseif ($BackupCreated) {
        Write-Warning 'Restoration was not verified. Do not reboot the computer.'
        Write-Warning "Registry backup retained at: $BackupFile"
        Write-Warning "Manual recovery command: `"$RegExe`" import `"$BackupFile`""
    }

    if ($TestAborted) {
        Write-Host 'Test ended because one or more steps were not approved.' -ForegroundColor Yellow
    }
}