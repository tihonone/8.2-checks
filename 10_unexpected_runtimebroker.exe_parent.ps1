# Stop runtimebroker.exe after execution, then you'll have an alert in solution console
# Unexpected runtimebroker.exe Parent — safe reversible lab EDR test
# Copies the Microsoft-signed RuntimeBroker.exe to a dedicated temporary directory.
# Launches the copy through cmd.exe without arguments to simulate an unexpected parent process.
# Does not interact with Windows Runtime, UWP/AppX, services, registry, network, or system processes.
# The copied process may exit quickly and return a non-zero exit code.

$ErrorActionPreference = 'Stop'

$TestDirectory = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath 'EDR_UnexpectedRuntimeBrokerParent_Test'
$SourceImage = Join-Path -Path $env:WINDIR -ChildPath 'System32\RuntimeBroker.exe'
$TestImage = Join-Path -Path $TestDirectory -ChildPath 'RuntimeBroker.exe'
$CmdExe = $env:COMSPEC

try {
    # Verify required Windows binaries before creating test artifacts.
    if (-not (Test-Path -LiteralPath $SourceImage -PathType Leaf)) {
        throw "Source system binary was not found: $SourceImage"
    }

    if (-not (Test-Path -LiteralPath $CmdExe -PathType Leaf)) {
        throw "cmd.exe was not found: $CmdExe"
    }

    $SourceSignature = Get-AuthenticodeSignature -FilePath $SourceImage
    if ($SourceSignature.Status -ne 'Valid') {
        throw "Source RuntimeBroker.exe signature is not valid. Status: $($SourceSignature.Status)"
    }

    # Create an isolated directory and copy only the existing signed system binary.
    New-Item -ItemType Directory -Path $TestDirectory -Force | Out-Null
    Copy-Item -LiteralPath $SourceImage -Destination $TestImage -Force

    $TestSignature = Get-AuthenticodeSignature -FilePath $TestImage
    Write-Host "Test image path: $TestImage"
    Write-Host "Test image signature status: $($TestSignature.Status)"

    if ($TestSignature.Status -ne 'Valid') {
        throw "Copied RuntimeBroker.exe signature is not valid. Status: $($TestSignature.Status)"
    }

    # Launch the copied binary through cmd.exe without arguments.
    # A quick exit or non-zero exit code is expected and does not indicate a failed EDR test.
    Write-Host 'Starting the copied RuntimeBroker.exe through cmd.exe.'
    & $CmdExe /d /c "`"$SourceImage`""
    $TestProcessExitCode = $LASTEXITCODE

    Write-Host "Copied RuntimeBroker.exe exited with code: $TestProcessExitCode"
    Write-Host 'Test completed: unexpected RuntimeBroker.exe parent and temporary image path telemetry were generated.'
}
finally {
    # Remove only artifacts created in the dedicated temporary test directory.
    if (Test-Path -LiteralPath $TestDirectory) {
        Remove-Item -LiteralPath $TestDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }

    if (Test-Path -LiteralPath $TestDirectory) {
        Write-Warning "Cleanup warning: the test directory still exists: $TestDirectory"
    }
    else {
        Write-Host 'Cleanup completed: temporary test artifacts were removed.'
    }
}