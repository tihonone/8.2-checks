# Unexpected services.exe Parent — safe reversible EDR test
# Copies the Microsoft-signed services.exe to a dedicated temporary directory.
# Launches the copy through cmd.exe without arguments to simulate an unexpected parent process.
# Does not create, modify, stop, restart, or interact with Windows services or SCM.
# The copied process is expected to terminate quickly and may return a non-zero exit code.

$ErrorActionPreference = 'Stop'

$TestDirectory = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath 'EDR_UnexpectedServicesParent_Test'
$SourceImage = Join-Path -Path $env:WINDIR -ChildPath 'System32\services.exe'
$TestImage = Join-Path -Path $TestDirectory -ChildPath 'services.exe'
$CmdExe = $env:COMSPEC

try {
    # Verify required system binaries before creating test artifacts.
    if (-not (Test-Path -LiteralPath $SourceImage -PathType Leaf)) {
        throw "Source system binary was not found: $SourceImage"
    }

    if (-not (Test-Path -LiteralPath $CmdExe -PathType Leaf)) {
        throw "cmd.exe was not found: $CmdExe"
    }

    $SourceSignature = Get-AuthenticodeSignature -FilePath $SourceImage
    if ($SourceSignature.Status -ne 'Valid') {
        throw "Source services.exe signature is not valid. Status: $($SourceSignature.Status)"
    }

    # Create an isolated directory and copy only the existing signed system binary.
    New-Item -ItemType Directory -Path $TestDirectory -Force | Out-Null
    Copy-Item -LiteralPath $SourceImage -Destination $TestImage -Force

    $TestSignature = Get-AuthenticodeSignature -FilePath $TestImage
    Write-Host "Test image path: $TestImage"
    Write-Host "Test image signature status: $($TestSignature.Status)"

    if ($TestSignature.Status -ne 'Valid') {
        throw "Copied services.exe signature is not valid. Status: $($TestSignature.Status)"
    }

    # Launch the copied binary through cmd.exe without arguments.
    # A quick exit or non-zero exit code is expected and does not indicate a failed EDR test.
    Write-Host 'Starting the copied services.exe through cmd.exe.'
    & $CmdExe /d /c "`"$SourceImage`""
    $TestProcessExitCode = $LASTEXITCODE

    Write-Host "Copied services.exe exited with code: $TestProcessExitCode"
    Write-Host 'Test completed: unexpected services.exe parent and temporary image path telemetry were generated.'
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