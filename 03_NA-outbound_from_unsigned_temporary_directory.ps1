# Outbound from Unsigned Temporary Directory — safe reversible EDR test
# Creates an unsigned child PowerShell script in a temporary directory.
# The child script sends one HTTPS GET request to example.com.
# No local data is uploaded, no payload is downloaded or executed,
# and all test artifacts are removed during cleanup.

$ErrorActionPreference = 'Stop'

$TestDirectory = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath 'EDR_UnsignedOutbound_Test'
$TestScript = Join-Path -Path $TestDirectory -ChildPath 'unsigned_outbound_test.ps1'
$TargetUrl = 'https://2ip.io/'
$ChildPowerShell = Join-Path -Path $PSHOME -ChildPath 'powershell.exe'

if (-not (Test-Path -LiteralPath $ChildPowerShell -PathType Leaf)) {
    $ChildPowerShell = (Get-Command powershell.exe -ErrorAction Stop).Source
}

try {
    # Create the dedicated temporary directory for the test.
    New-Item -ItemType Directory -Path $TestDirectory -Force | Out-Null

    # Create an intentionally unsigned child script.
    # A single-quoted here-string preserves child-script variables literally.
    $ChildScriptContent = @'
# Safe EDR test: outbound HTTPS request from an unsigned script in a temporary directory.
# Sends one GET request only. No local data is uploaded and no downloaded content is executed.

$ErrorActionPreference = 'Stop'
$TargetUrl = 'https://2ip.io/'

try {
    $Response = Invoke-WebRequest -Uri $TargetUrl -Method Get -TimeoutSec 15 -UseBasicParsing
    Write-Host "Test completed: outbound HTTPS request sent to $TargetUrl with HTTP status $($Response.StatusCode)."
}
catch {
    Write-Host "Test completed with a network error: $($_.Exception.Message)"
}
'@

    Set-Content -LiteralPath $TestScript -Value $ChildScriptContent -Encoding UTF8 -Force

    # Confirm that the child script was created and is not Authenticode-signed.
    $Signature = Get-AuthenticodeSignature -FilePath $TestScript
    Write-Host "Test script path: $TestScript"
    Write-Host "Signature status: $($Signature.Status)"

    if ($Signature.Status -ne 'NotSigned') {
        throw "Unexpected signature state: $($Signature.Status). The test requires an unsigned script."
    }

    # Execute the unsigned script from the temporary directory.
    # ExecutionPolicy applies only to this child process and does not modify device policy.
    & $ChildPowerShell -NoProfile -ExecutionPolicy Bypass -File $TestScript

    if ($LASTEXITCODE -ne 0) {
        throw "Child PowerShell process returned exit code $LASTEXITCODE."
    }

    Write-Host "Parent test completed successfully."
}
finally {
    # Remove only artifacts created in the dedicated test directory.
    if (Test-Path -LiteralPath $TestDirectory) {
        Remove-Item -LiteralPath $TestDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }

    if (Test-Path -LiteralPath $TestDirectory) {
        Write-Warning "Cleanup warning: test directory still exists: $TestDirectory"
    }
    else {
        Write-Host "Cleanup completed: temporary test artifacts were removed."
    }
}