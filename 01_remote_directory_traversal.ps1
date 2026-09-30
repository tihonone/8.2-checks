# Safe EDR test: PowerShell -EncodedCommand containing Get-ChildItem -Recurse
#
# Creates a dedicated temporary directory tree and starts a child PowerShell
# process with -EncodedCommand. The decoded command only enumerates the
# directory created by this script.
#
# No user data, system folders, network locations, registry keys, credentials,
# or security settings are accessed or modified.

$ErrorActionPreference = 'Stop'

$TestDirectory = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath 'EDR_GetChildItem_Recurse_Encoded_Test'
$ChildPowerShell = Join-Path -Path $PSHOME -ChildPath 'powershell.exe'

function New-TestFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Content
    )

    Set-Content -LiteralPath $Path -Value $Content -Encoding UTF8 -NoNewline -Force
}

try {
    if (-not (Test-Path -LiteralPath $ChildPowerShell -PathType Leaf)) {
        $ChildPowerShell = (Get-Command powershell.exe -ErrorAction Stop).Source
    }

    if (Test-Path -LiteralPath $TestDirectory) {
        throw "Test directory already exists: $TestDirectory. Review and remove it before running this scenario again."
    }

    # Create a small, bounded file tree for recursive enumeration.
    $LevelOneDirectory = Join-Path -Path $TestDirectory -ChildPath 'Level1'
    $LevelTwoDirectory = Join-Path -Path $LevelOneDirectory -ChildPath 'Level2'
    $SiblingDirectory = Join-Path -Path $TestDirectory -ChildPath 'Sibling'

    New-Item -ItemType Directory -Path $LevelTwoDirectory -Force | Out-Null
    New-Item -ItemType Directory -Path $SiblingDirectory -Force | Out-Null

    New-TestFile -Path (Join-Path $TestDirectory 'root.txt') -Content 'EDR safe test root file.'
    New-TestFile -Path (Join-Path $LevelOneDirectory 'level1.txt') -Content 'EDR safe test level 1 file.'
    New-TestFile -Path (Join-Path $LevelTwoDirectory 'level2.txt') -Content 'EDR safe test level 2 file.'
    New-TestFile -Path (Join-Path $SiblingDirectory 'sibling.txt') -Content 'EDR safe test sibling file.'

    # The decoded content contains the target behavior.
    # It reads only files and folder metadata under the dedicated test directory.
    $DecodedCommand = @"
`$ErrorActionPreference = 'Stop'
Get-ChildItem -Path '$TestDirectory' -Recurse -Depth 2 -Force |
    Select-Object FullName, PSIsContainer |
    Out-Host
"@

    # PowerShell -EncodedCommand requires Base64 of UTF-16LE content.
    $EncodedCommand = [Convert]::ToBase64String(
        [System.Text.Encoding]::Unicode.GetBytes($DecodedCommand)
    )

    if ([string]::IsNullOrWhiteSpace($EncodedCommand)) {
        throw 'Failed to produce the Base64-encoded test command.'
    }

    Write-Host "Test directory: $TestDirectory"
    Write-Host 'Starting child PowerShell with -EncodedCommand.'
    Write-Host 'Decoded behavior: Get-ChildItem -Recurse against test artifacts only.'

    # A separate child process makes -EncodedCommand visible in process telemetry.
    # No execution-policy setting is changed on the device.
    & $ChildPowerShell `
        -NoLogo `
        -NoProfile `
        -NonInteractive `
        -ExecutionPolicy Bypass `
        -EncodedCommand $EncodedCommand

    if ($LASTEXITCODE -ne 0) {
        throw "Child PowerShell process returned exit code $LASTEXITCODE."
    }

    Write-Host 'Test completed successfully: encoded bounded recursive enumeration was performed.'
}
finally {
    # Cleanup is constrained to the uniquely named test directory.
    if (Test-Path -LiteralPath $TestDirectory) {
        Remove-Item -LiteralPath $TestDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }

    if (Test-Path -LiteralPath $TestDirectory) {
        Write-Warning "Cleanup warning: test directory still exists: $TestDirectory"
    }
    else {
        Write-Host 'Cleanup completed: test files and directories were removed.'
    }
}