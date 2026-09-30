# Remote Directory Traversal — safe local SMB emulation
# Administrator privileges are required.
# Creates a temporary directory and an SMB share on localhost,
# performs read-only recursive enumeration, and then removes all artifacts.

$ErrorActionPreference = 'Stop'

$TestRoot  = Join-Path $env:TEMP 'EDR_RemoteDirectoryTraversal_Test'
$ShareName = 'EDRTraversalTest'
$DriveName = 'R'
$UncPath   = "\\127.0.0.1\$ShareName"

try {
    # 1. Controlled test files: no user or sensitive data is involved
    New-Item -ItemType Directory -Path "$TestRoot\Finance\Reports" -Force | Out-Null
    New-Item -ItemType Directory -Path "$TestRoot\Engineering\Builds" -Force | Out-Null
    Set-Content -Path "$TestRoot\README-test.txt" -Value 'EDR safe test artifact'
    Set-Content -Path "$TestRoot\Finance\Reports\Q1-test.txt" -Value 'Non-sensitive test content'
    Set-Content -Path "$TestRoot\Engineering\Builds\build-test.log" -Value 'Synthetic build log'

    # 2. Temporary SMB share available only through localhost
    New-SmbShare -Name $ShareName -Path $TestRoot -ReadAccess "$env:USERDOMAIN\$env:USERNAME" -FullAccess 'Administrators' | Out-Null

    # 3. Connect to the local SMB share through a UNC path
    cmd.exe /c "net use $DriveName`: $UncPath /persistent:no"

    # 4. Recursive enumeration: list names and metadata only; no file content is read or copied
    cmd.exe /c "dir $DriveName`:\ /s /b"
    cmd.exe /c "tree $DriveName`:\ /f"

    Write-Host "Test completed: safe recursive enumeration was performed against $UncPath"
}
finally {
    # 5. Cleanup: disconnect the SMB mapping and remove the temporary share and test files
    cmd.exe /c "net use $DriveName`: /delete /y" 2>$null
    Remove-SmbShare -Name $ShareName -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $TestRoot -Recurse -Force -ErrorAction SilentlyContinue
}