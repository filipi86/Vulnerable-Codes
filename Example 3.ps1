# Vulnerable PowerShell Script - Insecure File Handling

param (
    [string]$sourcePath,
    [string]$destinationPath
)

# File copy operation without proper validation - Vulnerability
Copy-Item -Path $sourcePath -Destination $destinationPath -Recurse -Force
Write-Host "Copied from $sourcePath to $destinationPath"