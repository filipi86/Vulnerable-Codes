# Vulnerable PowerShell Script - Local File Inclusion

param (
    [string]$includeFile
)

if (Test-Path $includeFile) {
    # Including file content directly - Vulnerability
    . $includeFile
}
else {
    Write-Host "File $includeFile does not exist."
}