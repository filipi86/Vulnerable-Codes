# Vulnerable PowerShell Script - Outdated Cryptographic Algorithm

param (
    [string]$data
)

# Using outdated MD5 for hashing - Vulnerability
$md5Hash = [System.Security.Cryptography.MD5]::Create()
$hashBytes = $md5Hash.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($data))
$hashString = [BitConverter]::ToString($hashBytes) -replace '-', ''
Write-Host "MD5 Hash of data: $hashString"