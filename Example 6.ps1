# Vulnerable PowerShell Script - Weak Password Handling

param (
    [string]$username,
    [string]$password
)

# Convert password to secure string
$securePass = ConvertTo-SecureString $password -AsPlainText -Force

# Creating a new user with the plain text password - Vulnerability
New-LocalUser -Name $username -Password $securePass -FullName "Test User" -Description "User created for testing purposes"
Write-Host "Created user $username with a weak password."