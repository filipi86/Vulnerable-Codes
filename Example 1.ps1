# Vulnerable PowerShell Script

# Hardcoded credentials - Vulnerability
$username = "admin"
$password = "password123"

# Weak encryption - Vulnerability
function Encrypt-String {
    param (
        [string]$plaintext,
        [byte[]]$key = (1..16)
    )
    $plaintextBytes = [System.Text.Encoding]::UTF8.GetBytes($plaintext)
    $aes = [System.Security.Cryptography.AesManaged]::new()
    $aes.Key = $key
    $aes.IV = $key  # Using the same key as IV is insecure
    $encryptor = $aes.CreateEncryptor()
    $cipherBytes = $encryptor.TransformFinalBlock($plaintextBytes, 0, $plaintextBytes.Length)
    return [Convert]::ToBase64String($cipherBytes)
}

# Input without validation - Vulnerability
param (
    [string]$filePath
)

Write-Host "Reading file: $filePath"
$fileContent = Get-Content -Path $filePath

# Insufficient output encoding - Vulnerability
Write-Host "File content: $fileContent"

# Insecure command execution - Vulnerability
function Run-Command {
    param (
        [string]$command
    )
    Invoke-Expression $command
}
Run-Command "dir C:\"

# Elevated privileges - Vulnerability
function CreateAdminAccount {
    param (
        [string]$newUser,
        [string]$newPassword
    )
    $secpasswd = ConvertTo-SecureString $newPassword -AsPlainText -Force
    New-LocalUser -Name $newUser -Password $secpasswd -PasswordNeverExpires:$true -FullName "Admin User"
    Add-LocalGroupMember -Group "Administrators" -Member $newUser
}
CreateAdminAccount -newUser "newAdmin" -newPassword "SuperSecret!"

# Logging sensitive information - Vulnerability
Write-Output "Username: $username"
Write-Output "Password: $password"