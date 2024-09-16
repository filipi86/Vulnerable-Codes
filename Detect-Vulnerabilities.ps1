param (
    [Parameter(Mandatory = $true)]
    [string]$path,
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("Directory", "File")]
    [string]$type
)

# Ensure the path parameter is not empty
if (-not $path) {
    Write-Host "Error: The path parameter is required and cannot be empty."
    exit
}

# Check if the provided path exists
if (-Not (Test-Path $path)) {
    Write-Host "Error: Path $path does not exist."
    exit
}

# Ensure the type parameter is valid
if ($type -eq "Directory") {
    if (-Not (Test-Path -Path $path -PathType Container)) {
        Write-Host "Error: Directory $path does not exist."
        exit
    }
} elseif ($type -eq "File") {
    if (-Not (Test-Path -Path $path -PathType Leaf)) {
        Write-Host "Error: File $path does not exist."
        exit
    }
}

# Define regex patterns and their names for extended ruleset based on OWASP Top 10, CWE Top 25, and OWASP API Security Top 10
$regexPatterns = @(
    @{ Name = 'Hardcoded Credentials'; Pattern = '\$\w+\s*=\s*"[^\"]*"|\$\w+\s*=\s*\''[^'']*\'''; Source = 'Regex' },
    @{ Name = 'Weak Encryption'; Pattern = 'AES|MD5'; Source = 'Regex' },
    @{ Name = 'Insecure Command Execution'; Pattern = '(?i)(Invoke-Expression|iex|Invoke-Command|Start-Process)'; Source = 'Regex' },
    @{ Name = 'SQL Injection'; Pattern = 'SELECT\s+\*\s+FROM\s+\w+\s+WHERE\s+\w+\s*=\s*''\$\(w+\)'''; Source = 'Regex' },
    @{ Name = 'Command Injection'; Pattern = '(?i)(Invoke-Expression|iex|Invoke-Command|Start-Process|New-Object\W.*\WSystem.IO.StreamWriter\W.*\WWriteLine)'; Source = 'OWASP Top 10' },
    @{ Name = 'Improper Input Validation'; Pattern = '(?i)(Read-Host|Get-Content|Set-Content|Add-Content|Copy-Item|Move-Item|Remove-Item|Rename-Item|Import-Module)\s-\w*\s\$.*$'; Source = 'OWASP Top 10' },
    @{ Name = 'Insecure HTTP Connections'; Pattern = 'http://'; Source = 'OWASP Top 10' },
    @{ Name = 'Weak Hash Functions'; Pattern = '(?i)(MD5|SHA1)'; Source = 'OWASP Top 10' },
    @{ Name = 'Unrestricted File Upload/Download'; Pattern = '(?i)(Invoke-WebRequest|Invoke-RestMethod|DownloadFile|UploadFile)'; Source = 'OWASP Top 10' },
    @{ Name = 'Sensitive Data Exposure'; Pattern = '(?i)\$.*(apikey|secret|password|token|credential)\s*=\s*".*"'; Source = 'OWASP Top 10' },
    @{ Name = 'Privilege Escalation Operations'; Pattern = '(?i)(New-LocalUser|Add-LocalGroupMember|Set-LocalUser|Invoke-Command)'; Source = 'OWASP Top 10' },
    @{ Name = 'Insecure Pipe Operations'; Pattern = '(?i)(Start-Process\s.*\|-input|-Strinpipes)'; Source = 'OWASP Top 10' },
    @{ Name = 'Usage of Unapproved PowerShell Modules'; Pattern = 'Import-Module\s.*\b(not-standard-module)\b'; Source = 'OWASP Top 10' },
    @{ Name = 'Potential Race Conditions in File Operations'; Pattern = '(Get-ChildItem\s.*\b-Filter\b.*\|.*\bMove-Item\b)'; Source = 'OWASP Top 10' },
    @{ Name = 'XML External Entity (XXE)'; Pattern = '(?i)(New-Object\s+System.Xml.XmlDocument|New-Object\s+System.Xml.XmlTextReader|New-Object\s+System.Xml.XmlTextWriter)'; Source = 'CWE Top 25' },
    @{ Name = 'Broken Access Control'; Pattern = '(?i)(Set-Acl|Get-Acl|Add-Member|Remove-Member)'; Source = 'CWE Top 25' },
    @{ Name = 'Security Misconfiguration'; Pattern = '(?i)(New-Object\s+System.Net.WebClient|Invoke-RestMethod|Invoke-WebRequest|DownloadFile|UploadFile)'; Source = 'CWE Top 25' },
    @{ Name = 'Cross-Site Scripting (XSS)'; Pattern = '(?i)(Write-Host|Write-Output)\s.*(<script|onerror|onload|alert\().*'; Source = 'CWE Top 25' },
    @{ Name = 'Insecure Deserialization'; Pattern = '(?i)(ConvertFrom-Json|ConvertFrom-Xml|Deserialize)'; Source = 'CWE Top 25' },
    @{ Name = 'Using Components with Known Vulnerabilities'; Pattern = 'Import-Module\s.*'; Source = 'CWE Top 25' },
    @{ Name = 'Insufficient Logging & Monitoring'; Pattern = '(?i)(Write-Host|Write-Output|Add-Content|Set-Content)\s.*'; Source = 'CWE Top 25' },
    @{ Name = 'Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)'; Pattern = '(?i)(Invoke-Expression|iex|Invoke-Command|Start-Process|New-Object\W.*\WSystem.Diagnostics.ProcessStartInfo\W.*\WFileName|New-Object\W.*\WSystem.Diagnostics.Process\W.*\WStart)'; Source = 'CWE Top 25' },
    @{ Name = 'Improper Handling of Extra Parameters'; Pattern = '-(?i)(Read-Host|Get-Content|Invoke-Expression|Invoke-WebRequest|Invoke-RestMethod)\s.*\$'; Source = 'CWE Top 25' },
    @{ Name = 'Improper Authorization'; Pattern = '(?i)(Set-Acl|New-LocalUser|Add-LocalGroupMember|Add-Member)'; Source = 'CWE Top 25' },
    @{ Name = 'Uncontrolled Resource Consumption'; Pattern = '(-ThrottleLimit\s(0|[1-9][0-9]*))|((Start-Process|Invoke-WebRequest|Invoke-RestMethod|DownloadFile\s|Add-Content\s|Set-Content\s|New-Item\s)\s-Parallel\s)'; Source = 'CWE Top 25' },
    @{ Name = 'Untrusted Search Path'; Pattern = '(?i)(.\\|\\.\\|%TEMP%|%WINDIR%|%SYSTEMROOT%|%HOMEPATH%|\.\\|\\|%APPDATA%|Invoke-Expression|iex|Invoke-Command|Start-Process|New-Object\s.*System.Diagnostics.Process\s.*Start)'; Source = 'CWE Top 25' },
    @{ Name = 'Path Traversal'; Pattern = '(\.\.\\|/home/\.\.|\\.\\.\/|^\/|^\\\\)(?i)'; Source = 'CWE Top 25' },
    @{ Name = 'Inadequate Encryption Strength'; Pattern = '(?i)(AESManaged|DES|TripleDES|RC2|Rijndael)'; Source = 'CWE Top 25' },
    @{ Name = 'Broken Object Level Authorization'; Pattern = '(?i)(Invoke-RestMethod|Invoke-WebRequest)\s.*\b(Get|Post|Put|Delete)\b.*\$.*\b(Authorization|AuthToken)\b\s*=\s*".*"'; Source = 'OWASP API Top 10' },
    @{ Name = 'Broken User Authentication'; Pattern = '(?i)\$.*(apikey|secret|password|token|auth).*=.*'; Source = 'OWASP API Top 10' },
    @{ Name = 'Excessive Data Exposure'; Pattern = '(?i)(Select-Object|Format-Table|Format-List)\s.*\b(Payload|Response|Content)\b'; Source = 'OWASP API Top 10' },
    @{ Name = 'Lack of Resources & Rate Limiting'; Pattern = '(?i)(Invoke-RestMethod|Invoke-WebRequest|Start-Job).*(-ThrottleLimit|Start-Sleep|Task.Delay)'; Source = 'OWASP API Top 10' },
    @{ Name = 'Broken Function Level Authorization'; Pattern = '(?i)(Invoke-RestMethod|Invoke-WebRequest|New-Object\s+System\.Net\.WebClient).*(Get|Post|Put|Delete)\s.*'; Source = 'OWASP API Top 10' },
    @{ Name = 'Mass Assignment'; Pattern = '(?i)(ConvertTo-Json|ConvertFrom-Json)\s+.*\|'; Source = 'OWASP API Top 10' },
    @{ Name = 'Security Misconfiguration (API)'; Pattern = '(?i)(New-Object\s+System\.Net\.WebClient|Invoke-RestMethod|Invoke-WebRequest|DownloadFile|UploadFile)'; Source = 'OWASP API Top 10' },
    @{ Name = 'Injection'; Pattern = '(?i)(Invoke-Expression|iex|Invoke-Command|Start-Process|New-Object\W.*\WSystem.IO.StreamWriter\W.*\WWriteLine)'; Source = 'OWASP API Top 10' },
    @{ Name = 'Improper Assets Management'; Pattern = '(?i)Import-Module|Write-Host|Write-Output'; Source = 'OWASP API Top 10' },
    @{ Name = 'Insufficient Logging & Monitoring (API)'; Pattern = '(?i)(Write-Host|Write-Output|Add-Content|Set-Content|Out-File)\s+.*(Response|Error|Exception|Credentials|Token|Password|Auth)'; Source = 'OWASP API Top 10' }
)

# Function to determine the color based on the source
function Get-ColorBasedOnSource ($source) {
    switch ($source) {
        'Regex' { return 'Yellow' }
        'OWASP Top 10' { return 'Cyan' }
        'CWE Top 25' { return 'Magenta' }
        'OWASP API Top 10' { return 'Green' }
        default { return 'White' }
    }
}

# Function to search for patterns in a file content and display results
function Search-Vulnerabilities {
    param (
        [string]$content,
        [array]$patterns,
        [string]$file
    )

    foreach ($patternDef in $patterns) {
        $matches = [regex]::Matches($content, $patternDef.Pattern)
        if ($matches.Count -gt 0) {
            $color = Get-ColorBasedOnSource $patternDef.Source
            Write-Host "File: $file" -ForegroundColor $color
            Write-Host "Pattern Found: $($patternDef.Name) - Source: $($patternDef.Source)" -ForegroundColor $color
            foreach ($match in $matches) {
                $lineNumber = ($content.Substring(0, $match.Index) -split "`n").Count
                Write-Host "  Line ${lineNumber}: $($match.Value)" -ForegroundColor $color
            }
        }
    }
}

if ($type -eq "Directory") {
    # Retrieve all .ps1 files from the directory and subdirectories
    $ps1Files = Get-ChildItem -Path $path -Recurse -Filter *.ps1
    foreach ($file in $ps1Files) {
        $content = Get-Content -Path $file.FullName -Raw
        Search-Vulnerabilities -content $content -patterns $regexPatterns -file $file.FullName
    }
} elseif ($type -eq "File") {
    # Retrieve and scan the specified .ps1 file
    $content = Get-Content -Path $path -Raw
    Search-Vulnerabilities -content $content -patterns $regexPatterns -file $path
}