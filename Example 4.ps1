# Vulnerable PowerShell Script - Insecure Network Communication

param (
    [string]$server,
    [int]$port
)

$message = "Hello, World!"
$bytes = [System.Text.Encoding]::UTF8.GetBytes($message)

# Sending data without encryption - Vulnerability
$tcpClient = New-Object System.Net.Sockets.TcpClient
$tcpClient.Connect($server, $port)
$stream = $tcpClient.GetStream()
$stream.Write($bytes, 0, $bytes.Length)
$stream.Close()
$tcpClient.Close()

Write-Host "Sent message to $server:$port"