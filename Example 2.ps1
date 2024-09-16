# Vulnerable PowerShell Script - SQL Injection

param (
    [string]$userId
)

# Constructing SQL query directly with user input - Vulnerability
$query = "SELECT * FROM Users WHERE UserId = '$userId';"

# Simulate a database query
function Execute-Query {
    param (
        [string]$sqlQuery
    )
    # Database connection simulation (Replace with actual DB connection in real scenarios)
    Write-Output "Executing query: $sqlQuery"
}

Execute-Query -sqlQuery $query