# Run this AFTER setting RESET_ADMIN_SECRET in Render env and redeploying.
# Usage: .\reset-admin-via-api.ps1
# Or:   .\reset-admin-via-api.ps1 -Secret "myreset2026" -Pin "1111"

param(
    [string]$Secret = "myreset2026",
    [string]$Pin = "1111"
)

$body = @{ secret = $Secret; pin = $Pin } | ConvertTo-Json
try {
    $r = Invoke-RestMethod -Uri "https://ptc-pob-tracker.onrender.com/api/reset-admin" -Method POST -ContentType "application/json" -Body $body
    $r | ConvertTo-Json
    Write-Host "`nLog in at https://ptc-pob-tracker.onrender.com with username 'admin' and PIN '$Pin'"
} catch {
    Write-Host "Error: $_"
    Write-Host "Ensure RESET_ADMIN_SECRET=$Secret is set in Render Environment and the app has been redeployed."
}
