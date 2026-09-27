<#
  PropTech - one-shot deploy pipeline

  Creates all Cloudflare resources, injects real IDs into wrangler.jsonc,
  applies remote migrations, and deploys.

  Idempotent: safe to re-run. Existing resources are reused, never duplicated.
  Requires: `npx wrangler login` to have been completed first.

  Usage:  .\deploy.ps1
#>

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

# Accept credentials without them ever being typed into a chat/terminal prompt.
# Put the token in .cloudflare-token (one line, no quotes) and re-run.
$tokenFile = Join-Path $PSScriptRoot '.cloudflare-token'
if ((Test-Path $tokenFile) -and -not $env:CLOUDFLARE_API_TOKEN) {
  $tok = (Get-Content $tokenFile -Raw).Trim()
  if ($tok) {
    $env:CLOUDFLARE_API_TOKEN = $tok
    Write-Host "[creds] Loaded API token from .cloudflare-token" -ForegroundColor DarkGray
  }
}

function Step($n) { Write-Host "`n[$n]" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "  OK   $m" -ForegroundColor Green }
function Warn($m) { Write-Host "  WARN $m" -ForegroundColor Yellow }
function Die($m)  { Write-Host "  FAIL $m" -ForegroundColor Red; exit 1 }

# ---------------------------------------------------------------- 0. auth gate
Step "0/6  Checking Cloudflare authentication"
$who = npx.cmd wrangler whoami 2>&1 | Out-String
if ($who -match 'not authenticated') {
  Die @"
Not authenticated with Cloudflare.

Run this in YOUR OWN terminal (not here) so it can wait as long as you need:

    cd $PSScriptRoot
    npx wrangler login

Approve in the browser, then re-run this script.
"@
}
Ok "authenticated as $(($who -split "`n" | Where-Object { $_ -match '@|Account' } | Select-Object -First 1).Trim())"

# ------------------------------------------------------- 1. D1 database
Step "1/6  D1 database 'proptech-db'"
$d1Id = $null
$existing = npx.cmd wrangler d1 list --json 2>$null | ConvertFrom-Json
$match = $existing | Where-Object { $_.name -eq 'proptech-db' } | Select-Object -First 1
if ($match) {
  $d1Id = $match.uuid
  Ok "already exists - reusing $d1Id"
} else {
  $out = npx.cmd wrangler d1 create proptech-db --json 2>&1 | Out-String
  try { $d1Id = ($out | ConvertFrom-Json).uuid } catch { $d1Id = ($out -split "`n" | Where-Object { $_ -match '[0-9a-f]{8}-[0-9a-f]{4}' } | Select-Object -First 1) -replace '.*?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}).*','$1' }
  if (-not $d1Id) { Die "could not determine D1 id. Raw: $out" }
  Ok "created $d1Id"
}

# ------------------------------------------------------- 2. R2 bucket
Step "2/6  R2 bucket 'proptech-media'"
$buckets = npx.cmd wrangler r2 bucket list --json 2>$null | ConvertFrom-Json
if ($buckets | Where-Object { $_.name -eq 'proptech-media' }) {
  Ok "already exists"
} else {
  npx.cmd wrangler r2 bucket create proptech-media 2>&1 | Out-Null
  Ok "created"
}

# ------------------------------------------------------- 3. KV namespace
Step "3/6  KV namespace 'PROPTECH_SESSIONS'"
$kvId = $null
$kvs = npx.cmd wrangler kv namespace list --json 2>$null | ConvertFrom-Json
$kvMatch = $kvs | Where-Object { $_.title -eq 'SESSIONS' -or $_.title -eq 'PROPTECH_SESSIONS' } | Select-Object -First 1
if ($kvMatch) {
  $kvId = $kvMatch.id
  Ok "already exists - reusing $kvId"
} else {
  $out = npx.cmd wrangler kv namespace create SESSIONS 2>&1 | Out-String
  $kvId = ($out -split "`n" | Where-Object { $_ -match '[0-9a-f]{32}' } | Select-Object -First 1) -replace '.*?([0-9a-f]{32}).*','$1'
  if (-not $kvId) { Die "could not determine KV namespace id. Raw: $out" }
  Ok "created $kvId"
}

# ------------------------------------------------------- 4. Queue
Step "4/6  Queue 'proptech-notifications'"
npx.cmd wrangler queues create proptech-notifications 2>&1 | Out-Null
Ok "ready"

# ------------------------------------------------------- 5. inject IDs
Step "5/6  Writing real IDs into wrangler.jsonc"
Copy-Item wrangler.jsonc "wrangler.jsonc.bak" -Force
$cfg = Get-Content wrangler.jsonc -Raw
$cfg = $cfg -replace 'REPLACE_WITH_D1_DATABASE_ID', $d1Id
$cfg = $cfg -replace 'REPLACE_WITH_KV_NAMESPACE_ID', $kvId
Set-Content wrangler.jsonc -Value $cfg -NoNewline
Ok "D1     -> $d1Id"
Ok "KV     -> $kvId"
Ok "backup -> wrangler.jsonc.bak"

# ------------------------------------------------------- 6. migrate + deploy
Step "6/6  Applying remote migrations"
npx.cmd wrangler d1 migrations apply proptech-db --remote 2>&1 | Select-Object -Last 8

Step "Deploying"
$deploy = npx.cmd wrangler deploy 2>&1 | Out-String
Write-Host $deploy

if ($deploy -match 'https://[a-z0-9.-]+\.workers\.dev') {
  $url = $Matches[0]
  Write-Host "`n========================================" -ForegroundColor Green
  Write-Host " DEPLOYED: $url" -ForegroundColor Green
  Write-Host "========================================" -ForegroundColor Green
  Write-Host ""
  Write-Host "Next steps:"
  Write-Host "  1. Bootstrap your super admin (one-time):"
  Write-Host "     npx wrangler secret put BOOTSTRAP_ADMIN_KEY"
  Write-Host "     curl -X POST https://<host>/api/setup/bootstrap-admin -H 'x-bootstrap-key: <key>' -H 'Content-Type: application/json' -d '{...}'"
  Write-Host "  2. Rotate/remove BOOTSTRAP_ADMIN_KEY afterwards."
} else {
  Warn "deploy output did not contain a workers.dev URL - review above"
}
