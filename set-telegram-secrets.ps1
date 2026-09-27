# Sets the Telegram Login OIDC credentials as encrypted Worker secrets.
#
# You need Login OIDC credentials from @BotFather -> your bot -> Bot Settings ->
# Login OIDC. These are NOT the bot token (the 123456:AA... value) - that one
# belongs to the Bot API and cannot authenticate anyone signing in.
#
# Fill in the two values below, run this script, then delete the file.
# It is gitignored, but delete it anyway so the values do not linger on disk.

$clientId     = "PASTE_CLIENT_ID_HERE"
$clientSecret = "PASTE_CLIENT_SECRET_HERE"

if ($clientId     -like "PASTE_*") { throw "Set $clientId first (line 15)." }
if ($clientSecret -like "PASTE_*") { throw "Set $clientSecret first (line 16)." }

Push-Location $PSScriptRoot
try {
    # secrets are written through stdin so the values never appear in shell
    # history, in a process listing, or in wrangler's own logs
    $clientId     | npx.cmd wrangler secret put TELEGRAM_CLIENT_ID
    $clientSecret | npx.cmd wrangler secret put TELEGRAM_CLIENT_SECRET

    Write-Host ""
    Write-Host "Secrets stored. The Worker needs a redeploy to pick them up."
    npx.cmd wrangler deploy
}
finally {
    Pop-Location
}
