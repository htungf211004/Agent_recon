# Install git pre-push hook for AI log submission (Windows PowerShell).
# Run once after cloning: powershell -ExecutionPolicy Bypass -File scripts\setup_hooks.ps1

$ErrorActionPreference = 'Stop'

$HookFile = '.git/hooks/pre-push'

# Git on Windows runs hooks via Git Bash, so the hook body must be bash.
$HookBody = @'
#!/usr/bin/env bash
# Pre-push: sweep recent Antigravity / Gemini prompts, then submit AI logs.
bash scripts/_pyrun.sh scripts/log_antigravity.py --auto || true
bash scripts/_pyrun.sh scripts/submit_log.py || true
exit 0
'@

$HookBody = $HookBody -replace "`r`n", "`n"
$HookPath = Join-Path (Get-Location) $HookFile
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($HookPath, $HookBody, $Utf8NoBom)

$HookBytes = [System.IO.File]::ReadAllBytes($HookPath)
if (
    $HookBytes.Length -ge 3 -and
    $HookBytes[0] -eq 0xEF -and
    $HookBytes[1] -eq 0xBB -and
    $HookBytes[2] -eq 0xBF
) {
    throw '[ai-log] Hook installation failed: UTF-8 BOM detected before shebang.'
}

$FirstLine = [System.IO.File]::ReadLines($HookPath) | Select-Object -First 1
if ($FirstLine -ne '#!/usr/bin/env bash') {
    throw '[ai-log] Hook installation failed: invalid shebang.'
}

$Bash = Get-Command bash -ErrorAction SilentlyContinue
if ($Bash) {
    & $Bash.Source -n $HookPath
    if ($LASTEXITCODE -ne 0) {
        throw '[ai-log] Hook installation failed: bash syntax check failed.'
    }
}
Write-Host "[ai-log] Git pre-push hook installed."

if (-not (Test-Path .ai-log)) { New-Item -ItemType Directory -Path .ai-log | Out-Null }
if (-not (Test-Path .ai-log/.gitkeep)) { New-Item -ItemType File -Path .ai-log/.gitkeep | Out-Null }

Write-Host "[ai-log] Setup complete. Configure AI_LOG_SERVER in your .env file."
