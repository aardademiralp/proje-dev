# ISU-SecOps-Orchestrator — Windows Kurulum ve Test Scripti
# ===========================================================
# Kullanim:
#   PowerShell'i bu dizinde acin ve calistirin:
#   .\setup_and_test.ps1
#
# Bu script:
#   1. Python sanal ortami olusturur
#   2. Bagimliliklari kurar
#   3. Demo engine binary'si olusturur
#   4. Testleri calistirir

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "╔══════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  ISU-SecOps-Orchestrator Kurulum Scripti     ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------------------
# 1. Python kontrolü
# ---------------------------------------------------------------------------
Write-Host "[1/5] Python kontrolü yapiliyor..." -ForegroundColor Yellow

$PythonCmd = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd --version 2>&1
        if ($ver -match "Python 3\.1[1-9]") {
            $PythonCmd = $cmd
            Write-Host "      ✅ $ver bulundu: $cmd" -ForegroundColor Green
            break
        }
    } catch { }
}

if (-not $PythonCmd) {
    Write-Host "      ❌ Python 3.11+ bulunamadi!" -ForegroundColor Red
    Write-Host "      Lütfen https://python.org adresinden Python 3.11+ indirin." -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# 2. Sanal ortam
# ---------------------------------------------------------------------------
Write-Host "[2/5] Sanal ortam olusturuluyor..." -ForegroundColor Yellow

if (-not (Test-Path ".venv")) {
    & $PythonCmd -m venv .venv
    Write-Host "      ✅ .venv olusturuldu" -ForegroundColor Green
} else {
    Write-Host "      ℹ  .venv zaten mevcut, atlaniyor" -ForegroundColor DarkGray
}

$PipCmd = ".\.venv\Scripts\pip.exe"
$PythonVenv = ".\.venv\Scripts\python.exe"

# ---------------------------------------------------------------------------
# 3. Bagimliliklar
# ---------------------------------------------------------------------------
Write-Host "[3/5] Bagimliliklar kuruluyor..." -ForegroundColor Yellow
& $PipCmd install -r orchestrator\requirements.txt --quiet
Write-Host "      ✅ Bagimliliklar kuruldu" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 4. Demo engine binary'si
# ---------------------------------------------------------------------------
Write-Host "[4/5] Demo engine binary'si olusturuluyor..." -ForegroundColor Yellow

$EngineDir = "core_engine"
if (-not (Test-Path $EngineDir)) {
    New-Item -ItemType Directory -Path $EngineDir | Out-Null
}

$DemoEngineScript = @"
import sys, json
# ISU-SecOps-Engine Demo Binary (Python tabanlı mock)
# Gercek Rust binary yerine test amacli kullanilir
demo_output = [
    {
        "address": "192.168.1.1",
        "hostname": "demo-router.local",
        "status": "up",
        "os": "Linux 5.15",
        "ports": [
            {"port": 22, "protocol": "tcp", "state": "open", "service": "SSH", "version": "OpenSSH_9.0"},
            {"port": 80, "protocol": "tcp", "state": "open", "service": "HTTP", "version": "nginx/1.24"},
            {"port": 3389, "protocol": "tcp", "state": "open", "service": "RDP", "version": ""}
        ]
    }
]
print(json.dumps(demo_output))
"@

# Windows'ta .bat wrapper ile Python scripti cagiran binary olustur
$WrapperBat = @"
@echo off
python "%~dp0isu-secops-engine.py" %*
"@

$DemoEngineScript | Out-File -FilePath "$EngineDir\isu-secops-engine.py" -Encoding utf8
$WrapperBat | Out-File -FilePath "$EngineDir\isu-secops-engine.bat" -Encoding ascii

# Config icin engine path'i .env'e yaz
$EnvContent = @"
ISU_LOG_LEVEL=INFO
ISU_LOG_FORMAT=text
ISU_ENGINE_PATH=$((Get-Location).Path)\core_engine\isu-secops-engine.bat
ISU_REPORTS_DIR=$((Get-Location).Path)\reports
ISU_SCAN_TIMEOUT=30
ISU_MAX_CONCURRENT_SCANS=3
ISU_REPORT_ORGANIZATION=ISU Siber Guvenlik Arastirma Lab
"@

$EnvContent | Out-File -FilePath ".env" -Encoding utf8 -Force
Write-Host "      ✅ Demo engine ve .env olusturuldu" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 5. Testleri calistir
# ---------------------------------------------------------------------------
Write-Host "[5/5] Test paketi calistiriliyor..." -ForegroundColor Yellow
Write-Host ""

$PytestCmd = ".\.venv\Scripts\pytest.exe"
if (Test-Path $PytestCmd) {
    & $PytestCmd tests/ -v --asyncio-mode=auto --tb=short --no-header 2>&1
} else {
    & $PythonVenv -m pytest tests/ -v --asyncio-mode=auto --tb=short --no-header 2>&1
}

Write-Host ""
Write-Host "╔══════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Kurulum tamamlandi!                          ║" -ForegroundColor Cyan
Write-Host "║                                               ║" -ForegroundColor Cyan
Write-Host "║  Sunucuyu baslatmak icin:                     ║" -ForegroundColor Cyan
Write-Host "║  .venv\Scripts\uvicorn.exe \`                  ║" -ForegroundColor Cyan
Write-Host "║    orchestrator.app.main:app \`               ║" -ForegroundColor Cyan
Write-Host "║    --reload --port 8000                       ║" -ForegroundColor Cyan
Write-Host "║                                               ║" -ForegroundColor Cyan
Write-Host "║  API Docs: http://localhost:8000/api/docs     ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════╝" -ForegroundColor Cyan
