<#
.SYNOPSIS
    Build the Aegis Windows app and, when Inno Setup 6 is installed, its installer.

.DESCRIPTION
    1. Installs the build tools (PyInstaller, Pillow) and Aegis with its UI extra.
    2. Freezes the desktop app into dist\Aegis\Aegis.exe.
    3. Compiles packaging\aegis.iss into dist\installer\Aegis-Setup-<version>.exe.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File packaging\build_windows.ps1
#>
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$python = if (Test-Path ".venv\Scripts\python.exe") { ".venv\Scripts\python.exe" } else { "python" }

function Invoke-Checked {
    param([string]$What, [scriptblock]$Command)
    & $Command
    if ($LASTEXITCODE -ne 0) { throw "$What failed (exit code $LASTEXITCODE)" }
}

Write-Host "==> Installing build dependencies"
Invoke-Checked "Dependency install" {
    & $python -m pip install --disable-pip-version-check -q -e ".[ui]" "pyinstaller>=6.10" "pillow>=10"
}

$version = (& $python -c "import aegis; print(aegis.__version__)").Trim()
Write-Host "==> Building Aegis $version"

New-Item -ItemType Directory -Force "build\packaging" | Out-Null
Invoke-Checked "Icon conversion" {
    & $python -c "from PIL import Image; Image.open('assets/icon.png').save('build/packaging/aegis.ico', sizes=[(16,16),(24,24),(32,32),(48,48),(64,64),(128,128),(256,256)])"
}

# PyInstaller resolves relative paths against --specpath, so pass absolute ones.
Invoke-Checked "PyInstaller" {
    & $python -m PyInstaller --noconfirm --clean --windowed --name Aegis `
        --icon "$root\build\packaging\aegis.ico" `
        --distpath dist --workpath "build\pyinstaller" --specpath "build\packaging" `
        --add-data "$root\assets;assets" `
        --add-data "$root\aegis\api\static;aegis\api\static" `
        --add-data "$root\aegis\detection\sigma\rules;aegis\detection\sigma\rules" `
        --collect-all flet `
        --collect-all flet_web `
        --collect-submodules sklearn `
        --collect-all win11toast `
        "packaging\aegis_app.py"
}
Write-Host "==> App built: dist\Aegis\Aegis.exe"

$iscc = @(
    (Get-Command iscc -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source),
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1

if (-not $iscc) {
    Write-Host "Inno Setup 6 was not found, so no installer was built."
    Write-Host "Install it (winget install JRSoftware.InnoSetup) and run this script again."
    exit 0
}

Write-Host "==> Compiling installer with $iscc"
Invoke-Checked "Inno Setup" { & $iscc "/DAppVersion=$version" "packaging\aegis.iss" }
Write-Host "==> Installer built: dist\installer\Aegis-Setup-$version.exe"
