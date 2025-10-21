Param(
    [string]$Branch = "main",
    [string]$InstallRoot = "$env:LOCALAPPDATA\mbox-reader"
)

$ErrorActionPreference = "Stop"

$AppName = "mbox-reader"
$RepoOwner = "allquixotic"
$RepoName = "mbox_reader"
$RawBase = "https://raw.githubusercontent.com/$RepoOwner/$RepoName/$Branch"
$RuntimeRoot = Join-Path $InstallRoot "runtime"
$JavaHome = Join-Path $RuntimeRoot "temurin-25"
$KotlinVersion = "2.2.20"
$KotlinHome = Join-Path $RuntimeRoot "kotlin-$KotlinVersion"
$BinDir = Join-Path $InstallRoot "bin"
$ShimPath = Join-Path $BinDir "mbox-reader.cmd"
$ScriptPath = Join-Path $InstallRoot "mbox_reader.main.kts"

function Write-Log {
    param([string]$Message)
    Write-Host "[$AppName installer] $Message"
}

function Ensure-Directory {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

Ensure-Directory $InstallRoot
Ensure-Directory $RuntimeRoot
Ensure-Directory $BinDir

Add-Type -AssemblyName System.IO.Compression.FileSystem

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
Ensure-Directory $tempRoot

try {
    $arch = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
    if ($arch -like "*ARM*") {
        $javaArch = "aarch64"
    } else {
        $javaArch = "x64"
    }
    $javaUrl = "https://api.adoptium.net/v3/binary/latest/25/ga/windows/$javaArch/jdk/hotspot/normal/eclipse"
    $javaZip = Join-Path $tempRoot "temurin.zip"

    if (-not (Test-Path $JavaHome)) {
        Write-Log "Downloading Temurin Java 25 ($javaArch) from Adoptium"
        Invoke-WebRequest -Uri $javaUrl -OutFile $javaZip -UseBasicParsing
        if (Test-Path $JavaHome) {
            Remove-Item $JavaHome -Recurse -Force
        }
        $javaExtractDir = Join-Path $tempRoot "jdk"
        Ensure-Directory $javaExtractDir
        [System.IO.Compression.ZipFile]::ExtractToDirectory($javaZip, $javaExtractDir)
        $jdkFolder = Get-ChildItem -Directory $javaExtractDir | Select-Object -First 1
        if (-not $jdkFolder) {
            throw "Failed to locate extracted JDK directory."
        }
        Move-Item $jdkFolder.FullName $JavaHome
    } else {
        Write-Log "Temurin Java 25 already installed at $JavaHome"
    }

    if (-not (Test-Path $KotlinHome)) {
        $kotlinUrl = "https://github.com/JetBrains/kotlin/releases/download/v$KotlinVersion/kotlin-compiler-$KotlinVersion.zip"
        $kotlinZip = Join-Path $tempRoot "kotlin.zip"
        Write-Log "Downloading Kotlin $KotlinVersion compiler from JetBrains"
        Invoke-WebRequest -Uri $kotlinUrl -OutFile $kotlinZip -UseBasicParsing
        if (Test-Path $KotlinHome) {
            Remove-Item $KotlinHome -Recurse -Force
        }
        $kotlinExtractDir = Join-Path $tempRoot "kotlin"
        Ensure-Directory $kotlinExtractDir
        [System.IO.Compression.ZipFile]::ExtractToDirectory($kotlinZip, $kotlinExtractDir)
        $kotlinFolder = Get-ChildItem -Directory $kotlinExtractDir | Where-Object { $_.Name -like "kotlinc*" } | Select-Object -First 1
        if (-not $kotlinFolder) {
            throw "Failed to locate extracted Kotlin compiler directory."
        }
        Move-Item $kotlinFolder.FullName $KotlinHome
    } else {
        Write-Log "Kotlin $KotlinVersion already installed at $KotlinHome"
    }

    $tmpScript = Join-Path $tempRoot "mbox_reader.main.kts"
    Write-Log "Downloading mbox_reader.main.kts from $RawBase"
    Invoke-WebRequest -Uri "$RawBase/mbox_reader.main.kts" -OutFile $tmpScript -UseBasicParsing
    Move-Item $tmpScript $ScriptPath -Force

    $shimContent = @"
@echo off
setlocal
set "INSTALL_ROOT=$InstallRoot"
set "SCRIPT_PATH=$ScriptPath"
set "JAVA_HOME=%INSTALL_ROOT%\runtime\temurin-25"
set "KOTLIN_HOME=%INSTALL_ROOT%\runtime\kotlin-$KotlinVersion"
if not exist "%KOTLIN_HOME%\bin\kotlin.bat" (
  echo mbox-reader: Kotlin runtime is missing. Re-run the installer. 1>&2
  exit /b 1
)
if not exist "%JAVA_HOME%\bin\java.exe" (
  echo mbox-reader: Temurin Java 25 runtime is missing. Re-run the installer. 1>&2
  exit /b 1
)
set "PATH=%JAVA_HOME%\bin;%PATH%"
"%KOTLIN_HOME%\bin\kotlin.bat" -script "%SCRIPT_PATH%" %*
"@

    Set-Content -Path $ShimPath -Value $shimContent -Encoding ASCII

    Write-Log "Creating shim at $ShimPath"

    $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ([string]::IsNullOrWhiteSpace($currentPath)) {
        $updatedPath = $BinDir
    } elseif ($currentPath.Split(";") -notcontains $BinDir) {
        $updatedPath = "$currentPath;$BinDir"
    } else {
        $updatedPath = $currentPath
    }
    if ($updatedPath -ne $currentPath) {
        Write-Log "Adding $BinDir to user PATH"
        [Environment]::SetEnvironmentVariable("Path", $updatedPath, "User")
        Write-Log "Restart your terminal or log off/on to refresh PATH."
    }

    Write-Log "Installation complete. Launch with: mbox-reader"
}
finally {
    if (Test-Path $tempRoot) {
        Remove-Item $tempRoot -Recurse -Force
    }
}
