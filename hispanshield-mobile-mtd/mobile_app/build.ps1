# BUILD SCRIPT - Mobile Threat Defense App
# Este script automatiza el proceso de build

Write-Host "================================" -ForegroundColor Cyan
Write-Host "Mobile Threat Defense - Build Script" -ForegroundColor Cyan
Write-Host "================================`n" -ForegroundColor Cyan

# Detectar Flutter
$flutterPath = (Get-Command flutter -ErrorAction SilentlyContinue).Source

if (-not $flutterPath) {
    Write-Host "ERROR: Flutter no encontrado en PATH" -ForegroundColor Red
    Write-Host "Instala Flutter desde: https://docs.flutter.dev/get-started/install/windows`n" -ForegroundColor Yellow
    
    Write-Host "Rutas comunes de Flutter:" -ForegroundColor Yellow
    Write-Host "  C:\src\flutter\bin\flutter.bat"
    Write-Host "  C:\flutter\bin\flutter.bat"
    Write-Host "  %USERPROFILE%\flutter\bin\flutter.bat`n"
    
    $manualPath = Read-Host "Ingresa la ruta completa a flutter.bat (o ENTER para salir)"
    
    if ($manualPath) {
        $flutterPath = $manualPath
    } else {
        exit 1
    }
}

Write-Host "Flutter encontrado: $flutterPath`n" -ForegroundColor Green

# Navegar al directorio
$projectDir = $PSScriptRoot
Set-Location $projectDir

Write-Host "Paso 1: Limpiando proyecto..." -ForegroundColor Yellow
& $flutterPath clean

Write-Host "`nPaso 2: Obteniendo dependencias..." -ForegroundColor Yellow
& $flutterPath pub get

Write-Host "`nPaso 3: Verificando keystore..." -ForegroundColor Yellow
$keystorePath = "android\mtd-release-key.jks"

if (-not (Test-Path $keystorePath)) {
    Write-Host "Keystore no encontrado. Se necesita keytool (viene con JDK)" -ForegroundColor Red
    Write-Host "`nInstrucciones manuales:" -ForegroundColor Yellow
    Write-Host "1. Instala JDK si no lo tienes: https://adoptium.net/" -ForegroundColor Cyan
    Write-Host "2. Ejecuta este comando en android\ :" -ForegroundColor Cyan
    Write-Host "   keytool -genkey -v -keystore mtd-release-key.jks -keyalg RSA -keysize 2048 -validity 10000 -alias mtd_release_key" -ForegroundColor White
    Write-Host "`nPresiona ENTER para continuar sin keystore (build debug)..." -ForegroundColor Yellow
    Read-Host
} else {
    Write-Host "Keystore encontrado: $keystorePath" -ForegroundColor Green
}

# Menú de build
Write-Host "`n================================" -ForegroundColor Cyan
Write-Host "Selecciona tipo de build:" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host "1. App Bundle Release (para Google Play)"
Write-Host "2. APK Release (para distribución directa)"
Write-Host "3. APK Debug (para testing)"
Write-Host "4. Salir`n"

$option = Read-Host "Opción"

switch ($option) {
    1 {
        Write-Host "`nConstruyendo App Bundle Release..." -ForegroundColor Green
        & $flutterPath build appbundle --release
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "`n✅ BUILD EXITOSO!" -ForegroundColor Green
            Write-Host "Archivo: build\app\outputs\bundle\release\app-release.aab`n" -ForegroundColor Cyan
            
            # Abrir carpeta de output
            $outputPath = "build\app\outputs\bundle\release"
            if (Test-Path $outputPath) {
                explorer $outputPath
            }
        } else {
            Write-Host "`n❌ Build falló. Revisa los errores arriba." -ForegroundColor Red
        }
    }
    2 {
        Write-Host "`nConstruyendo APK Release..." -ForegroundColor Green
        & $flutterPath build apk --release
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "`n✅ BUILD EXITOSO!" -ForegroundColor Green
            Write-Host "Archivo: build\app\outputs\flutter-apk\app-release.apk`n" -ForegroundColor Cyan
            
            $outputPath = "build\app\outputs\flutter-apk"
            if (Test-Path $outputPath) {
                explorer $outputPath
            }
        } else {
            Write-Host "`n❌ Build falló. Revisa los errores arriba." -ForegroundColor Red
        }
    }
    3 {
        Write-Host "`nConstruyendo APK Debug..." -ForegroundColor Green
        & $flutterPath build apk --debug
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "`n✅ BUILD EXITOSO!" -ForegroundColor Green
            Write-Host "Archivo: build\app\outputs\flutter-apk\app-debug.apk`n" -ForegroundColor Cyan
            
            $outputPath = "build\app\outputs\flutter-apk"
            if (Test-Path $outputPath) {
                explorer $outputPath
            }
        } else {
            Write-Host "`n❌ Build falló. Revisa los errores arriba." -ForegroundColor Red
        }
    }
    4 {
        Write-Host "Saliendo..." -ForegroundColor Yellow
        exit 0
    }
    default {
        Write-Host "Opción inválida" -ForegroundColor Red
        exit 1
    }
}

Write-Host "`nPresiona ENTER para salir..."
Read-Host
