[CmdletBinding()]
param(
    [string]$CompilerPath,
    [switch]$UseExistingPackage,
    [switch]$UseInstalledDependencies
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $repo 'dist'
if (-not $CompilerPath) {
    $compiler = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($compiler) { $CompilerPath = $compiler.Source }
    else { $CompilerPath = Join-Path ([Environment]::GetEnvironmentVariable('ProgramFiles(x86)')) 'Inno Setup 6/ISCC.exe' }
}
if (-not (Test-Path -LiteralPath $CompilerPath -PathType Leaf)) {
    throw 'Install Inno Setup 6 or newer, or pass -CompilerPath pointing to ISCC.exe.'
}
if (-not $UseExistingPackage) {
    & (Join-Path $PSScriptRoot 'Build-WindowsPackage.ps1') -UseInstalledDependencies:$UseInstalledDependencies
}
$archive = Join-Path $dist 'PersonalNetworkSecurity-win-x64.zip'
if (-not (Test-Path -LiteralPath $archive)) { throw 'Build the Windows package first.' }
$stage = Join-Path $dist ('installer-stage-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage | Out-Null
$package = Join-Path $stage 'package'
Expand-Archive -LiteralPath $archive -DestinationPath $package
$bootstrapper = Join-Path $stage 'MicrosoftEdgeWebview2Setup.exe'
Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/p/?LinkId=2124703' -OutFile $bootstrapper
$signature = Get-AuthenticodeSignature -LiteralPath $bootstrapper
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation(?:,|$)') {
    throw 'Microsoft WebView2 bootstrapper signature verification failed.'
}
$version = (Get-Content (Join-Path $repo 'frontend/package.json') -Raw | ConvertFrom-Json).version
& $CompilerPath "/DPackageDir=$package" "/DBootstrapper=$bootstrapper" "/DAppVersion=$version" (Join-Path $PSScriptRoot 'installer/PersonalNetworkSecurity.iss')
if ($LASTEXITCODE -ne 0) { throw 'Installer compilation failed.' }
Get-FileHash -LiteralPath (Join-Path $dist 'PersonalNetworkSecurity-Setup-win-x64.exe') -Algorithm SHA256
