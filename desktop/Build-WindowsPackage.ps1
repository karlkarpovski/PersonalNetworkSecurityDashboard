[CmdletBinding()]
param([switch]$UseInstalledDependencies)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$frontend = Join-Path $repo 'frontend'
$project = Join-Path $PSScriptRoot 'PersonalNetworkSecurity.Desktop/PersonalNetworkSecurity.Desktop.csproj'
$dist = Join-Path $repo 'dist'
$publish = Join-Path $dist ('windows-x64-' + [Guid]::NewGuid().ToString('N'))
$archive = Join-Path $dist 'PersonalNetworkSecurity-win-x64.zip'

Push-Location $frontend
try {
    if (-not $UseInstalledDependencies) {
        npm.cmd ci
        if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency installation failed.' }
    }
    npm.cmd run build
    if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }
} finally {
    Pop-Location
}

dotnet publish $project -c Release -r win-x64 --self-contained true -o $publish
if ($LASTEXITCODE -ne 0) { throw 'Windows publish failed.' }
Copy-Item -LiteralPath (Join-Path $frontend 'dist') -Destination (Join-Path $publish 'wwwroot') -Recurse
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Windows-Setup.md') -Destination $publish

$licenses = New-Item -ItemType Directory -Path (Join-Path $publish 'licenses')
foreach ($dependency in 'react', 'react-dom', 'lucide-react', 'three', '@microsoft/signalr') {
    $license = Get-ChildItem -LiteralPath (Join-Path $frontend "node_modules/$dependency") -File |
        Where-Object Name -Match '^LICENSE(?:\.|$)' | Select-Object -First 1
    if ($license) {
        Copy-Item -LiteralPath $license.FullName -Destination (Join-Path $licenses.FullName ($dependency.Replace('/', '-') + '.txt'))
    }
}

Compress-Archive -Path (Join-Path $publish '*') -DestinationPath $archive -Force
Get-FileHash -LiteralPath $archive -Algorithm SHA256
