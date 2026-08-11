param(
  [string]$version = '7.0.0'
)

$ErrorActionPreference = 'Stop'

function Exec([scriptblock]$cmd) {
    & $cmd
    if ($LASTEXITCODE -ne 0) { throw "Command failed (exit $LASTEXITCODE)" }
}

Exec { dotnet tool install -g --version $version wix }
Exec { wix eula accept wix7 }
Exec { wix extension add -g WixToolset.UI.wixext/$version }
Exec { wix extension add -g WixToolset.Util.wixext/$version }
Set-Location win32
Exec { dotnet new console --force --name CustomAction }
Exec { dotnet add CustomAction package WixToolset.WcaUtil --version $version --package-directory packages }
Set-Location ..
