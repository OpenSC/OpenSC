param(
  [string]$version = '5.0.2'
)
& dotnet tool install -g --version $version wix
& wix extension add -g WixToolset.UI.wixext/$version
& wix extension add -g WixToolset.Util.wixext/$version