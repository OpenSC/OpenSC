param(
  [string]$version = '6.0.0'
)
& dotnet tool install -g --version $version wix
& wix extension add -g WixToolset.UI.wixext/$version
& wix extension add -g WixToolset.Util.wixext/$version
& cd win32
& dotnet new console --force --name CustomAction
& dotnet add CustomAction package WixToolset.WcaUtil --version $version --package-directory packages
& cd ..