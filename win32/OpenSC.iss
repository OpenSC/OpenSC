[Setup]
AppName=OpenSC
AppVerName=OpenSC 0.12.0
AppPublisher=OpenSC project
AppPublisherURL=http://www.opensc-project.org/
AppSupportURL=http://www.opensc-project.org/opensc/
AppUpdatesURL=http://www.opensc-project.org/opensc/
DefaultDirName={pf}\OpenSC
OutputBaseFilename=OpenSC-0.12.0
Compression=lzma/normal
SolidCompression=true
MinVersion=0,5.0.2195
VersionInfoCompany=OpenSC Project
AppCopyright=LGPL
PrivilegesRequired=poweruser
DisableDirPage=false
DisableProgramGroupPage=false
ShowLanguageDialog=auto
AppID={{BDD73EB0-0485-4B79-93EC-CF2EAEFF3BAB}
UsePreviousAppDir=true
AppendDefaultDirName=false
AppVersion=0.12.0
VersionInfoVersion=0.12.0
VersionInfoDescription=OpenSC tools and libraries
VersionInfoTextVersion=v0.12.0
DisableReadyPage=true
InternalCompressLevel=max
VersionInfoCopyright=2010 OpenSC Project
DisableStartupPrompt=true
AlwaysShowComponentsList=false
ShowComponentSizes=false
FlatComponentsList=false
WizardImageBackColor=clWhite
DisableFinishedPage=false
InfoBeforeFile=README.rtf
VersionInfoProductName=OpenSC
VersionInfoProductVersion=0.12.0
AllowRootDirectory=true
UninstallDisplayName=OpenSC
DefaultGroupName=OpenSC

[Tasks]

[Files]
Source: opensc\*.profile; DestDir: {app}\profiles
Source: opensc\*.dll; DestDir: {sys}; Flags: overwritereadonly replacesameversion ignoreversion uninsnosharedfileprompt restartreplace
Source: opensc\*.exe; DestDir: {app}; Flags: overwritereadonly replacesameversion ignoreversion
Source: engine_pkcs11\*.dll; DestDir: {sys}; Components: OpenSSL_engine; Flags: overwritereadonly replacesameversion ignoreversion
Source: opensc.conf; DestDir: {app};
;Source: www.opensc-project.org.url; DestDir: {app}
[Icons]
;Name: {group}\OpenSC Project website; Filename: {app}\www.opensc-project.org.url; Comment: Go to OpenSC Project website; Components: 

[Registry]
Root: HKLM; Subkey: Software\OpenSC Project\OpenSC; ValueType: string; ValueName: ConfigFile; ValueData: {app}\opensc.conf; Flags: uninsdeletekey; Components: 
Root: HKLM; Subkey: Software\OpenSC Project\OpenSC; ValueType: string; ValueName: ProfileDir; ValueData: {app}\profiles; Flags: uninsdeletekey; Components: 
[Components]
Name: OpenSC; Description: OpenSC core library; Flags: fixed; Types: custom compact full
Name: OpenSSL_engine; Description: OpenSSL engine for using PKCS11 modules; Types: custom full
