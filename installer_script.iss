[Setup]
AppName=Broken
AppVersion={#GetFileVersion("release\broken.exe")}
DefaultDirName={pf}\Broken
DefaultGroupName=Broken
OutputDir=.
OutputBaseFilename=broken_Setup
Compression=lzma
SolidCompression=yes

[Files]
Source: "release\broken.exe"; DestDir: "{app}"; Flags: ignoreversion
; Tambahkan file lain jika diperlukan

[Icons]
Name: "{group}\Broken"; Filename: "{app}\broken.exe"
Name: "{group}\Uninstall Broken"; Filename: "{uninstallexe}"
