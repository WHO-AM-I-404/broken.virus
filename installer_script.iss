[Setup]
AppName=Destructive Glitch Simulator
AppVersion={#GetFileVersion("release\DestructiveGlitchSimulator.exe")}
DefaultDirName={pf}\Destructive Glitch Simulator
DefaultGroupName=Destructive Glitch Simulator
OutputDir=.
OutputBaseFilename=DestructiveGlitchSimulator_Setup
Compression=lzma
SolidCompression=yes

[Files]
Source: "release\DestructiveGlitchSimulator.exe"; DestDir: "{app}"; Flags: ignoreversion
; Tambahkan file lain jika diperlukan

[Icons]
Name: "{group}\Destructive Glitch Simulator"; Filename: "{app}\DestructiveGlitchSimulator.exe"
Name: "{group}\Uninstall Destructive Glitch Simulator"; Filename: "{uninstallexe}"
