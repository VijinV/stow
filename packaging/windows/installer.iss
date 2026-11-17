; Inno Setup script -> dist\Stow-<version>-windows-x64-setup.exe
; Build: iscc /DVersion=0.2.1 packaging\windows\installer.iss
#ifndef Version
  #define Version "0.2.1"
#endif
[Setup]
AppId={{6C1C9C5E-3B57-4C2B-9E7E-6A1B5E0D2F41}
AppName=Stow
AppVersion={#Version}
AppPublisher=Stow
AppComments=Your files, safely kept.
DefaultDirName={localappdata}\Programs\Stow
DefaultGroupName=Stow
PrivilegesRequired=lowest
OutputDir=..\..\dist
OutputBaseFilename=Stow-{#Version}-windows-x64-setup
SetupIconFile=..\..\assets\icon.ico
UninstallDisplayIcon={app}\backup-taker.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible

[Files]
Source: "..\..\target\x86_64-pc-windows-msvc\release\backup-taker.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Stow"; Filename: "{app}\backup-taker.exe"
Name: "{userdesktop}\Stow"; Filename: "{app}\backup-taker.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Run]
Filename: "{app}\backup-taker.exe"; Description: "Launch Stow"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "schtasks.exe"; Parameters: "/Delete /TN BackupTaker /F"; Flags: runhidden; RunOnceId: "RemoveTask"
