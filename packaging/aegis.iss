; Inno Setup 6 script for the Aegis Windows installer.
; Built by packaging\build_windows.ps1, which passes /DAppVersion=<version>.
;
; Installs per user (no administrator prompt) so anyone can install Aegis.
; Aegis still asks to be run as administrator only for firewall changes.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{8E3C5B2A-4F1D-4C7E-9B6A-2D5F8A1C3E7B}
AppName=Aegis
AppVersion={#AppVersion}
AppVerName=Aegis {#AppVersion}
AppPublisher=Om Jangam
AppComments=Keeps this computer safe: security check, attack detection and firewall control.
DefaultDirName={localappdata}\Programs\Aegis
DefaultGroupName=Aegis
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=..\dist\installer
OutputBaseFilename=Aegis-Setup-{#AppVersion}
SetupIconFile=..\build\packaging\aegis.ico
UninstallDisplayIcon={app}\Aegis.exe
UninstallDisplayName=Aegis
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"

[Files]
Source: "..\dist\Aegis\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Aegis"; Filename: "{app}\Aegis.exe"; Comment: "Aegis security"
Name: "{autodesktop}\Aegis"; Filename: "{app}\Aegis.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\Aegis.exe"; Description: "Start Aegis now"; Flags: nowait postinstall skipifsilent
