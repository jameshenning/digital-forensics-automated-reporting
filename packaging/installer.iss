; DFARS Desktop installer script for Inno Setup 6.x
; -----------------------------------------------------------------------------
; Compile this with Inno Setup Compiler (https://jrsoftware.org/isinfo.php) AFTER
; running `python packaging/build.py`. The result is a single self-contained
; .exe installer in dist/installer/.
;
; Inno Setup is NOT installed by build.py — you'll need to install it once
; from https://jrsoftware.org/isdl.php and add it to PATH (or use the GUI).
;
; To compile from CLI:
;     iscc packaging/installer.iss
;
; Output:
;     dist/installer/DFARS-Desktop-Setup-1.0.0.exe

#define MyAppName "DFARS Desktop"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "DFARS Project"
#define MyAppURL ""
#define MyAppExeName "DFARS Desktop.exe"
#define SourceBundle "..\dist\DFARS Desktop"

[Setup]
; AppId — keep this UUID stable across versions so updates replace the old install.
; Generate a fresh one (Tools → Generate App ID in the IDE) for any FORK of this app.
AppId={{8E5C2F4A-3B7D-4E1F-9C8A-1F2E3D4C5B6A}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}

DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
DisableDirPage=no
LicenseFile=
InfoBeforeFile=
InfoAfterFile=

OutputBaseFilename=DFARS-Desktop-Setup-{#MyAppVersion}
OutputDir=..\dist\installer
SetupIconFile=..\app\static\dfars.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}

Compression=lzma2
SolidCompression=yes

ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

PrivilegesRequired=admin
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Recursively pulls in everything PyInstaller produced under dist\DFARS Desktop\
Source: "{#SourceBundle}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\_internal\app\static\dfars.ico"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon; IconFilename: "{app}\_internal\app\static\dfars.ico"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; The user's data lives in %APPDATA%\DFARS\ — we deliberately do NOT delete it
; on uninstall so forensic case data survives a reinstall. Document this loudly
; in the README so users know how to wipe it manually if they really want to.
