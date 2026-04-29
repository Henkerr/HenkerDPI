; HenkerDPI V2 Installer Script
; Inno Setup 6+

[Setup]
AppId={{A8F4E3B2-5D6C-4B9A-8E2F-3D7E9F1B4C6A}
AppName=HenkerDPI V2
AppVersion=2.0.0
AppPublisher=Henkerr
AppPublisherURL=https://github.com/Henkerr
DefaultDirName={autopf}\HenkerDPI_V2
DefaultGroupName=HenkerDPI V2
OutputDir=installer
OutputBaseFilename=HenkerDPI_V2_Setup
SetupIconFile=icon.ico
UninstallDisplayIcon={app}\icon.ico
Compression=lzma2/ultra64
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
DisableWelcomePage=no
WizardImageFile=compiler:WizModernImage.bmp
WizardSmallImageFile=compiler:WizModernSmallImage.bmp

[Languages]
Name: "turkish"; MessagesFile: "compiler:Languages\Turkish.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create desktop shortcut"; GroupDescription: "Shortcuts:"
Name: "startmenu"; Description: "Add to Start menu"; GroupDescription: "Shortcuts:"
Name: "autostart"; Description: "Start automatically on Windows boot"; GroupDescription: "Other:"; Flags: unchecked

[Files]
Source: "dist\HenkerDPI_V2.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "icon.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "icon.png"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
; Start menu
Name: "{group}\HenkerDPI V2"; Filename: "{app}\HenkerDPI_V2.exe"; IconFilename: "{app}\icon.ico"; Tasks: startmenu
Name: "{group}\Uninstall HenkerDPI V2"; Filename: "{uninstallexe}"; IconFilename: "{app}\icon.ico"; Tasks: startmenu

; Desktop shortcut
Name: "{commondesktop}\HenkerDPI V2"; Filename: "{app}\HenkerDPI_V2.exe"; IconFilename: "{app}\icon.ico"; Tasks: desktopicon

[Run]
; Kurulumdan sonra çalıştır
Filename: "{app}\HenkerDPI_V2.exe"; Description: "Launch HenkerDPI V2"; Flags: nowait postinstall skipifsilent runascurrentuser

[Registry]
; Auto-start (seçiliyse)
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "HenkerDPI_V2"; ValueData: """{app}\HenkerDPI_V2.exe"""; Flags: uninsdeletevalue; Tasks: autostart

[UninstallDelete]
Type: files; Name: "{app}\henkerdpi_v2.pid"
Type: files; Name: "{app}\settings.json"
Type: files; Name: "{app}\custom_domains.json"
Type: files; Name: "{app}\lang_pref.json"
Type: files; Name: "{app}\theme_pref.json"
Type: dirifempty; Name: "{app}"

[UninstallRun]
Filename: "taskkill"; Parameters: "/f /im HenkerDPI_V2.exe"; Flags: runhidden; RunOnceId: "KillApp"
Filename: "schtasks"; Parameters: "/delete /tn HenkerDPI_V2 /f"; Flags: runhidden; RunOnceId: "RemoveTask"

[Code]
function InitializeUninstall(): Boolean;
var
  ResultCode: Integer;
begin
  Result := True;
  Exec('taskkill', '/f /im HenkerDPI_V2.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;
