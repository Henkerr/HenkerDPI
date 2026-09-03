; HenkerDPI Installer Script
; Inno Setup 6+

[Setup]
AppId={{A8F4E3B2-5D6C-4B9A-8E2F-3D7E9F1B4C6A}
AppName=HenkerDPI
AppVersion=3.0.2
AppPublisher=Henkerr
AppPublisherURL=https://github.com/Henkerr
DefaultDirName={autopf}\HenkerDPI
DefaultGroupName=HenkerDPI
OutputDir=installer
OutputBaseFilename=HenkerDPI_Setup
SetupIconFile=icon.ico
UninstallDisplayIcon={app}\icon.ico
Compression=lzma2/ultra64
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
UninstallDisplayName=HenkerDPI
; Fewest possible clicks: no welcome page, no program-group page, and the
; folder page only when the user is not simply accepting the default.
DisableWelcomePage=yes
DisableProgramGroupPage=yes
DisableDirPage=auto
DisableReadyPage=yes
; Stop a second copy of the installer racing the first.
SetupMutex=HenkerDPI_Setup_Mutex
; Named after the app's single-instance mutex so Inno can tell the user to
; close a running copy instead of failing on a locked executable.
AppMutex=Global\HenkerDPI_SingleInstance

[Languages]
Name: "turkish"; MessagesFile: "compiler:Languages\Turkish.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create desktop shortcut"; GroupDescription: "Shortcuts:"
Name: "startmenu"; Description: "Add to Start menu"; GroupDescription: "Shortcuts:"

[InstallDelete]
; Upgrading from <= 2.3.0 reuses the recorded install folder, so the old
; executable and its updater backup would otherwise linger next to the new one.
Type: files; Name: "{app}\HenkerDPI_V2.exe"
Type: files; Name: "{app}\HenkerDPI_V2.exe.old"
Type: files; Name: "{app}\HenkerDPI.exe.old"
Type: files; Name: "{app}\HenkerDPI.exe.new"

[Files]
Source: "dist\HenkerDPI.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "icon.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "icon.png"; DestDir: "{app}"; Flags: ignoreversion
; LGPL v3 requires these to travel with the binary. They are embedded in the
; exe as well, but shipping them on disk makes them findable without unpacking.
Source: "LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "THIRD-PARTY-NOTICES.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "licenses\*"; DestDir: "{app}\licenses"; Flags: ignoreversion

[Icons]
; Start menu
Name: "{group}\HenkerDPI"; Filename: "{app}\HenkerDPI.exe"; IconFilename: "{app}\icon.ico"; Tasks: startmenu
Name: "{group}\Uninstall HenkerDPI"; Filename: "{uninstallexe}"; IconFilename: "{app}\icon.ico"; Tasks: startmenu

; Desktop shortcut
Name: "{commondesktop}\HenkerDPI"; Filename: "{app}\HenkerDPI.exe"; IconFilename: "{app}\icon.ico"; Tasks: desktopicon

[Run]
; Kurulumdan sonra çalıştır
Filename: "{app}\HenkerDPI.exe"; Description: "Launch HenkerDPI"; Flags: nowait postinstall skipifsilent runascurrentuser

; Autostart is intentionally NOT wired here. The exe requires administrator,
; and a plain HKLM..\Run value does not auto-elevate (it either nags with UAC
; every logon or is silently skipped). Autostart is owned solely by the in-app
; toggle, which registers an elevated, silent, drop-to-tray Scheduled Task.

[UninstallDelete]
; Preferences and the DNS journal live in %LOCALAPPDATA%\HenkerDPI since 2.3.0.
; {localappdata} resolves to the profile running the uninstaller; that is the
; same account that ran the elevated app, so it is the right target here.
; The {app}\* entries clean up files left behind by an upgrade from <= 2.2.0.
Type: filesandordirs; Name: "{localappdata}\HenkerDPI"
Type: files; Name: "{app}\henkerdpi_v2.pid"
Type: files; Name: "{app}\settings.json"
Type: files; Name: "{app}\settings.json.bak"
Type: files; Name: "{app}\custom_domains.json"
Type: files; Name: "{app}\lang_pref.json"
Type: files; Name: "{app}\theme_pref.json"
Type: dirifempty; Name: "{app}"

[UninstallDelete]
Type: files; Name: "{app}\HenkerDPI.exe.old"
Type: files; Name: "{app}\HenkerDPI.exe.new"

[UninstallRun]
Filename: "taskkill"; Parameters: "/f /im HenkerDPI.exe"; Flags: runhidden; RunOnceId: "KillApp"
Filename: "schtasks"; Parameters: "/delete /tn HenkerDPI /f"; Flags: runhidden; RunOnceId: "RemoveTask"
; Pre-rename logon task, for anyone upgrading from <= 2.3.0 and then removing.
Filename: "schtasks"; Parameters: "/delete /tn HenkerDPI_V2 /f"; Flags: runhidden; RunOnceId: "RemoveLegacyTask"

[Code]
procedure KillRunningApp();
var
  ResultCode: Integer;
begin
  // The installer overwrites the executable in place, which Windows refuses
  // while it is running. Close both the current and the pre-rename name.
  Exec('taskkill', '/f /im HenkerDPI.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('taskkill', '/f /im HenkerDPI_V2.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  KillRunningApp();
  Result := '';
end;

function InitializeUninstall(): Boolean;
begin
  Result := True;
  KillRunningApp();
end;
