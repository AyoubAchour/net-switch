#ifndef AppVersion
  #error Pass /DAppVersion from package.json via scripts/build-release.ps1
#endif
#ifndef StageDir
  #error Pass /DStageDir with the allowlisted staging directory
#endif
#ifndef OutputDir
  #error Pass /DOutputDir with the release output directory
#endif
#ifndef AppArch
  #error Pass /DAppArch from scripts/build-release.ps1
#endif
#if AppArch == "arm64"
  #define AllowedArch "arm64"
#elif AppArch == "x64"
  #define AllowedArch "x64compatible"
#else
  #error AppArch must be x64 or arm64
#endif

[Setup]
AppId={{3ECce0AD-AE44-4768-8219-2C15C098976C}
AppName=Net Switch
AppVersion={#AppVersion}
AppPublisher=Ayoub Achour
DefaultDirName={autopf}\Net Switch
DefaultGroupName=Net Switch
DisableProgramGroupPage=yes
UsePreviousAppDir=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed={#AllowedArch}
ArchitecturesInstallIn64BitMode={#AllowedArch}
#if AppArch == "arm64"
MinVersion=10.0.22000
#endif
SetupIconFile={#StageDir}\assets\net-switch.ico
UninstallDisplayIcon={app}\assets\net-switch.ico
OutputDir={#OutputDir}
OutputBaseFilename=NetSwitch-Setup-{#AppVersion}-{#AppArch}
Compression=lzma2
SolidCompression=yes
CloseApplications=no
RestartApplications=no
UninstallLogging=yes

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: unchecked

[Files]
; StageDir is built exclusively from the allowlist, never from the working tree.
Source: "{#StageDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Net Switch"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ""{app}\launch.ps1"""; WorkingDir: "{app}"; IconFilename: "{app}\assets\net-switch.ico"
Name: "{autodesktop}\Net Switch"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ""{app}\launch.ps1"""; WorkingDir: "{app}"; IconFilename: "{app}\assets\net-switch.ico"; Tasks: desktopicon

[Run]
; Before Net Switch opens again: a startup task from 0.3.0 ran node.exe
; directly, which showed a console window. Missing tasks are fine, and a
; failure is logged without stopping the install (the server retries).
Filename: "{app}\runtime\node.exe"; Parameters: """{app}\tools\update-autostart.mjs"""; WorkingDir: "{app}"; StatusMsg: "Updating the startup task..."; Flags: runhidden waituntilterminated
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ""{app}\launch.ps1"""; WorkingDir: "{app}"; Description: "Open Net Switch"; Flags: postinstall nowait skipifsilent runasoriginaluser

[UninstallRun]
; The tasks that start Net Switch with Windows would otherwise point at files
; that are gone. A failure is logged and doesn't stop the uninstall.
Filename: "{app}\runtime\node.exe"; Parameters: """{app}\tools\remove-autostart.mjs"""; WorkingDir: "{app}"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveAutostart"

[Code]
var
  DeleteMachineData: Boolean;

function StopNetSwitch: Boolean;
var
  ExitCode: Integer;
begin
  Result := False;
  ExitCode := -1;
  if not FileExists(ExpandConstant('{app}\tools\stop.ps1')) then begin
    Log('Cannot stop Net Switch: tools\stop.ps1 is missing.');
    Exit;
  end;
  if Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    ExpandConstant('-NoProfile -ExecutionPolicy Bypass -File "{app}\tools\stop.ps1" -AppDir "{app}"'),
    ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ExitCode) then
    Result := ExitCode = 0;
  Log(Format('Net Switch shutdown result: %d', [ExitCode]));
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  { First install has no running copy. Upgrades must stop the existing copy. }
  if FileExists(ExpandConstant('{app}\server.mjs')) or
     FileExists(ExpandConstant('{app}\tools\stop.ps1')) then
    if not StopNetSwitch then
      Result := 'Net Switch could not be stopped. Quit Net Switch and retry. No files have been replaced.';
end;

function InitializeUninstall: Boolean;
begin
  { Abort before any deletion if the app cannot be stopped safely. }
  Result := StopNetSwitch;
  if not Result then
    SuppressibleMsgBox('Net Switch could not be stopped. Quit Net Switch and retry uninstalling. No files have been removed.', mbError, MB_OK, IDOK);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ExitCode: Integer;
begin
  { The questions use SuppressibleMsgBox: a silent uninstall (/SILENT, as winget
    runs it) takes the default answer instead of waiting for a click. }
  if CurUninstallStep = usUninstall then begin
    DeleteMachineData := False;
    if SuppressibleMsgBox('Undo the Windows settings Net Switch changed (connection priority, keeping Wi-Fi on with the cable)?',
      mbConfirmation, MB_YESNO or MB_DEFBUTTON1, IDYES) = IDYES then begin
      ExitCode := -1;
      { A certified migration may hold the only Undo record while the live
        folder is absent. Recover it before Node decides "nothing to undo". }
      if Exec(ExpandConstant('{app}\tools\netswitch-cleanup.exe'), '--prepare',
        ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ExitCode) then begin
        Log(Format('Net Switch Undo recovery result: %d', [ExitCode]));
        if ExitCode = 0 then begin
          ExitCode := -1;
          if Exec(ExpandConstant('{app}\runtime\node.exe'),
            ExpandConstant('"{app}\tools\restore-windows.mjs"'),
            ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ExitCode) then
            DeleteMachineData := ExitCode = 0;
        end;
      end;
      Log(Format('Net Switch Windows restore result: %d', [ExitCode]));
      if not DeleteMachineData then
        SuppressibleMsgBox('Windows settings could not be fully restored. Your undo record is kept in ' +
          ExpandConstant('{commonappdata}\Net Switch') +
          '. Reinstall Net Switch to retry restoring them.', mbError, MB_OK, IDOK);
    end else begin
      DeleteMachineData := SuppressibleMsgBox('Delete the Windows undo record anyway? The current Windows settings will stay in place, and Net Switch will no longer be able to undo them.',
        mbConfirmation, MB_YESNO or MB_DEFBUTTON2, IDNO) = IDYES;
    end;
    { Run while the cleanup binary still exists. Never follow a junction or
      rewrite an ACL, and retain every recovery record if restoration failed. }
    if DeleteMachineData then begin
      ExitCode := -1;
      Exec(ExpandConstant('{app}\tools\netswitch-cleanup.exe'), '--remove',
        ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ExitCode);
      Log(Format('Net Switch machine cleanup result: %d', [ExitCode]));
      if ExitCode <> 0 then
        SuppressibleMsgBox('Some Net Switch machine data could not be deleted from ' + ExpandConstant('{commonappdata}\Net Switch') + '.', mbError, MB_OK, IDOK);
    end;
    { User settings and logs are always retained. An elevated uninstaller may
      belong to a different account from the person who used the app. }
  end;
end;
