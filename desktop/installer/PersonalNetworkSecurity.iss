#ifndef PackageDir
  #error PackageDir is required
#endif
#ifndef Bootstrapper
  #error Bootstrapper is required
#endif
#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
[Setup]
AppId={{A8DF086F-B704-4915-A332-69E0D9DA4E31}
AppName=Personal Network Security
AppVersion={#AppVersion}
DefaultDirName={localappdata}\Programs\PersonalNetworkSecurity
DefaultGroupName=Personal Network Security
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
OutputDir=..\..\dist
OutputBaseFilename=PersonalNetworkSecurity-Setup-win-x64
SetupIconFile=..\PersonalNetworkSecurity.Desktop\Assets\Logo.ico
UninstallDisplayIcon={app}\PersonalNetworkSecurity.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
DisableProgramGroupPage=yes
[Messages]
FinishedLabel=Setup has installed [name]. Launch the app and follow the getting-started guide on Overview. GeoIP databases are optional; Settings contains instructions for adding locations and network ownership.

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked
[Files]
Source: "{#PackageDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#Bootstrapper}"; Flags: dontcopy
[Icons]
Name: "{autoprograms}\Personal Network Security"; Filename: "{app}\PersonalNetworkSecurity.exe"
Name: "{autodesktop}\Personal Network Security"; Filename: "{app}\PersonalNetworkSecurity.exe"; Tasks: desktopicon
[Run]
Filename: "{app}\PersonalNetworkSecurity.exe"; Description: "Launch Personal Network Security"; Flags: nowait postinstall skipifsilent
[Code]
var
  DependencyPage: TWizardPage;
  DependencyLabel: TNewStaticText;
  DriverButton: TNewButton;
  ContinueWithoutDriver: TNewCheckBox;

function NpcapInstalled: Boolean;
begin
  Result := FileExists(ExpandConstant('{sys}\Npcap\wpcap.dll'));
end;

function HasRuntimeAt(Root: Integer): Boolean;
var
  Version: String;
begin
  Result := RegQueryStringValue(Root,
    'Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}',
    'pv', Version) and (Version <> '') and (Version <> '0.0.0.0');
end;

function WebViewInstalled: Boolean;
begin
  Result := HasRuntimeAt(HKCU) or HasRuntimeAt(HKLM32);
end;

procedure OpenDriver(Sender: TObject);
var
  Code: Integer;
begin
  ShellExec('open', 'https://npcap.com/#download', '', '', SW_SHOWNORMAL, ewNoWait, Code);
end;

procedure InitializeWizard;
begin
  DependencyPage := CreateCustomPage(wpWelcome, 'Packet capture driver',
    'Npcap is required for live traffic capture.');
  DependencyLabel := TNewStaticText.Create(DependencyPage);
  DependencyLabel.Parent := DependencyPage.Surface;
  DependencyLabel.SetBounds(0, 0, DependencyPage.SurfaceWidth, ScaleY(85));
  DependencyLabel.AutoSize := False;
  DependencyLabel.WordWrap := True;
  DependencyLabel.Caption :=
    'Setup includes .NET and installs Microsoft WebView2 when needed. WebView2 installation requires internet access.' +
    Chr(13) + Chr(10) + Chr(13) + Chr(10) + 'If Npcap is missing, install it from the official website, then return here and click Next. Its installer may request administrator approval.';
  DriverButton := TNewButton.Create(DependencyPage);
  DriverButton.Parent := DependencyPage.Surface;
  DriverButton.SetBounds(0, ScaleY(100), ScaleX(230), ScaleY(30));
  DriverButton.Caption := 'Open official Npcap download';
  DriverButton.OnClick := @OpenDriver;
  ContinueWithoutDriver := TNewCheckBox.Create(DependencyPage);
  ContinueWithoutDriver.Parent := DependencyPage.Surface;
  ContinueWithoutDriver.SetBounds(0, ScaleY(150), DependencyPage.SurfaceWidth, ScaleY(40));
  ContinueWithoutDriver.Caption := 'Install the app now and set up packet capture later';
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := (PageID = DependencyPage.ID) and NpcapInstalled;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if (CurPageID = DependencyPage.ID) and not NpcapInstalled and not ContinueWithoutDriver.Checked then
  begin
    MsgBox('Npcap is not detected yet. Install it, or select the option to set up capture later.', mbInformation, MB_OK);
    Result := False;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ExitCode: Integer;
begin
  Result := '';
  if not WebViewInstalled then
  begin
    ExtractTemporaryFile('MicrosoftEdgeWebview2Setup.exe');
    if not Exec(ExpandConstant('{tmp}\MicrosoftEdgeWebview2Setup.exe'),
      '/silent /install', '', SW_HIDE, ewWaitUntilTerminated, ExitCode) then
      Result := 'Could not start Microsoft WebView2 setup. Check your connection and retry.'
    else if not WebViewInstalled then
      Result := Format('Microsoft WebView2 installation did not complete (code %d). Check your connection and retry.', [ExitCode]);
  end;
end;
