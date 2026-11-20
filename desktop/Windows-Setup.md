# Personal Network Security for Windows

## Install with Setup

Run **PersonalNetworkSecurity-Setup-win-x64.exe**. Setup installs the app for your Windows account, adds a Start menu shortcut, and offers an optional desktop shortcut. The .NET runtime and dashboard are included. If Microsoft WebView2 is missing, Setup installs it using Microsoft's signed bootstrapper and requires an internet connection.

If Npcap is missing, Setup provides a button to open its official download page. Install Npcap, approve its administrator prompt, then return to Setup and click Next. You can also choose to install the app first and configure packet capture later. Capture requires Npcap and its configured permissions.

The free Npcap edition is installed separately. Automatic redistribution and silent installation require an appropriate Npcap OEM license. See [Npcap redistribution](https://npcap.com/oem/redist).

Run a newer Setup to update the installed app. Use Windows Installed apps to uninstall it. Uninstall removes the program and shortcuts while retaining the user database and settings under the data directory below. WebView2 and Npcap remain shared dependencies.

The generated setup executable is unsigned until a release signing certificate is configured. Windows may show an unknown-publisher warning. Verify the download source and the published SHA-256 before running it.

## Guided first use and optional GeoIP

After launch, Overview offers a getting-started guide when either GeoIP database is unavailable. Start capture and inspect applications, connections, traffic charts, or history immediately. Select **Guide me through GeoIP setup** to open Settings.

Under **Settings → Offline GeoIP**, follow the numbered instructions to obtain MMDB files from your own MaxMind account, extract them, and copy them into the displayed directory. **Copy database directory** helps locate that folder in File Explorer. Select **Reload databases** and confirm each file is ready. Save an approximate origin to enable mapped routes for endpoints with coordinates.

The City file enables approximate location and country information. The ASN file enables network ownership information. MaxMind credentials and license keys are not requested by the dashboard. The guide remains available in Settings after you hide the Overview reminder.

## Portable ZIP

Extract the complete ZIP to a folder you can write to, then run **PersonalNetworkSecurity.exe**. Close the window to stop capture and save the final checkpoint.

The Windows x64 package includes .NET and the dashboard assets. Windows must have the [WebView2 Evergreen Runtime](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/distribution). Install [Npcap](https://npcap.com/#download) separately to capture traffic. Capture permissions follow the Npcap installation settings.

The desktop app opens on a private loopback port and signs in automatically. Use **Live Packet Monitor** to choose an authorized adapter and start capture. The dashboard and local databases work offline.

SQLite data and the WebView2 profile live under `%LOCALAPPDATA%\PersonalNetworkSecurity`. Use **Settings** to manage retention and load optional MaxMind City and ASN databases.

To update, close the app and extract the new ZIP to a fresh folder. The new version opens the same local database and applies schema migrations.

Natural Earth provides the public-domain map assets. The `licenses` folder includes notices for bundled frontend packages.

## Build Setup from source

Install Inno Setup 6.3 or newer on the build machine alongside the project's .NET and Node prerequisites. Then run from the repository root:

```powershell
./desktop/Build-WindowsInstaller.ps1
```

Pass `-CompilerPath` to select an ISCC.exe installation. The script builds the Windows ZIP, downloads the WebView2 bootstrapper from Microsoft, verifies its Authenticode signature and publisher, and compiles `dist/PersonalNetworkSecurity-Setup-win-x64.exe`. Users running Setup do not need Git, Node, the .NET SDK, or Inno Setup.

For an already verified ZIP, use `-UseExistingPackage`. This packages the existing ZIP exactly as supplied, so confirm it contains the intended application revision.
