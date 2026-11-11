# Personal Network Security for Windows

Extract the complete ZIP to a folder you can write to, then run **PersonalNetworkSecurity.exe**. Close the window to stop capture and save the final checkpoint.

The Windows x64 package includes .NET and the dashboard assets. Windows must have the [WebView2 Evergreen Runtime](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/distribution). Install [Npcap](https://npcap.com/#download) separately to capture traffic. Capture permissions follow the Npcap installation settings.

The desktop app opens on a private loopback port and signs in automatically. Use **Live Packet Monitor** to choose an authorized adapter and start capture. The dashboard and local databases work offline.

SQLite data and the WebView2 profile live under `%LOCALAPPDATA%\PersonalNetworkSecurity`. Use **Settings** to manage retention and load optional MaxMind City and ASN databases.

To update, close the app and extract the new ZIP to a fresh folder. The new version opens the same local database and applies schema migrations.

Natural Earth provides the public-domain map assets. The `licenses` folder includes notices for bundled frontend packages.
