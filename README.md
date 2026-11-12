# Personal Network Security

## Windows desktop package

Build the self-contained Windows x64 ZIP from PowerShell on Windows with the .NET 10 SDK and Node 24 installed.

```powershell
./desktop/Build-WindowsPackage.ps1
```

Extract `dist/PersonalNetworkSecurity-win-x64.zip` and run `PersonalNetworkSecurity.exe`. The ZIP includes .NET and the production frontend. Install WebView2 Evergreen for the desktop window and Npcap for packet capture. [Windows setup guide](desktop/Windows-Setup.md)

Use `PersonalNetworkSecurity.exe --verify` from an interactive Windows desktop for an automated launch and keyboard-focus check. Set `PNS_DB_PATH` and `PNS_WEBVIEW_DATA_DIR` to temporary paths to isolate the check from your usual data.

The local Soft UI dashboard includes Windows IP packet capture, session counters, a 3D globe and an opt-in globe demo.

## Run locally on Windows

From the workspace root, start the backend in PowerShell.

```powershell
dotnet run --project backend/PersonalNetworkSecurity.Api
```

In a second terminal, start Vite.

```powershell
Set-Location frontend
npm.cmd ci
npm.cmd run dev
```

Open [the local dashboard](http://127.0.0.1:5173/). Vite proxies the health request to `127.0.0.1:5181`. Use **Check connection** on Overview to repeat the request. To exercise recovery, stop the API, check the connection, restart the API, and check again. Stop both servers with Ctrl+C when finished.

## Try the globe

Open **Global Traffic Map**, then turn on **Demo traffic**. The globe uses a local country-border texture and works without Npcap or a running API. Drag to rotate, scroll to zoom, and double-click the globe to focus an area. Click an arc or marker, or use the keyboard-accessible endpoint list, to inspect a route. Cyan travels outbound, orange travels inbound, and a red marker identifies the flagged example. The performance setting reduces curve segments and particle count.

Demo addresses and volumes are fictional and stay within the map view. If WebGL 2 is unavailable, the demo endpoint list remains usable. Live map and GeoIP integration are scheduled for Phases 5 and 6.

## Start Windows capture

1. Install [Npcap](https://npcap.com/#download) on Windows and start or restart the backend. The installer requires administrator rights. If the driver is installed in administrator-only mode, its access policy also applies when opening an adapter. Start with a standard user account. [Npcap permissions guide](https://npcap.com/guide/npcap-users-guide.html)
2. Open **Live Packet Monitor**. Paste the **Dashboard access code** from the backend terminal and select **Unlock**. Select an adapter you own or are authorized to monitor, then choose **Start capture**.
3. Generate traffic through that adapter and check **Overview** for rates and totals, **Live Packet Monitor** for metadata, and **Active Connections** for grouped IP flows. **Stop capture** ends the session and saves a final archive checkpoint.

Capture defaults to non-promiscuous mode and uses a 512-byte snapshot length. Packet parsing uses the original length reported by Npcap and only metadata leaves the callback. Captured payloads are discarded. The loopback adapter excludes the dashboard's development ports.

Direction uses the current unicast addresses of Windows interfaces. Both-local and ambiguous packets have their own counters and are excluded from upload/download rates and remote flows. NAT, VPNs, tunnel encapsulation, broadcast and multicast can limit what can be attributed. Flow entries expire after two minutes and the flow table and unique-IP set each cap at 4,096 entries. The live packet monitor shows up to 200 rows, and the API returns up to 50 recent flows.

## Analyze captured traffic

- **Active Connections** shows observed TCP state and process ownership alongside endpoint, country and byte totals. Windows socket tables are sampled every two seconds. TCP matches the full endpoint tuple. UDP requires an exact local binding with no conflicting owner. Process identity includes PID and start time. Short-lived sockets, wildcard bindings, inaccessible processes and scoped IPv6 addresses can remain unattributed. [Windows TCP owner table](https://learn.microsoft.com/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable) · [Windows UDP owner table](https://learn.microsoft.com/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable)
- **Applications** reports attributable bytes and packet counts for the session, estimated recent rates, and destinations found in the current flow sample. Local traffic is credited to the observed sender once.
- **Packet History** opens the current capture or a retained session. Apply a filter to search it, page through matches, or export the retained matching rows as CSV or JSON. The archive also offers a JSON export of the latest session checkpoint, including sampled flow and process summaries.
- **Traffic Analytics** shows throughput and packet rate over one or five minutes of observed stream samples, plus protocol distribution and country, application, IP and port rankings. Each view labels its sample scope.

## Configure security alerts

Open **Security Alerts** after unlocking the dashboard. Review the evidence for an event, then acknowledge or dismiss it. The Overview shows the open count, and live globe endpoints with an open high-severity alert receive a red marker when coordinates are available.

- Detection rules count non-trusted inbound and outbound bytes, distinct outbound destinations, repeated outbound TCP SYNs, and inbound RST+ACK replies matching observed SYNs. Thresholds use fixed 10-second windows. Retransmissions can contribute to SYN counts, and the reset rule requires both packets to be observed in the same window.
- Watchlist matches are informational, configured destination ports and countries are low severity, and blocklist matches are high severity. These labels reflect the configured rule and captured evidence. The app leaves traffic and firewall rules untouched.
- Optional reconnaissance rules flag TCP SYNs to distinct ports or destination and port combinations, echo requests to distinct hosts, unusual TCP flag patterns, and IP protocols outside an explicit numeric allowlist. Set each threshold above zero to enable it and choose a shared fixed window from 1 to 300 seconds. These are indicators for review. Capture is limited to inbound and outbound traffic visible to the selected adapter.
- Optional traffic anomaly rules flag high inbound TCP SYN, UDP, or ICMP rates and multiple incomplete inbound TCP handshakes. Each rate is measured against the full configured traffic anomaly window. UDP can use a packet or byte threshold. Connection exhaustion estimates incomplete handshakes from captured packets within the window. It cannot measure the operating system backlog or connections established before capture.
- Optional DNS rules inspect complete plaintext UDP/53 questions from the local machine and correlate visible replies within a configurable window. Configure a local domain suffix denylist, exclusions, query and NXDOMAIN thresholds, a numeric record type allowlist, and tunneling sensitivity. The conflicting-reply rule checks for NOERROR and NXDOMAIN on the same captured transaction. TCP DNS, encrypted DNS, and answer-record comparisons are outside this detector's coverage. DNS names appear in DNS alert evidence and are excluded from general packet records.
- Optional outbound rules flag regular TCP connection attempts, large asymmetric transfers, and connections outside an expected port list. Approved process names rely on available socket attribution. The threat intelligence rule matches IPs, CIDRs, and visible DNS questions against a manually supplied snapshot with a source and date. Snapshots expire after the configured age. Alert evidence includes the snapshot source and date.
- Optional local network rules flag conflicting IPv4 ARP replies, unexpected gateway MACs, DHCPv4 offers or acknowledgments with unapproved server identifiers, and unusual internal TCP attempts to configured sensitive ports. Gateway addresses come from the selected Windows adapter at capture start. A trusted MAC list can include failover devices; without one, the first visible ARP reply establishes the baseline. Coverage is limited to traffic visible on the selected adapter. DHCP identifiers are not authenticated.
- Trusted IP addresses are excluded from rule evaluation. Repeats of the same rule and endpoint are suppressed for 30 seconds. The latest 200 alerts, their states, and rule settings are saved locally. Export filtered alerts as CSV or JSON from **Security Alerts**.

The development API uses IPv4 loopback, a fixed Host check, explicit browser origins, and a random bearer code that changes on API restart. The dashboard keeps the code in the tab's session storage. SignalR sends a fresh snapshot when connecting and updates about once a second. A reconnect clears stale data and starts a fresh 60-second throughput window. Protocol counts use the recent packet buffer.

For parallel local development instances, set matching `PNS_API_PORT` and `PNS_UI_PORT` environment variables in both terminals before starting the servers. Open the configured UI port on `127.0.0.1`.

## Enable offline geolocation

1. Obtain **GeoLite2 City** and **GeoLite2 ASN** in MMDB format from your MaxMind account. [MaxMind GeoLite downloads](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/)
2. Create the directory shown under **Settings → Offline GeoIP** and copy in `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`. The default directory is `%LOCALAPPDATA%\PersonalNetworkSecurity\GeoIP`. To use another directory, set `PNS_GEOIP_DIR` in the backend terminal before startup.
3. Choose **Reload databases**. City and ASN load independently. If a replacement cannot load, the previous usable reader remains active and Settings displays the warning.
4. Save an approximate map origin using coarse coordinates or a public IP address you supply. A public IP requires a City match. The API saves the origin locally.

**Global Traffic Map** draws live arcs when both endpoints have coordinates. The endpoint list still shows private, special-use, and unmatched addresses, with reasons where available. **IP Intelligence** looks up any valid IPv4 or IPv6 address locally. GeoIP can identify a VPN, proxy, or hosting network's exit area. The map shows estimated areas and communication between endpoints. Physical packet routes remain unknown.

Demo mode stays separate. The application makes no external geolocation or public-IP discovery requests.

## Local storage and retention

The API opens `%LOCALAPPDATA%\PersonalNetworkSecurity\dashboard.sqlite3` and applies schema migrations on startup. Set `PNS_DB_PATH` in the API terminal to use another file. Use a separate database path for each parallel backend instance.

In **Settings → Local storage**, choose a retention period from 1 to 90 days. The default is seven days. The archive keeps up to 30 capture sessions, 10,000 packet metadata rows per session, and 200 alerts. It stores packet metadata, the latest summary checkpoint per session, alert state, detection rules, address lists, origin settings, and a bounded GeoIP cache keyed to the installed database contents. Packet payloads and dashboard access codes stay out of SQLite.

The API checkpoints a running capture about every 10 seconds and on stop or orderly shutdown. Alert events are batched separately, while alert actions and settings save immediately. An abrupt shutdown can lose records gathered since the last checkpoint. Automatic cleanup runs at startup and during operation. Applying a shorter period removes expired archive records immediately. Exported files are managed separately.

## Network tools

Open **Tools** and switch between **Home** and **Advanced**. Connection Health checks Wi-Fi link status, the first available IPv4 gateway, system DNS, and ICMP and TLS reachability for the hostname or address you enter. ICMP responses depend on the endpoint and network policy.

Application Activity shows attributed traffic and recent destinations from the current capture. Advanced mode adds protocol and time filters for the destination list. Network Change Timeline samples adapter state, assigned addresses, gateways, and DNS settings every 10 seconds. Device Inventory uses the Windows IPv4 neighbor cache. Device names are saved locally, and first and last observation times cover the current app run.

Session Comparison opens two SQLite checkpoints. Export a redacted JSON report with totals, or use Advanced mode to include timestamps, sampled flow totals, and alert metadata. The report omits IP addresses, MAC addresses, process names, adapter names, and raw alert evidence.

## Build and verify

```powershell
dotnet build PersonalNetworkSecurity.slnx
dotnet run --project tests/PersonalNetworkSecurity.Capture.Checks
Set-Location frontend
npm.cmd ci
npm.cmd run build
```

With both development servers running, `Invoke-RestMethod http://127.0.0.1:5173/api/health` should return `status: ready`. The frontend build runs TypeScript checking before bundling, and the dev server provides the API proxy. The desktop package serves the production bundle from its loopback host.

The fixture runner also tests IP classification and missing or corrupt MMDB files. For positive lookup and reload checks, set `PNS_GEO_TEST_DIR` to a directory containing the public `GeoIP2-City-Test.mmdb` and `GeoLite2-ASN-Test.mmdb` fixtures saved as `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`. [MaxMind test data](https://github.com/maxmind/MaxMind-DB/tree/main/test-data)

Set `PNS_TEST_WINDOWS_SOCKETS=1` to also verify ownership against real IPv4 and IPv6 TCP and UDP loopback sockets using Windows socket APIs.

Set `PNS_TEST_DESKTOP_HOST=1` to check the desktop host's static assets, cookie authentication, and origin policy. Set `PNS_TEST_DESKTOP_CAPTURE=1` alongside it to send a controlled Npcap loopback packet and verify that host shutdown saves it. The fixture runner measures the time to aggregate 100,000 metadata updates and checks the storage bounds.

See the [architecture and implementation roadmap](docs/roadmap.md) for dependency versions, prerequisites, planned modules and acceptance checks.
