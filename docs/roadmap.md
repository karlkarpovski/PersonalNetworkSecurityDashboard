# Architecture and delivery plan

## Desktop and development

Use .NET 10 LTS and ASP.NET Core with a React/TypeScript frontend. Package the release as a WPF application hosting WebView2 Evergreen. WPF lets the .NET launcher own the local server lifecycle, and WebView2 gives the existing React frontend a Windows-managed Chromium runtime for WebGL. A Tauri wrapper would add a Rust toolchain and sidecar lifecycle around the .NET backend. Use a regular browser with Vite during development. Ship all UI, basemap and texture assets locally, and record their licenses.

## Capture and streaming

Open a user-selected Npcap adapter on explicit start, in non-promiscuous mode by default. Parse with PacketDotNet inside the capture pipeline and discard payloads after extracting metadata. Use current interface addresses, the capture interface, and link-layer evidence where available to classify inbound, outbound, local, or unknown traffic. Keep ambiguity visible for VPNs, multicast, broadcast and loopback. Account separately for driver drops, queue drops and samples omitted by the UI.

Feed a bounded channel of metadata into a flow aggregator. Use adapter, protocol, address family and normalized local/remote endpoints as the flow key. Maintain separate directional counters and expire idle flows. Publish capped snapshots through SignalR at a fixed cadence, independent of packet rate. Include a session ID and monotonic sequence number. On reconnect, replace the client snapshot from a fresh baseline before applying updates. REST handles configuration, queries and exports. Persist summarized traffic separately from the live packet ring.

Serve the production frontend and API from one ephemeral IPv4 loopback origin. The desktop launcher will establish a per-launch authenticated session using an unpredictable secret delivered by the host, with an HttpOnly, SameSite session cookie after bootstrap. Validate the Host header and require same-origin checks for mutations and WebSocket upgrades. Restrict WebView2 navigation to the application origin and use a scoped API with no blanket CORS policy. If capture requires elevation, keep the web UI unprivileged and isolate elevated operations behind a Windows ACL-restricted capture helper. The development UI uses a per-launch bearer code from the API console and an authenticated SignalR subscription. The client discards its previous baseline when the stream disconnects.

## Geolocation and globe

Resolve eligible public IPv4 and IPv6 addresses against local GeoLite2 City and ASN MMDB files. Cache hits and misses with a size limit and database version. Validate both files before activating an update and keep existing readers available until outstanding lookups finish. Classify special-use addresses locally. Keep unmatched coordinates empty and show ASN independently of City coverage. VPNs and proxies generally map to the observed egress. Display the database's accuracy radius when available.

Use a user-configured approximate origin or look up a public address supplied by the user against the same local database. If either endpoint lacks coordinates, retain the flow in tables and omit its arc. Phase 6 keeps origin settings in memory and supports reloading locally supplied City and ASN files while the API runs.

Render the globe directly in Three.js to control arrow orientation, pointer picking and GPU resource disposal. Use a local country-border texture from [Natural Earth 1:110m Admin 0 countries](https://github.com/nvkelso/natural-earth-vector/blob/v5.1.2/geojson/ne_110m_admin_0_countries.geojson). A bidirectional flow has two tracks at different altitudes along the same great-circle corridor. Cyan particles move outbound and orange particles move inbound. Arrowheads follow the tangent of each track. Volume drives width within a fixed range. For live data, use inactivity to drive opacity and expiry, cap routes by priority and recency, and keep snapshot updates separate from animation frames. Keep a shared flow selection and filter model for the globe and planned 2D view. Label arcs as approximate endpoint communication, with no physical path information.

## Dependency baseline

| Phase | Version target |
| --- | --- |
| Foundation | .NET SDK 10.0.403 with feature-band patch roll-forward, ASP.NET Core 10, Node 24 LTS, npm 11, React 19.3.0, Vite 8.3.6, TypeScript 6.0 |
| Dashboard | Shared CSS tokens and Lucide React 1.70.0. Evaluate Recharts 3 when real series are introduced. |
| Globe | Three.js 0.187.0 with OrbitControls. Confirm 2D needs before adding MapLibre GL JS 5. |
| Capture | SharpPcap 6.3.1, PacketDotNet 1.4.8, separately installed Npcap |
| Streaming | ASP.NET Core SignalR 10 and a matching Microsoft SignalR JavaScript client |
| Geolocation | MaxMind.GeoIP2 6.1.0 |
| Storage and logging | Microsoft.Data.Sqlite 10.0.14 and Serilog.AspNetCore 10.0.0 |
| Desktop | WPF on .NET 10, WebView2 SDK 1.0.4314.35, Evergreen runtime |

Versions for later phases are candidates. Recheck published stable patches, compatibility, security and licenses before each restore. Pin direct dependencies and check in npm's resolved lockfile.

## Target layout

```text
backend/
  PersonalNetworkSecurity.Api/             HTTP, SignalR and composition root
  PersonalNetworkSecurity.Core/            Contracts and domain models
  PersonalNetworkSecurity.Capture/         Npcap, parsing and Windows attribution
  PersonalNetworkSecurity.Analysis/        Flow aggregation, analytics and security rules
  PersonalNetworkSecurity.GeoIP/           Offline lookup and database lifecycle
  PersonalNetworkSecurity.Infrastructure/ SQLite, settings and exports
frontend/src/                              Shell and feature modules
desktop/                                   WPF/WebView2 host and packaging
tests/                                     Unit, integration and capture fixtures
docs/                                      Architecture and operator instructions
```

Add projects as their phase introduces real code.

## Dashboard layout

The user's reference informs the horizontal navigation, navy surfaces with blue edge lighting, wide throughput plot paired with a protocol ring, and map paired with destination rankings. Use shared Soft UI panels and inset controls across views. At narrow widths, stack the panels in reading order and keep navigation horizontally scrollable with keyboard focus visible.

- Globe and IP intelligence use a wide geographic stage with filters above it and endpoint or destination details alongside it. Keep the details below the visualization on narrow screens.
- Packet monitor, connections, applications and history use a filter row over a results table. Show selected-record details in an adjacent panel where space permits.
- Analytics uses the overview's wide-and-narrow chart pairing and compact legends. Alerts use the same panel header with severity labels, then place evidence next to the selected alert.
- Settings groups controls into titled panels for adapter, local databases and storage. Keep API health distinct from capture state throughout.
- Use empty chart scaffolds for unavailable data. An explicitly labeled demo mode in Phase 3 will supply simulated routes and traffic.

The local SVG basemap uses [Natural Earth 1:110m land](https://github.com/nvkelso/natural-earth-vector/blob/v5.1.2/geojson/ne_110m_land.geojson), projected to a simplified equirectangular silhouette. Natural Earth data is in the [public domain](https://www.naturalearthdata.com/about/terms-of-use/).

## Roadmap and acceptance checks

| Phase | Deliverable | Verify before moving on |
| --- | --- | --- |
| 1 | Loopback API, React shell, local tooling and honest startup state | Build both projects and check navigation, health and API-offline handling |
| 2 | Dashboard cards, charts and responsive layout | Check keyboard navigation, resize behavior and empty states |
| 3 | Globe interaction, bidirectional arcs, filters and isolated demo mode | Inspect both directions, route picking, camera controls and frame time at the route cap |
| 4 | Adapter selection, Npcap lifecycle, parsing and bounded flow aggregation | Compare fixture and authorized live counts, then exercise missing driver, permission and unplug cases |
| 5 | Authenticated REST and SignalR, live UI and reconnection | Reject foreign hosts and origins, reconnect without stale data, and verify demo/live isolation |
| 6 | Local City and ASN resolution, origin settings and map details | Test private, IPv6, missing, corrupt and replacement databases plus missing origins |
| 7 | Windows socket attribution, packet history and traffic analytics | Check tuple matching, PID reuse and ambiguous UDP ownership against Windows observations |
| 8 | Evidence-based rules, watchlists and alert actions | Check threshold windows, suppression, evidence text and acknowledgement behavior |
| 9 | SQLite migrations, retention, settings and CSV/JSON exports | Exercise restart, migration, retention, interrupted writes and export safety |
| 10 | Performance, accessibility and Windows packaging | Run automated suites, stress and offline tests, then install and capture on supported Windows 10 and 11 systems |

## Prerequisites

- Phase 1 requires the .NET 10 SDK, Node 24 and npm, and a modern browser. Git is needed once the workspace is initialized or attached to the intended repository. VS Code or a Visual Studio release with .NET 10 support can open the solution.
- Phase 4 requires the official [Npcap installer](https://npcap.com/#download). Installation needs administrator permission. Runtime capture permissions depend on the driver configuration. Review Npcap licensing before bundling it.
- Phase 6 requires a MaxMind account and [GeoLite City and ASN MMDB downloads](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/). Keep license keys outside source control. Manual file updates are sufficient for offline operation.
- The packaged desktop app requires the [WebView2 Evergreen Runtime](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/distribution).

Dependency references include the [Microsoft .NET support policy](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core), [Vite 8 releases](https://github.com/vitejs/vite/releases), [React releases](https://react.dev/versions), [Globe.gl](https://github.com/vasturiano/globe.gl), [SharpPcap](https://www.nuget.org/packages/SharpPcap/6.3.1), [PacketDotNet](https://www.nuget.org/packages/PacketDotNet/1.4.8), and [MaxMind.GeoIP2](https://www.nuget.org/packages/MaxMind.GeoIP2/6.1.0).
