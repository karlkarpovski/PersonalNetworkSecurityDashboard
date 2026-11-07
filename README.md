# Personal Network Security

Phase 2 adds a responsive Soft UI dashboard with session metrics, traffic and protocol panels, an offline basemap, and summaries for applications, alerts and activity. The API health indicator is functional. Traffic views show explicit empty states until monitoring is available.

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

## Build and verify

```powershell
dotnet build PersonalNetworkSecurity.slnx
Set-Location frontend
npm.cmd ci
npm.cmd run build
```

With both servers running, `Invoke-RestMethod http://127.0.0.1:5173/api/health` should return `status: ready` and `capture: unavailable`. The frontend build runs TypeScript checking before bundling. Its output is a static bundle in `frontend/dist`. The dev server currently provides the API proxy. Release hosting and the WebView2 launcher are part of the packaging phase.

See the [architecture and implementation roadmap](docs/roadmap.md) for dependency versions, prerequisites, planned modules and acceptance checks.
