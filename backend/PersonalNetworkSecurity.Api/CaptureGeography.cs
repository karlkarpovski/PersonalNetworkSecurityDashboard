using PersonalNetworkSecurity.GeoIP;

internal sealed record OriginRequest(string? Mode, double? Latitude, double? Longitude, string? Label, string? Ip);
internal sealed record GeoOrigin(string Mode, double Latitude, double Longitude, string Label, string? Ip,
    int? AccuracyRadiusKm);
internal sealed record GeoSettings(GeoDatabaseStatus Databases, OriginRequest? Configuration, GeoOrigin? Origin);
internal sealed record GeoSnapshot(GeoOrigin? Origin, GeoResult[] Endpoints);

internal sealed class CaptureGeography(GeoIpDatabase database)
{
    private OriginRequest? configuration;

    public GeoSettings Settings()
    {
        var current = Volatile.Read(ref configuration);
        return new(database.Status, current, ResolveOrigin(current));
    }

    public GeoSettings Reload()
    {
        database.Reload();
        return Settings();
    }

    public GeoResult? Lookup(string? text) => IpClassifier.Parse(text) is { } address ? database.Resolve(address) : null;

    public string? SetOrigin(OriginRequest request)
    {
        switch (request.Mode)
        {
            case "none":
                Volatile.Write(ref configuration, null);
                return null;
            case "manual":
                if (request.Latitude is not (>= -90 and <= 90) || request.Longitude is not (>= -180 and <= 180))
                    return "Enter a latitude from −90 to 90 and a longitude from −180 to 180.";
                var label = request.Label?.Trim();
                if (label?.Length > 80) return "Use an origin label of 80 characters or fewer.";
                Volatile.Write(ref configuration, request with { Label = label, Ip = null });
                return null;
            case "public-ip":
                if (Lookup(request.Ip) is not { Status: "located" } located)
                    return "Enter a public address with coordinates in the local City database.";
                Volatile.Write(ref configuration, new OriginRequest("public-ip", null, null, null, located.Ip));
                return null;
            default:
                return "Choose a supported origin mode.";
        }
    }

    public GeoSnapshot Snapshot(CaptureView view)
    {
        var endpoints = view.Traffic?.RecentFlows.Select(flow => flow.Endpoint.RemoteIp)
            .Distinct(StringComparer.Ordinal).Select(Lookup).OfType<GeoResult>().ToArray() ?? [];
        return new(ResolveOrigin(Volatile.Read(ref configuration)), endpoints);
    }

    private GeoOrigin? ResolveOrigin(OriginRequest? request)
    {
        if (request is { Mode: "manual", Latitude: { } lat, Longitude: { } lng })
            return new("manual", lat, lng, string.IsNullOrEmpty(request.Label) ? "Approximate origin" : request.Label, null, null);
        if (request is { Mode: "public-ip" }
            && Lookup(request.Ip) is { Latitude: { } latitude, Longitude: { } longitude } location)
            return new("public-ip", latitude, longitude, location.City ?? location.Country ?? "Approximate origin",
                location.Ip, location.AccuracyRadiusKm);
        return null;
    }
}
