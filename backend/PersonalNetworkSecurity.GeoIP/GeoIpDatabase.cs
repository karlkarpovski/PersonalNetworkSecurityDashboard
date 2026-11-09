using System.Net;
using MaxMind.Db;
using MaxMind.GeoIP2;

namespace PersonalNetworkSecurity.GeoIP;

public sealed record GeoResult(string Ip, string AddressKind, string Status, string? Country = null,
    string? CountryCode = null, string? Region = null, string? City = null, double? Latitude = null,
    double? Longitude = null, int? AccuracyRadiusKm = null, long? Asn = null, string? Organization = null);

public sealed record GeoFileStatus(string FileName, string State, string? DatabaseType, string? Warning);
public sealed record GeoDatabaseStatus(string Directory, GeoFileStatus City, GeoFileStatus Asn);

public sealed class GeoIpDatabase : IDisposable
{
    private const int CacheCapacity = 4096;
    private const long MaximumFileBytes = 256L * 1024 * 1024;
    private readonly object gate = new();
    private readonly object reloadGate = new();
    private readonly Dictionary<IPAddress, GeoResult> cache = new();
    private readonly Slot city = new("GeoLite2-City.mmdb", "City");
    private readonly Slot asn = new("GeoLite2-ASN.mmdb", "ASN");
    private readonly string directory;
    private bool disposed;

    public GeoIpDatabase(string directory)
    {
        this.directory = Path.GetFullPath(directory);
        Reload();
    }

    public GeoDatabaseStatus Status
    {
        get { lock (gate) return new(directory, city.Status, asn.Status); }
    }

    public GeoDatabaseStatus Reload()
    {
        lock (reloadGate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            var cityReplacement = Load(city);
            var asnReplacement = Load(asn);
            lock (gate)
            {
                city.Replace(cityReplacement);
                asn.Replace(asnReplacement);
                cache.Clear();
                return new(directory, city.Status, asn.Status);
            }
        }
    }

    public GeoResult Resolve(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        var kind = IpClassifier.Classify(address);
        if (kind != "public") return new(address.ToString(), kind, "non-public");

        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (cache.TryGetValue(address, out var existing)) return existing;
            var result = Lookup(address);
            if (cache.Count == CacheCapacity) cache.Clear();
            cache[address] = result;
            return result;
        }
    }

    private GeoResult Lookup(IPAddress address)
    {
        MaxMind.GeoIP2.Responses.CityResponse? location = null;
        MaxMind.GeoIP2.Responses.AsnResponse? network = null;
        var failed = false;
        try { city.Reader?.TryCity(address, out location); }
        catch (Exception ex) when (IsDatabaseError(ex)) { failed = true; }
        try { asn.Reader?.TryAsn(address, out network); }
        catch (Exception ex) when (IsDatabaseError(ex)) { failed = true; }

        var latitude = location?.Location.Latitude;
        var longitude = location?.Location.Longitude;
        var hasPoint = latitude is >= -90 and <= 90 && longitude is >= -180 and <= 180;
        var status = hasPoint ? "located" : location is not null || network is not null ? "partial" :
            failed ? "lookup-error" : city.Reader is null && asn.Reader is null ? "database-unavailable" : "not-found";
        return new(address.ToString(), "public", status, location?.Country.Name, location?.Country.IsoCode,
            location?.MostSpecificSubdivision.Name, location?.City.Name, hasPoint ? latitude : null,
            hasPoint ? longitude : null, location?.Location.AccuracyRadius, network?.AutonomousSystemNumber,
            network?.AutonomousSystemOrganization);
    }

    private (DatabaseReader? Reader, string? Warning, bool Missing) Load(Slot slot)
    {
        try
        {
            using var stream = new FileStream(Path.Combine(directory, slot.FileName), FileMode.Open, FileAccess.Read,
                FileShare.Read | FileShare.Delete);
            if (stream.Length is <= 0 or > MaximumFileBytes)
                return (null, "The file is empty or larger than 256 MB.", false);
            var reader = new DatabaseReader(stream);
            if (reader.Metadata.DatabaseType != $"GeoLite2-{slot.Kind}" && reader.Metadata.DatabaseType != $"GeoIP2-{slot.Kind}")
            {
                reader.Dispose();
                return (null, $"The file is not a MaxMind {slot.Kind} database.", false);
            }
            return (reader, null, false);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return (null, "The database file is missing.", true);
        }
        catch (Exception ex) when (IsDatabaseError(ex) || ex is UnauthorizedAccessException)
        {
            return (null, "The file is unreadable or is not a valid MaxMind database.", false);
        }
    }

    private static bool IsDatabaseError(Exception error) =>
        error is InvalidDatabaseException or IOException or ArgumentException or InvalidOperationException
            or NotSupportedException or OverflowException or IndexOutOfRangeException;

    public void Dispose()
    {
        lock (reloadGate)
        lock (gate)
        {
            if (disposed) return;
            disposed = true;
            city.Reader?.Dispose();
            asn.Reader?.Dispose();
            cache.Clear();
        }
    }

    private sealed class Slot(string fileName, string kind)
    {
        public string FileName { get; } = fileName;
        public string Kind { get; } = kind;
        public DatabaseReader? Reader { get; private set; }
        public GeoFileStatus Status { get; private set; } = new(fileName, "missing", null, null);

        public void Replace((DatabaseReader? Reader, string? Warning, bool Missing) replacement)
        {
            if (replacement.Reader is { } next)
            {
                Reader?.Dispose();
                Reader = next;
            }
            Status = new(FileName, Reader is not null ? "ready" : replacement.Missing ? "missing" : "invalid",
                Reader?.Metadata.DatabaseType, replacement.Warning);
        }
    }
}
