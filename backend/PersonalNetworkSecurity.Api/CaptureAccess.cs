using System.Security.Cryptography;
using System.Text;

internal sealed class CaptureAccess
{
    public const string HubPath = "/api/capture/live";
    public string Code { get; } = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));

    public bool Accepts(HttpContext context)
    {
        var request = context.Request;
        var header = request.Headers.Authorization.ToString();
        var code = header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? header[7..] :
            request.Path == HubPath && context.WebSockets.IsWebSocketRequest
                ? request.Query["access_token"].ToString() : "";
        return code.Length == Code.Length && CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(code), Encoding.UTF8.GetBytes(Code));
    }
}
