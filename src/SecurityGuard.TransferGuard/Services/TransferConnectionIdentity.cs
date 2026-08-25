using System.Security.Cryptography;
using System.Text;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Services;

public static class TransferConnectionIdentity
{
    public static string Create(
        NetworkConnectionObservation observation)
    {
        ArgumentNullException.ThrowIfNull(
            observation);

        var process =
            !string.IsNullOrWhiteSpace(
                observation.ApplicationPath)
                ? observation.ApplicationPath
                : observation.Process?.ExecutablePath ??
                  observation.Process?.ProcessName ??
                  string.Empty;

        var source =
            string.Join(
                "\n",
                Normalize(
                    process),
                Normalize(
                    observation.RemoteAddress),
                observation.RemotePort.ToString(),
                observation.Protocol.ToString());

        var hash =
            SHA256.HashData(
                Encoding.UTF8.GetBytes(
                    source));

        return $"NET:{Convert.ToHexString(hash)}";
    }

    private static string Normalize(
        string value)
    {
        return value
            .Trim()
            .ToUpperInvariant();
    }
}