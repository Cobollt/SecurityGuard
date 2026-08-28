using System.Security.Cryptography;
using System.Text;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Services;

public static class TransferFileDecisionIdentity
{
    public static string Create(
        FileTransferCandidate candidate)
    {
        ArgumentNullException.ThrowIfNull(
            candidate);

        var fileIdentity =
            !string.IsNullOrWhiteSpace(
                candidate.Sha256)
                ? $"HASH:{candidate.Sha256}"
                : $"PATH:{Normalize(candidate.FilePath)}";

        var processPath =
            candidate.Connection.Process?.ExecutablePath ??
            candidate.Connection.ApplicationPath ??
            candidate.Connection.Process?.ProcessName ??
            string.Empty;

        var source =
            string.Join(
                "\n",
                fileIdentity,
                Normalize(
                    processPath),
                Normalize(
                    candidate.Connection.RemoteAddress),
                candidate.Connection.RemotePort.ToString(),
                candidate.Connection.Protocol.ToString());

        var hash =
            SHA256.HashData(
                Encoding.UTF8.GetBytes(
                    source));

        return $"FILEXFER:{Convert.ToHexString(hash)}";
    }

    private static string Normalize(
        string value)
    {
        return value
            .Trim()
            .ToUpperInvariant();
    }
}