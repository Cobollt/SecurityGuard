using System.Security.Cryptography;
using System.Text;
using SecurityGuard.ArchiveGuard.Models;

namespace SecurityGuard.ArchiveGuard.Services;

public static class ArchiveGuardDecisionIdentity
{
    public static string Create(
        ArchiveGuardScanResult result)
    {
        ArgumentNullException.ThrowIfNull(
            result);

        var fileIdentity =
            !string.IsNullOrWhiteSpace(
                result.Sha256)
                ? result.Sha256
                : Path.GetFullPath(
                    result.FilePath)
                    .ToUpperInvariant();

        var raw =
            string.Join(
                "|",
                "ARCHIVEGUARD",
                fileIdentity,
                result.Verdict);

        var hash =
            SHA256.HashData(
                Encoding.UTF8.GetBytes(
                    raw));

        return
            $"ARCHIVE:{Convert.ToHexString(hash)}";
    }
}