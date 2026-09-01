using System.Security.Cryptography;
using System.Text;
using SecurityGuard.TransferGuard.Enums;

namespace SecurityGuard.TransferGuard.Services;

public static class TransferTemporaryBlockIdentity
{
    public static Guid Create(
        Guid sourceSecurityRuleId,
        string processPath,
        string remoteAddress,
        int remotePort,
        TransferProtocol protocol)
    {
        if (sourceSecurityRuleId ==
            Guid.Empty)
        {
            throw new ArgumentException(
                "Source security rule ID is required.",
                nameof(
                    sourceSecurityRuleId));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(
            processPath);

        ArgumentException.ThrowIfNullOrWhiteSpace(
            remoteAddress);

        var source =
            string.Join(
                "\n",
                sourceSecurityRuleId.ToString("D"),
                Normalize(
                    processPath),
                Normalize(
                    remoteAddress),
                remotePort.ToString(),
                protocol.ToString());

        var hash =
            SHA256.HashData(
                Encoding.UTF8.GetBytes(
                    source));

        return new Guid(
            hash.AsSpan(
                0,
                16));
    }

    private static string Normalize(
        string value)
    {
        return value
            .Trim()
            .ToUpperInvariant();
    }
}