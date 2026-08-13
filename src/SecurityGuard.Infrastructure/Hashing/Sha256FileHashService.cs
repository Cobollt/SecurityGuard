using System.Security.Cryptography;
using SecurityGuard.Core.Contracts;

namespace SecurityGuard.Infrastructure.Hashing;

public sealed class Sha256FileHashService
    : IFileHashService
{
    public async Task<string> ComputeSha256Async(
        string filePath,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException(
                "File was not found.",
                filePath);
        }

        await using var stream =
            new FileStream(
                filePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                131072,
                FileOptions.Asynchronous |
                FileOptions.SequentialScan);

        using var sha256 =
            SHA256.Create();

        var hash =
            await sha256.ComputeHashAsync(
                stream,
                cancellationToken);

        return Convert
            .ToHexString(hash)
            .ToUpperInvariant();
    }
}