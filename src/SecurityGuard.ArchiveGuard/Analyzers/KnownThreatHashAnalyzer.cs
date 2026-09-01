using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.ArchiveGuard.Analyzers;

public sealed class KnownThreatHashAnalyzer
    : IArchiveFileAnalyzer
{
    private readonly IKnownThreatHashStore _hashStore;

    public KnownThreatHashAnalyzer(
        IKnownThreatHashStore hashStore)
    {
        _hashStore =
            hashStore;
    }

    public async Task<IReadOnlyList<ArchiveScanFinding>> AnalyzeAsync(
        ArchiveFileMetadata metadata,
        CancellationToken cancellationToken = default)
    {
        var malicious =
            await _hashStore.IsMaliciousAsync(
                metadata.Sha256,
                cancellationToken);

        if (!malicious)
        {
            return [];
        }

        return
        [
            new ArchiveScanFinding(
                ArchiveFindingKind.KnownMaliciousHash,
                ScanVerdict.Malicious,
                SecuritySeverity.Critical,
                "Known malicious SHA-256",
                $"SHA256={metadata.Sha256}")
        ];
    }
}