using SecurityGuard.ArchiveGuard.Models;

namespace SecurityGuard.ArchiveGuard.Contracts;

public interface IArchiveFileAnalyzer
{
    Task<IReadOnlyList<ArchiveScanFinding>> AnalyzeAsync(
        ArchiveFileMetadata metadata,
        CancellationToken cancellationToken = default);
}