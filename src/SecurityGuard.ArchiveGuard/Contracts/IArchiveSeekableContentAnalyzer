using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.ArchiveGuard.Models;

namespace SecurityGuard.ArchiveGuard.Contracts;

public interface IArchiveSeekableContentAnalyzer
{
    bool Supports(
        DetectedFileType fileType);

    Task<IReadOnlyList<ArchiveScanFinding>> AnalyzeAsync(
        ArchiveFileMetadata metadata,
        Stream stream,
        string? physicalFilePath,
        CancellationToken cancellationToken = default);
}