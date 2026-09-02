using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.ArchiveGuard.Models;

namespace SecurityGuard.ArchiveGuard.Analyzers;

public sealed class ZipStructureAnalyzer
    : IArchiveFileAnalyzer
{
    private readonly IZipSafetyAnalyzer _zipSafetyAnalyzer;

    public ZipStructureAnalyzer(
        IZipSafetyAnalyzer zipSafetyAnalyzer)
    {
        _zipSafetyAnalyzer =
            zipSafetyAnalyzer;
    }

    public async Task<IReadOnlyList<ArchiveScanFinding>> AnalyzeAsync(
        ArchiveFileMetadata metadata,
        CancellationToken cancellationToken = default)
    {
        if (metadata.FileType !=
            DetectedFileType.Zip)
        {
            return [];
        }

        var result =
            await _zipSafetyAnalyzer.AnalyzeAsync(
                metadata.FilePath,
                cancellationToken);

        return result.Findings;
    }
}