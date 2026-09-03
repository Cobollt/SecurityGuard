using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.ArchiveGuard.Models;

namespace SecurityGuard.ArchiveGuard.Analyzers;

public sealed class PeSeekableContentAnalyzer
    : IArchiveSeekableContentAnalyzer
{
    private readonly IPeStaticAnalyzer _analyzer;

    public PeSeekableContentAnalyzer(
        IPeStaticAnalyzer analyzer)
    {
        _analyzer =
            analyzer;
    }

    public bool Supports(
        DetectedFileType fileType)
    {
        return fileType ==
               DetectedFileType.Pe;
    }

    public async Task<IReadOnlyList<ArchiveScanFinding>> AnalyzeAsync(
        ArchiveFileMetadata metadata,
        Stream stream,
        CancellationToken cancellationToken = default)
    {
        var result =
            await _analyzer.AnalyzeAsync(
                stream,
                metadata.FilePath,
                cancellationToken);

        return result.Findings;
    }
}