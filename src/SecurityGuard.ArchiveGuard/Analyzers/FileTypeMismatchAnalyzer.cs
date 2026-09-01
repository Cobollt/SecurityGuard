using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.ArchiveGuard.Analyzers;

public sealed class FileTypeMismatchAnalyzer
    : IArchiveFileAnalyzer
{
    private readonly IFileTypeCompatibilityService _compatibilityService;

    public FileTypeMismatchAnalyzer(
        IFileTypeCompatibilityService compatibilityService)
    {
        _compatibilityService =
            compatibilityService;
    }

    public Task<IReadOnlyList<ArchiveScanFinding>> AnalyzeAsync(
        ArchiveFileMetadata metadata,
        CancellationToken cancellationToken = default)
    {
        if (metadata.FileType ==
            DetectedFileType.Unknown)
        {
            return Task.FromResult<
                IReadOnlyList<ArchiveScanFinding>>(
                []);
        }

        if (_compatibilityService.IsCompatible(
                metadata.FileType,
                metadata.Extension))
        {
            return Task.FromResult<
                IReadOnlyList<ArchiveScanFinding>>(
                []);
        }

        var kind =
            metadata.FileType ==
            DetectedFileType.Pe
                ? ArchiveFindingKind.ExecutableContentMismatch
                : ArchiveFindingKind.FileTypeMismatch;

        var severity =
            metadata.FileType ==
            DetectedFileType.Pe
                ? SecuritySeverity.High
                : SecuritySeverity.Medium;

        IReadOnlyList<ArchiveScanFinding> findings =
        [
            new ArchiveScanFinding(
                kind,
                ScanVerdict.Suspicious,
                severity,
                "File content does not match extension",
                $"FileName={metadata.FileName}; Extension={metadata.Extension}; DetectedType={metadata.FileType}")
        ];

        return Task.FromResult(
            findings);
    }
}