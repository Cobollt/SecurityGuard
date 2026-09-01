using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.ArchiveGuard.Analyzers;

public sealed class ExecutableContentMismatchAnalyzer
    : IArchiveFileAnalyzer
{
    private static readonly HashSet<string> PeExtensions =
        new(
            StringComparer.OrdinalIgnoreCase)
        {
            ".exe",
            ".dll",
            ".sys",
            ".scr",
            ".cpl",
            ".ocx",
            ".drv"
        };

    public Task<IReadOnlyList<ArchiveScanFinding>> AnalyzeAsync(
        ArchiveFileMetadata metadata,
        CancellationToken cancellationToken = default)
    {
        if (!HasDosHeader(
                metadata.Header))
        {
            return Task.FromResult<
                IReadOnlyList<ArchiveScanFinding>>(
                []);
        }

        if (PeExtensions.Contains(
                metadata.Extension))
        {
            return Task.FromResult<
                IReadOnlyList<ArchiveScanFinding>>(
                []);
        }

        IReadOnlyList<ArchiveScanFinding> findings =
        [
            new ArchiveScanFinding(
                ArchiveFindingKind.ExecutableContentMismatch,
                ScanVerdict.Suspicious,
                SecuritySeverity.High,
                "Executable content does not match file extension",
                $"FileName={metadata.FileName}; Extension={metadata.Extension}")
        ];

        return Task.FromResult(
            findings);
    }

    private static bool HasDosHeader(
        byte[] header)
    {
        return header.Length >= 2 &&
               header[0] == 0x4D &&
               header[1] == 0x5A;
    }
}