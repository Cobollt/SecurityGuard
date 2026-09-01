using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.ArchiveGuard.Analyzers;

public sealed class DoubleExtensionAnalyzer
    : IArchiveFileAnalyzer
{
    private static readonly HashSet<string> ExecutableExtensions =
        new(
            StringComparer.OrdinalIgnoreCase)
        {
            ".exe",
            ".scr",
            ".com",
            ".msi",
            ".bat",
            ".cmd",
            ".ps1",
            ".vbs",
            ".js",
            ".jse",
            ".wsf"
        };

    private static readonly HashSet<string> DecoyExtensions =
        new(
            StringComparer.OrdinalIgnoreCase)
        {
            ".pdf",
            ".doc",
            ".docx",
            ".xls",
            ".xlsx",
            ".ppt",
            ".pptx",
            ".txt",
            ".jpg",
            ".jpeg",
            ".png",
            ".zip",
            ".rar",
            ".7z"
        };

    public Task<IReadOnlyList<ArchiveScanFinding>> AnalyzeAsync(
        ArchiveFileMetadata metadata,
        CancellationToken cancellationToken = default)
    {
        var finalExtension =
            metadata.Extension;

        if (!ExecutableExtensions.Contains(
                finalExtension))
        {
            return Task.FromResult<
                IReadOnlyList<ArchiveScanFinding>>(
                []);
        }

        var withoutFinalExtension =
            Path.GetFileNameWithoutExtension(
                metadata.FileName);

        var previousExtension =
            Path.GetExtension(
                withoutFinalExtension);

        if (!DecoyExtensions.Contains(
                previousExtension))
        {
            return Task.FromResult<
                IReadOnlyList<ArchiveScanFinding>>(
                []);
        }

        IReadOnlyList<ArchiveScanFinding> findings =
        [
            new ArchiveScanFinding(
                ArchiveFindingKind.DoubleExtension,
                ScanVerdict.Suspicious,
                SecuritySeverity.High,
                "Suspicious double extension",
                $"FileName={metadata.FileName}")
        ];

        return Task.FromResult(
            findings);
    }
}