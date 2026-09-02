using System.IO.Compression;
using SecurityGuard.ArchiveGuard.Configuration;
using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.ArchiveGuard.Services;

public sealed class ZipSafetyAnalyzer
    : IZipSafetyAnalyzer
{
    private static readonly HashSet<string> NestedContainerExtensions =
        new(
            StringComparer.OrdinalIgnoreCase)
        {
            ".zip",
            ".7z",
            ".rar",
            ".gz",
            ".gzip",
            ".tgz",
            ".tar",
            ".docx",
            ".docm",
            ".xlsx",
            ".xlsm",
            ".pptx",
            ".pptm",
            ".jar",
            ".apk",
            ".epub",
            ".odt",
            ".ods",
            ".odp",
            ".nupkg",
            ".vsix"
        };

    private readonly ArchiveGuardOptions _options;
    private readonly ZipEntryPathInspector _pathInspector;

    public ZipSafetyAnalyzer(
        ArchiveGuardOptions options,
        ZipEntryPathInspector pathInspector)
    {
        _options =
            options;

        _pathInspector =
            pathInspector;
    }

    public Task<ZipSafetyAssessment> AnalyzeAsync(
        string filePath,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            filePath);

        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            using var stream =
                new FileStream(
                    filePath,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read,
                    bufferSize:
                        8192,
                    FileOptions.SequentialScan);

            using var archive =
                new ZipArchive(
                    stream,
                    ZipArchiveMode.Read,
                    leaveOpen:
                        false);

            return Task.FromResult(
                AnalyzeArchive(
                    archive,
                    cancellationToken));
        }
        catch (InvalidDataException exception)
        {
            return Task.FromResult(
                CreateInvalidStructureAssessment(
                    exception));
        }
    }

    private ZipSafetyAssessment AnalyzeArchive(
        ZipArchive archive,
        CancellationToken cancellationToken)
    {
        var entries =
            new List<ZipEntrySafetyInfo>();

        var findings =
            new List<ArchiveScanFinding>();

        var seenPaths =
            new HashSet<string>(
                StringComparer.OrdinalIgnoreCase);

        var entryCount =
            0;

        long totalCompressed =
            0;

        long totalExpanded =
            0;

        var entryLimitReported =
            false;

        var totalSizeReported =
            false;

        var entriesTruncated =
            false;

        var findingsTruncated =
            false;

        foreach (var entry in
                 archive.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();

            entryCount++;

            if (entryCount >
                    _options.MaxZipEntryCount &&
                !entryLimitReported)
            {
                AddFinding(
                    findings,
                    new ArchiveScanFinding(
                        ArchiveFindingKind.ZipEntryCountExceeded,
                        ScanVerdict.Suspicious,
                        SecuritySeverity.High,
                        "ZIP entry count limit exceeded",
                        $"Entries={entryCount}; Limit={_options.MaxZipEntryCount}"),
                    ref findingsTruncated);

                entryLimitReported =
                    true;
            }

            var expandedLength =
                entry.Length;

            var compressedLength =
                entry.CompressedLength;

            totalExpanded =
                SaturatingAdd(
                    totalExpanded,
                    expandedLength);

            totalCompressed =
                SaturatingAdd(
                    totalCompressed,
                    compressedLength);

            if (totalExpanded >
                    _options.MaxZipExpandedBytes &&
                !totalSizeReported)
            {
                AddFinding(
                    findings,
                    new ArchiveScanFinding(
                        ArchiveFindingKind.ZipExpandedSizeExceeded,
                        ScanVerdict.Suspicious,
                        SecuritySeverity.Critical,
                        "ZIP expanded size limit exceeded",
                        $"ExpandedBytes={totalExpanded}; Limit={_options.MaxZipExpandedBytes}"),
                    ref findingsTruncated);

                totalSizeReported =
                    true;
            }

            var directory =
                string.IsNullOrEmpty(
                    entry.Name);

            var compressionRatio =
                CalculateCompressionRatio(
                    expandedLength,
                    compressedLength);

            if (!directory &&
                expandedLength >
                _options.MaxZipEntryBytes)
            {
                AddFinding(
                    findings,
                    new ArchiveScanFinding(
                        ArchiveFindingKind.ZipEntrySizeExceeded,
                        ScanVerdict.Suspicious,
                        SecuritySeverity.High,
                        "ZIP entry size limit exceeded",
                        $"Entry={entry.FullName}; ExpandedBytes={expandedLength}; Limit={_options.MaxZipEntryBytes}"),
                    ref findingsTruncated);
            }

            if (!directory &&
                compressionRatio >
                _options.MaxZipCompressionRatio)
            {
                AddFinding(
                    findings,
                    new ArchiveScanFinding(
                        ArchiveFindingKind.ZipCompressionRatioExceeded,
                        ScanVerdict.Suspicious,
                        SecuritySeverity.Critical,
                        "Suspicious ZIP compression ratio",
                        $"Entry={entry.FullName}; Ratio={compressionRatio:F2}; Limit={_options.MaxZipCompressionRatio:F2}"),
                    ref findingsTruncated);
            }

            var path =
                _pathInspector.Inspect(
                    entry.FullName);

            if (path.IsAbsolute)
            {
                AddFinding(
                    findings,
                    new ArchiveScanFinding(
                        ArchiveFindingKind.ZipAbsolutePath,
                        ScanVerdict.Suspicious,
                        SecuritySeverity.High,
                        "ZIP entry contains an absolute path",
                        $"Entry={entry.FullName}"),
                    ref findingsTruncated);
            }

            if (path.HasTraversal)
            {
                AddFinding(
                    findings,
                    new ArchiveScanFinding(
                        ArchiveFindingKind.ZipPathTraversal,
                        ScanVerdict.Suspicious,
                        SecuritySeverity.Critical,
                        "ZIP entry contains path traversal",
                        $"Entry={entry.FullName}"),
                    ref findingsTruncated);
            }

            if (path.HasAlternateDataStream)
            {
                AddFinding(
                    findings,
                    new ArchiveScanFinding(
                        ArchiveFindingKind.ZipAlternateDataStreamPath,
                        ScanVerdict.Suspicious,
                        SecuritySeverity.High,
                        "ZIP entry contains a Windows alternate data stream path",
                        $"Entry={entry.FullName}"),
                    ref findingsTruncated);
            }

            if (!string.IsNullOrWhiteSpace(
                    path.NormalizedPath) &&
                !seenPaths.Add(
                    path.NormalizedPath))
            {
                AddFinding(
                    findings,
                    new ArchiveScanFinding(
                        ArchiveFindingKind.ZipDuplicatePath,
                        ScanVerdict.Suspicious,
                        SecuritySeverity.Medium,
                        "ZIP contains duplicate normalized paths",
                        $"Entry={entry.FullName}; Normalized={path.NormalizedPath}"),
                    ref findingsTruncated);
            }

            if (entry.IsEncrypted)
            {
                AddFinding(
                    findings,
                    new ArchiveScanFinding(
                        ArchiveFindingKind.ZipEncryptedEntry,
                        ScanVerdict.Unknown,
                        SecuritySeverity.Medium,
                        "ZIP entry is encrypted",
                        $"Entry={entry.FullName}"),
                    ref findingsTruncated);
            }

            var nestedContainer =
                IsNestedContainerCandidate(
                    entry.Name);

            if (entries.Count <
                _options.MaxRecordedZipEntries)
            {
                entries.Add(
                    new ZipEntrySafetyInfo(
                        entry.FullName,
                        path.NormalizedPath,
                        compressedLength,
                        expandedLength,
                        compressionRatio,
                        directory,
                        entry.IsEncrypted,
                        nestedContainer));
            }
            else
            {
                entriesTruncated =
                    true;
            }
        }

        return new ZipSafetyAssessment(
            true,
            entryCount,
            totalCompressed,
            totalExpanded,
            entries,
            findings,
            entriesTruncated,
            findingsTruncated);
    }

    private void AddFinding(
        ICollection<ArchiveScanFinding> findings,
        ArchiveScanFinding finding,
        ref bool truncated)
    {
        if (findings.Count >=
            _options.MaxArchiveFindings)
        {
            truncated =
                true;

            return;
        }

        findings.Add(
            finding);
    }

    private static double CalculateCompressionRatio(
        long expandedLength,
        long compressedLength)
    {
        if (expandedLength <= 0)
        {
            return 1.0;
        }

        if (compressedLength <= 0)
        {
            return double.PositiveInfinity;
        }

        return (double)expandedLength /
               compressedLength;
    }

    private static long SaturatingAdd(
        long current,
        long value)
    {
        if (value <= 0)
        {
            return current;
        }

        if (current >
            long.MaxValue -
            value)
        {
            return long.MaxValue;
        }

        return current +
               value;
    }

    private static bool IsNestedContainerCandidate(
        string fileName)
    {
        if (string.IsNullOrWhiteSpace(
                fileName))
        {
            return false;
        }

        return NestedContainerExtensions.Contains(
            Path.GetExtension(
                fileName));
    }

    private static ZipSafetyAssessment CreateInvalidStructureAssessment(
        InvalidDataException exception)
    {
        return new ZipSafetyAssessment(
            false,
            0,
            0,
            0,
            [],
            [
                new ArchiveScanFinding(
                    ArchiveFindingKind.ZipInvalidStructure,
                    ScanVerdict.Error,
                    SecuritySeverity.High,
                    "Invalid ZIP structure",
                    exception.Message)
            ],
            false,
            false);
    }
}