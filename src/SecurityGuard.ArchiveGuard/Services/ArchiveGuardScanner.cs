using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.ArchiveGuard.Services;

public sealed class ArchiveGuardScanner
    : IArchiveGuardScanner
{
    private readonly IArchiveFileMetadataService _metadataService;
    private readonly IReadOnlyList<IArchiveFileAnalyzer> _analyzers;
    private readonly IArchiveRecursiveScanner _recursiveScanner;
    private readonly IReadOnlyList<IArchiveSeekableContentAnalyzer> _seekableAnalyzers;

    public ArchiveGuardScanner(
        IArchiveFileMetadataService metadataService,
        IEnumerable<IArchiveFileAnalyzer> analyzers,
        IEnumerable<IArchiveSeekableContentAnalyzer> seekableAnalyzers,
        IArchiveRecursiveScanner recursiveScanner)
    {
        _metadataService =
            metadataService;

        _analyzers =
            analyzers.ToArray();

        _seekableAnalyzers =
            seekableAnalyzers.ToArray();

        _recursiveScanner =
            recursiveScanner;
    }

    public async Task<ArchiveGuardScanResult> ScanAsync(
        ArchiveScanRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            request);

        var startedAt =
            DateTimeOffset.UtcNow;

        ArchiveFileMetadata metadata;

        try
        {
            metadata =
                await _metadataService.LoadAsync(
                    request.FilePath,
                    cancellationToken);
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            return new ArchiveGuardScanResult(
                Guid.NewGuid(),
                request.FilePath,
                null,
                null,
                ScanVerdict.Error,
                [
                    new ArchiveScanFinding(
                        ArchiveFindingKind.FileAccessFailure,
                        ScanVerdict.Error,
                        SecuritySeverity.High,
                        "Unable to inspect file",
                        exception.Message)
                ],
                startedAt,
                DateTimeOffset.UtcNow);
        }

        var findings =
            new List<ArchiveScanFinding>();

        foreach (var analyzer in
                _seekableAnalyzers)
        {
            if (!analyzer.Supports(
                    metadata.FileType))
            {
                continue;
            }

            try
            {
                await using var stream =
                    new FileStream(
                        metadata.FilePath,
                        FileMode.Open,
                        FileAccess.Read,
                        FileShare.Read,
                        bufferSize:
                            64 * 1024,
                        FileOptions.Asynchronous |
                        FileOptions.SequentialScan);

                var analyzerFindings =
                    await analyzer.AnalyzeAsync(
                        metadata,
                        stream,
                        metadata.FilePath,
                        cancellationToken);

                findings.AddRange(
                    analyzerFindings);
            }
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                findings.Add(
                    new ArchiveScanFinding(
                        ArchiveFindingKind.AnalyzerFailure,
                        ScanVerdict.Error,
                        SecuritySeverity.High,
                        $"Seekable analyzer failed: {analyzer.GetType().Name}",
                        exception.Message));
            }
        }

        var recursiveVerdict =
            ScanVerdict.Clean;

        if (_recursiveScanner.Supports(
            metadata.FileType))
        {
            try
            {
                var recursive =
                    await _recursiveScanner.ScanAsync(
                        metadata.FilePath,
                        metadata.FileType,
                        cancellationToken);

                findings.AddRange(
                    recursive.Findings);

                recursiveVerdict =
                    recursive.Verdict;
            }
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                findings.Add(
                    new ArchiveScanFinding(
                        ArchiveFindingKind.AnalyzerFailure,
                        ScanVerdict.Error,
                        SecuritySeverity.High,
                        "Recursive archive scanner failed",
                        exception.Message));

                recursiveVerdict =
                    ScanVerdict.Error;
            }
        }

        var verdict =
            SelectHigherVerdict(
                CalculateVerdict(
                    findings),
                recursiveVerdict);

        var verdict =
            CalculateVerdict(
                findings);

        return new ArchiveGuardScanResult(
            Guid.NewGuid(),
            metadata.FilePath,
            metadata.Sha256,
            metadata.Length,
            verdict,
            findings,
            startedAt,
            DateTimeOffset.UtcNow,
            metadata.FileType);
    }

    private static ScanVerdict CalculateVerdict(
        IReadOnlyCollection<ArchiveScanFinding> findings)
    {
        if (findings.Any(
                finding =>
                    finding.Verdict ==
                    ScanVerdict.Malicious))
        {
            return ScanVerdict.Malicious;
        }

        if (findings.Any(
                finding =>
                    finding.Verdict ==
                    ScanVerdict.Error))
        {
            return ScanVerdict.Error;
        }

        if (findings.Any(
                finding =>
                    finding.Verdict ==
                    ScanVerdict.Suspicious))
        {
            return ScanVerdict.Suspicious;
        }

        if (findings.Any(
                finding =>
                    finding.Verdict ==
                    ScanVerdict.Unknown))
        {
            return ScanVerdict.Unknown;
        }

        return ScanVerdict.Clean;
    }

    private static ScanVerdict SelectHigherVerdict(
        ScanVerdict first,
        ScanVerdict second)
    {
        return GetVerdictRank(
                second) >
            GetVerdictRank(
                first)
            ? second
            : first;
    }

    private static int GetVerdictRank(
        ScanVerdict verdict)
    {
        return verdict switch
        {
            ScanVerdict.Malicious =>
                4,

            ScanVerdict.Error =>
                3,

            ScanVerdict.Suspicious =>
                2,

            ScanVerdict.Unknown =>
                1,

            _ =>
                0
        };
    }
}