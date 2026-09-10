using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.ArchiveGuard.Exceptions;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.ArchiveGuard.Services;

public sealed class ArchiveGuardScanner
    : IArchiveGuardScanner
{
    private readonly IArchiveFileMetadataService _metadataService;
    private readonly IReadOnlyList<IArchiveFileAnalyzer> _analyzers;
    private readonly IReadOnlyList<IArchiveSeekableContentAnalyzer> _seekableAnalyzers;
    private readonly IArchiveRecursiveScanner _recursiveScanner;
    private readonly IArchiveGuardFileConsistencyService _consistencyService;
    private readonly IArchiveGuardScanCache _scanCache;

    public ArchiveGuardScanner(
        IArchiveFileMetadataService metadataService,
        IEnumerable<IArchiveFileAnalyzer> analyzers,
        IEnumerable<IArchiveSeekableContentAnalyzer> seekableAnalyzers,
        IArchiveRecursiveScanner recursiveScanner,
        IArchiveGuardFileConsistencyService consistencyService,
        IArchiveGuardScanCache scanCache)
    {
        _metadataService =
            metadataService;

        _analyzers =
            analyzers.ToArray();

        _seekableAnalyzers =
            seekableAnalyzers.ToArray();

        _recursiveScanner =
            recursiveScanner;

        _consistencyService =
            consistencyService;

        _scanCache =
            scanCache;
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
        catch (ArchiveFileChangedException exception)
        {
            return CreateChangedResult(
                exception.FilePath,
                startedAt);
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
                DateTimeOffset.UtcNow,
                DetectedFileType.Unknown);
        }

        if (_scanCache.TryGet(
                metadata,
                out var cached))
        {
            if (!await _consistencyService.IsConsistentAsync(
                    metadata,
                    cancellationToken))
            {
                return CreateChangedResult(
                    metadata.FilePath,
                    startedAt);
            }

            return cached with
            {
                Id =
                    Guid.NewGuid(),

                FilePath =
                    metadata.FilePath,

                Sha256 =
                    metadata.Sha256,

                FileSize =
                    metadata.Length,

                Findings =
                    cached.Findings.ToArray(),

                StartedAtUtc =
                    startedAt,

                CompletedAtUtc =
                    DateTimeOffset.UtcNow
            };
        }

        var findings =
            new List<ArchiveScanFinding>();

        foreach (var analyzer in
                 _analyzers)
        {
            try
            {
                var analyzerFindings =
                    await analyzer.AnalyzeAsync(
                        metadata,
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
                        $"Analyzer failed: {analyzer.GetType().Name}",
                        exception.Message));
            }
        }

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

        if (!await _consistencyService.IsConsistentAsync(
                metadata,
                cancellationToken))
        {
            return CreateChangedResult(
                metadata.FilePath,
                startedAt);
        }

        var verdict =
            SelectHigherVerdict(
                CalculateVerdict(
                    findings),
                recursiveVerdict);

        var result =
            new ArchiveGuardScanResult(
                Guid.NewGuid(),
                metadata.FilePath,
                metadata.Sha256,
                metadata.Length,
                verdict,
                findings,
                startedAt,
                DateTimeOffset.UtcNow,
                metadata.FileType);

        _scanCache.Store(
            metadata,
            result);

        return result;
    }

    private static ArchiveGuardScanResult CreateChangedResult(
        string filePath,
        DateTimeOffset startedAt)
    {
        return new ArchiveGuardScanResult(
            Guid.NewGuid(),
            filePath,
            null,
            null,
            ScanVerdict.Unknown,
            [
                new ArchiveScanFinding(
                    ArchiveFindingKind.FileChangedDuringScan,
                    ScanVerdict.Unknown,
                    SecuritySeverity.High,
                    "File changed during scan",
                    "ArchiveGuard discarded the scan because the file contents changed while analysis was in progress.")
            ],
            startedAt,
            DateTimeOffset.UtcNow,
            DetectedFileType.Unknown);
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