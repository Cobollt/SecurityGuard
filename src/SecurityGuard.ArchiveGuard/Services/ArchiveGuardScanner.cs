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

    public ArchiveGuardScanner(
        IArchiveFileMetadataService metadataService,
        IEnumerable<IArchiveFileAnalyzer> analyzers)
    {
        _metadataService =
            metadataService;

        _analyzers =
            analyzers.ToArray();
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
                 _analyzers)
        {
            cancellationToken.ThrowIfCancellationRequested();

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
}