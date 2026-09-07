using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;

namespace SecurityGuard.ArchiveGuard.Services;

public sealed class ArchiveGuardWorkflowService
    : IArchiveGuardWorkflowService
{
    private readonly IArchiveGuardScanner _scanner;
    private readonly IDecisionRequestRepository _decisionRepository;
    private readonly IArchiveGuardAuditSink _audit;
    private readonly ArchiveGuardDecisionRequestFactory _decisionFactory;

    public ArchiveGuardWorkflowService(
        IArchiveGuardScanner scanner,
        IDecisionRequestRepository decisionRepository,
        IArchiveGuardAuditSink audit,
        ArchiveGuardDecisionRequestFactory decisionFactory)
    {
        _scanner =
            scanner;

        _decisionRepository =
            decisionRepository;

        _audit =
            audit;

        _decisionFactory =
            decisionFactory;
    }

    public async Task<ArchiveGuardWorkflowResult> ScanAsync(
        string filePath,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            filePath);

        var result =
            await _scanner.ScanAsync(
                new ArchiveScanRequest(
                    filePath),
                cancellationToken);

        await WriteScanAuditAsync(
            result,
            cancellationToken);

        if (result.Verdict ==
            ScanVerdict.Clean)
        {
            return new ArchiveGuardWorkflowResult(
                result,
                null);
        }

        var request =
            _decisionFactory.Create(
                result);

        var pending =
            await _decisionRepository.GetPendingAsync(
                cancellationToken);

        var existing =
            pending.FirstOrDefault(
                item =>
                    string.Equals(
                        item.Identity,
                        request.Identity,
                        StringComparison.Ordinal));

        if (existing is not null)
        {
            return new ArchiveGuardWorkflowResult(
                result,
                existing);
        }

        await _decisionRepository.AddAsync(
            request,
            cancellationToken);

        await _audit.WriteAsync(
            SecurityEventType.ArchiveScan,
            SecuritySeverity.Info,
            "ArchiveGuard decision request created",
            $"DecisionRequestId={request.Id}; File={result.FilePath}; Verdict={result.Verdict}",
            cancellationToken);

        return new ArchiveGuardWorkflowResult(
            result,
            request);
    }

    private Task WriteScanAuditAsync(
        ArchiveGuardScanResult result,
        CancellationToken cancellationToken)
    {
        return _audit.WriteAsync(
            SecurityEventType.ArchiveScan,
            GetSeverity(
                result.Verdict),
            "ArchiveGuard scan completed",
            BuildAuditDetails(
                result),
            cancellationToken);
    }

    private static SecuritySeverity GetSeverity(
        ScanVerdict verdict)
    {
        return verdict switch
        {
            ScanVerdict.Clean =>
                SecuritySeverity.Info,

            ScanVerdict.Unknown =>
                SecuritySeverity.Medium,

            ScanVerdict.Suspicious =>
                SecuritySeverity.High,

            ScanVerdict.Malicious =>
                SecuritySeverity.Critical,

            ScanVerdict.Error =>
                SecuritySeverity.High,

            _ =>
                SecuritySeverity.Info
        };
    }

    private static string BuildAuditDetails(
        ArchiveGuardScanResult result)
    {
        return string.Join(
            Environment.NewLine,
            new[]
            {
                $"File={result.FilePath}",
                $"SHA256={result.Sha256 ?? "Unavailable"}",
                $"Size={result.FileSize?.ToString() ?? "Unknown"}",
                $"DetectedType={result.FileType}",
                $"Verdict={result.Verdict}",
                $"Findings={result.Findings.Count}",
                $"StartedAtUtc={result.StartedAtUtc:O}",
                $"CompletedAtUtc={result.CompletedAtUtc:O}"
            });
    }
}