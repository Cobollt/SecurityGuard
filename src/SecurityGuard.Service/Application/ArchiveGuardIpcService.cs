using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Ipc.ArchiveGuard;

namespace SecurityGuard.Service.Application;

public sealed class ArchiveGuardIpcService
    : IArchiveGuardIpcService
{
    private readonly IArchiveGuardWorkflowService _workflowService;
    private readonly IScanResultRepository _scanResultRepository;

    public ArchiveGuardIpcService(
        IArchiveGuardWorkflowService workflowService,
        IScanResultRepository scanResultRepository)
    {
        _workflowService =
            workflowService;

        _scanResultRepository =
            scanResultRepository;
    }

    public async Task<ArchiveGuardScanIpcDto> ScanAsync(
        ArchiveGuardScanIpcRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            request);

        ArgumentException.ThrowIfNullOrWhiteSpace(
            request.FilePath);

        var filePath =
            Path.GetFullPath(
                request.FilePath);

        if (!File.Exists(
                filePath))
        {
            throw new FileNotFoundException(
                "File was not found.",
                filePath);
        }

        var result =
            await _workflowService.ScanAsync(
                filePath,
                cancellationToken);

        return Map(
            result);
    }

    public async Task<IReadOnlyList<ArchiveGuardRecentScanIpcDto>> GetRecentAsync(
        ArchiveGuardRecentScansIpcRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            request);

        var limit =
            Math.Clamp(
                request.Limit,
                1,
                200);

        var queryLimit =
            Math.Min(
                500,
                Math.Max(
                    limit * 4,
                    50));

        var scans =
            await _scanResultRepository.GetRecentAsync(
                queryLimit,
                cancellationToken);

        return scans
            .Where(
                scan =>
                    scan.Module ==
                    SecurityModuleKind.ArchiveGuard)
            .Take(
                limit)
            .Select(
                scan =>
                    new ArchiveGuardRecentScanIpcDto(
                        scan.Id,
                        scan.FilePath,
                        scan.Sha256,
                        scan.FileSize,
                        scan.Verdict,
                        scan.Summary,
                        scan.CompletedAtUtc))
            .ToArray();
    }

    private static ArchiveGuardScanIpcDto Map(
        ArchiveGuardWorkflowResult workflow)
    {
        var scan =
            workflow.ScanResult;

        var actions =
            workflow.DecisionRequest?.AvailableActions ??
            [];

        return new ArchiveGuardScanIpcDto(
            scan.Id,
            scan.FilePath,
            scan.Sha256,
            scan.FileSize,
            scan.Verdict,
            scan.FileType.ToString(),
            scan.Findings
                .Select(
                    finding =>
                        new ArchiveGuardFindingIpcDto(
                            finding.Kind.ToString(),
                            finding.Verdict,
                            finding.Severity,
                            finding.Title,
                            finding.Details,
                            finding.EntryPath))
                .ToArray(),
            workflow.DecisionRequest?.Id,
            actions,
            scan.StartedAtUtc,
            scan.CompletedAtUtc);
    }
}