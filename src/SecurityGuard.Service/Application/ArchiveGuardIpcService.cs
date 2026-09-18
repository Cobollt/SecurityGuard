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
    private readonly IQuarantineRepository _quarantineRepository;
    private readonly IQuarantineService _quarantineService;
    private readonly IArchiveGuardExceptionService _exceptionService;

    public ArchiveGuardIpcService(
        IArchiveGuardWorkflowService workflowService,
        IScanResultRepository scanResultRepository,
        IQuarantineRepository quarantineRepository,
        IQuarantineService quarantineService,
        IArchiveGuardExceptionService exceptionService)
    {
        _workflowService =
            workflowService;

        _scanResultRepository =
            scanResultRepository;

        _quarantineRepository =
            quarantineRepository;

        _quarantineService =
            quarantineService;

        _exceptionService =
            exceptionService;
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

    public async Task<IReadOnlyList<ArchiveGuardQuarantineItemIpcDto>> GetQuarantineItemsAsync(
        ArchiveGuardQuarantineItemsIpcRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            request);

        var limit =
            Math.Clamp(
                request.Limit,
                1,
                200);

        var items =
            await _quarantineRepository.GetAllAsync(
                cancellationToken);

        return items
            .Where(
                item =>
                    string.Equals(
                        item.SourceModule,
                        SecurityModuleKind.ArchiveGuard.ToString(),
                        StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(
                item =>
                    item.QuarantinedAtUtc)
            .Take(
                limit)
            .Select(
                item =>
                    new ArchiveGuardQuarantineItemIpcDto(
                        item.Id,
                        item.OriginalPath,
                        item.OriginalFileName,
                        item.Sha256,
                        item.SizeBytes,
                        item.Reason,
                        item.QuarantinedAtUtc))
            .ToArray();
    }

    public async Task<ArchiveGuardQuarantineRestoreIpcDto> RestoreFromQuarantineWithExceptionAsync(
        ArchiveGuardQuarantineRestoreIpcRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            request);

        if (request.QuarantineId ==
            Guid.Empty)
        {
            throw new ArgumentException(
                "Quarantine ID is required.",
                nameof(request));
        }

        var record =
            await _quarantineRepository.GetByIdAsync(
                request.QuarantineId,
                cancellationToken);

        if (record is null)
        {
            throw new InvalidOperationException(
                $"Quarantine item '{request.QuarantineId}' was not found.");
        }

        if (!string.Equals(
                record.SourceModule,
                SecurityModuleKind.ArchiveGuard.ToString(),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "The quarantine item does not belong to ArchiveGuard.");
        }

        if (string.IsNullOrWhiteSpace(
                record.Sha256))
        {
            throw new InvalidOperationException(
                "The quarantine item does not contain a SHA-256 hash.");
        }

        await _exceptionService.AddSha256ExceptionAsync(
            record.Sha256,
            record.OriginalFileName,
            cancellationToken);

        var restoredPath =
            await _quarantineService.RestoreAsync(
                record.Id,
                cancellationToken: cancellationToken);

        return new ArchiveGuardQuarantineRestoreIpcDto(
            record.Id,
            restoredPath,
            record.Sha256);
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