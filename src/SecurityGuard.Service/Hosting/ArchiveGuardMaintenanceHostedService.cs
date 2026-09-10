using Microsoft.Extensions.Hosting;
using SecurityGuard.ArchiveGuard.Configuration;
using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.Service.Hosting;

public sealed class ArchiveGuardMaintenanceHostedService
    : BackgroundService
{
    private readonly IArchiveGuardSpoolCleanupService _spoolCleanup;
    private readonly IScanResultRepository _scanResultRepository;
    private readonly ArchiveGuardOptions _options;
    private readonly IAuditService _auditService;

    public ArchiveGuardMaintenanceHostedService(
        IArchiveGuardSpoolCleanupService spoolCleanup,
        IScanResultRepository scanResultRepository,
        ArchiveGuardOptions options,
        IAuditService auditService)
    {
        _spoolCleanup =
            spoolCleanup;

        _scanResultRepository =
            scanResultRepository;

        _options =
            options;

        _auditService =
            auditService;
    }

    protected override async Task ExecuteAsync(
        CancellationToken stoppingToken)
    {
        await RunMaintenanceAsync(
            true,
            stoppingToken);

        using var timer =
            new PeriodicTimer(
                TimeSpan.FromMinutes(
                    Math.Max(
                        1,
                        _options.MaintenanceIntervalMinutes)));

        while (await timer.WaitForNextTickAsync(
                   stoppingToken))
        {
            await RunMaintenanceAsync(
                false,
                stoppingToken);
        }
    }

    private async Task RunMaintenanceAsync(
        bool startup,
        CancellationToken cancellationToken)
    {
        try
        {
            var now =
                DateTimeOffset.UtcNow;

            var spoolCutoff =
                startup
                    ? now
                    : now.AddMinutes(
                        -_options.SpoolFileRetentionMinutes);

            var deletedSpools =
                await _spoolCleanup.CleanupAsync(
                    spoolCutoff,
                    cancellationToken);

            await _scanResultRepository.PruneAsync(
                SecurityModuleKind.ArchiveGuard,
                now.AddDays(
                    -_options.ScanHistoryRetentionDays),
                _options.MaxStoredScanResults,
                cancellationToken);

            if (deletedSpools >
                0)
            {
                await _auditService.WriteAsync(
                    SecurityModuleKind.ArchiveGuard,
                    SecurityEventType.System,
                    SecuritySeverity.Info,
                    "ArchiveGuard maintenance completed",
                    $"DeletedSpoolFiles={deletedSpools}",
                    cancellationToken:
                        cancellationToken);
            }
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            await _auditService.WriteAsync(
                SecurityModuleKind.ArchiveGuard,
                SecurityEventType.System,
                SecuritySeverity.Medium,
                "ArchiveGuard maintenance failed",
                exception.Message,
                cancellationToken:
                    cancellationToken);
        }
    }
}