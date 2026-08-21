using Microsoft.Extensions.Hosting;
using SecurityGuard.AlgorithmGuard.Configuration;
using SecurityGuard.AlgorithmGuard.Services;

namespace SecurityGuard.Service.Hosting;

public sealed class AlgorithmDecisionMaintenanceHostedService
    : BackgroundService
{
    private readonly AlgorithmDecisionMaintenanceService _maintenanceService;
    private readonly AlgorithmGuardOptions _options;

    public AlgorithmDecisionMaintenanceHostedService(
        AlgorithmDecisionMaintenanceService maintenanceService,
        AlgorithmGuardOptions options)
    {
        _maintenanceService =
            maintenanceService;

        _options =
            options;
    }

    protected override async Task ExecuteAsync(
        CancellationToken stoppingToken)
    {
        await _maintenanceService.CleanupAsync(
            stoppingToken);

        using var timer =
            new PeriodicTimer(
                _options.MaintenanceInterval);

        while (await timer.WaitForNextTickAsync(
                   stoppingToken))
        {
            await _maintenanceService.CleanupAsync(
                stoppingToken);
        }
    }
}