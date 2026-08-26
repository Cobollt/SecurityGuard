using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.Service.Application;

public sealed class TransferGuardSettingsCoordinator
    : ITransferGuardSettingsCoordinator
{
    private readonly ITransferGuardSettingsService _settingsService;
    private readonly ITransferGuardRuntimeController _runtimeController;

    public TransferGuardSettingsCoordinator(
        ITransferGuardSettingsService settingsService,
        ITransferGuardRuntimeController runtimeController)
    {
        _settingsService =
            settingsService;

        _runtimeController =
            runtimeController;
    }

    public Task<TransferGuardSettings> GetAsync(
        CancellationToken cancellationToken = default)
    {
        return _settingsService.GetAsync(
            cancellationToken);
    }

    public async Task UpdateAsync(
        TransferGuardSettings settings,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            settings);

        var previous =
            await _settingsService.GetAsync(
                cancellationToken);

        await _settingsService.SaveAsync(
            settings,
            cancellationToken);

        try
        {
            await _runtimeController.ApplyAsync(
                settings,
                cancellationToken);
        }
        catch
        {
            await _settingsService.SaveAsync(
                previous,
                cancellationToken);

            try
            {
                await _runtimeController.ApplyAsync(
                    previous,
                    cancellationToken);
            }
            catch
            {
            }

            throw;
        }
    }
}