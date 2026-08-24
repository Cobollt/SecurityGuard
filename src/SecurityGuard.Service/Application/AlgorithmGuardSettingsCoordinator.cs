using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.AlgorithmGuard.Models;

namespace SecurityGuard.Service.Application;

public sealed class AlgorithmGuardSettingsCoordinator
    : IAlgorithmGuardSettingsCoordinator
{
    private readonly IAlgorithmGuardSettingsService _settingsService;
    private readonly IAlgorithmGuardRuntimeController _runtimeController;

    public AlgorithmGuardSettingsCoordinator(
        IAlgorithmGuardSettingsService settingsService,
        IAlgorithmGuardRuntimeController runtimeController)
    {
        _settingsService =
            settingsService;

        _runtimeController =
            runtimeController;
    }

    public Task<AlgorithmGuardSettings> GetAsync(
        CancellationToken cancellationToken = default)
    {
        return _settingsService.GetAsync(
            cancellationToken);
    }

    public async Task UpdateAsync(
        AlgorithmGuardSettings settings,
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