using SecurityGuard.Core.Contracts;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Enums;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Services;

public sealed class TransferGuardSettingsService
    : ITransferGuardSettingsService
{
    private const string EnabledKey =
        "TransferGuard.Enabled";

    private const string ModeKey =
        "TransferGuard.Mode";

    private const string FailurePolicyKey =
        "TransferGuard.FailurePolicy";

    private readonly ISettingsRepository _settingsRepository;

    public TransferGuardSettingsService(
        ISettingsRepository settingsRepository)
    {
        _settingsRepository =
            settingsRepository;
    }

    public async Task<TransferGuardSettings> GetAsync(
        CancellationToken cancellationToken = default)
    {
        var defaults =
            TransferGuardSettings.Default;

        var enabledValue =
            await _settingsRepository.GetAsync(
                EnabledKey,
                cancellationToken);

        var modeValue =
            await _settingsRepository.GetAsync(
                ModeKey,
                cancellationToken);

        var failureValue =
            await _settingsRepository.GetAsync(
                FailurePolicyKey,
                cancellationToken);

        var enabled =
            bool.TryParse(
                enabledValue,
                out var parsedEnabled)
                ? parsedEnabled
                : defaults.Enabled;

        var mode =
            Enum.TryParse<TransferGuardMode>(
                modeValue,
                true,
                out var parsedMode)
                ? parsedMode
                : defaults.Mode;

        var failurePolicy =
            Enum.TryParse<TransferEnforcementFailurePolicy>(
                failureValue,
                true,
                out var parsedFailurePolicy)
                ? parsedFailurePolicy
                : defaults.FailurePolicy;

        return new TransferGuardSettings(
            enabled,
            mode,
            failurePolicy);
    }

    public async Task SaveAsync(
        TransferGuardSettings settings,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            settings);

        await _settingsRepository.SetAsync(
            EnabledKey,
            settings.Enabled.ToString(),
            cancellationToken);

        await _settingsRepository.SetAsync(
            ModeKey,
            settings.Mode.ToString(),
            cancellationToken);

        await _settingsRepository.SetAsync(
            FailurePolicyKey,
            settings.FailurePolicy.ToString(),
            cancellationToken);
    }
}