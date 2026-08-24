using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.AlgorithmGuard.Enums;
using SecurityGuard.AlgorithmGuard.Models;
using SecurityGuard.Core.Contracts;

namespace SecurityGuard.AlgorithmGuard.Services;

public sealed class AlgorithmGuardSettingsService
    : IAlgorithmGuardSettingsService
{
    private const string EnabledKey =
        "AlgorithmGuard.Enabled";

    private const string ModeKey =
        "AlgorithmGuard.Mode";

    private const string FailurePolicyKey =
        "AlgorithmGuard.FailurePolicy";

    private readonly ISettingsRepository _settingsRepository;

    public AlgorithmGuardSettingsService(
        ISettingsRepository settingsRepository)
    {
        _settingsRepository =
            settingsRepository;
    }

    public async Task<AlgorithmGuardSettings> GetAsync(
        CancellationToken cancellationToken = default)
    {
        var defaults =
            AlgorithmGuardSettings.Default;

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
            Enum.TryParse<AlgorithmGuardMode>(
                modeValue,
                true,
                out var parsedMode)
                ? parsedMode
                : defaults.Mode;

        var failurePolicy =
            Enum.TryParse<EnforcementFailurePolicy>(
                failureValue,
                true,
                out var parsedFailurePolicy)
                ? parsedFailurePolicy
                : defaults.FailurePolicy;

        return new AlgorithmGuardSettings(
            enabled,
            mode,
            failurePolicy);
    }

    public async Task SaveAsync(
        AlgorithmGuardSettings settings,
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