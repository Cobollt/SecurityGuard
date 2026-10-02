using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.AlgorithmGuard.Enums;
using SecurityGuard.AlgorithmGuard.Models;

namespace SecurityGuard.AlgorithmGuard.Services;

public sealed class AdaptiveAlgorithmEnforcementService
    : IAlgorithmEnforcementService,
      IAlgorithmRuntimeEnforcer
{
    private readonly AppLockerAlgorithmEnforcementService _appLocker;
    private readonly ProcessExecutionEnforcementService _processFallback;
    private readonly IAppLockerHealthService _healthService;

    private readonly SemaphoreSlim _selectionGate =
        new(1, 1);

    private Backend _backend =
        Backend.Unknown;

    public AdaptiveAlgorithmEnforcementService(
        AppLockerAlgorithmEnforcementService appLocker,
        ProcessExecutionEnforcementService processFallback,
        IAppLockerHealthService healthService)
    {
        _appLocker =
            appLocker;

        _processFallback =
            processFallback;

        _healthService =
            healthService;
    }

    public AlgorithmEnforcementLevel GetLevel(
        string? filePath)
    {
        return AlgorithmEnforcementClassifier.GetLevel(
            filePath);
    }

    public async Task<AlgorithmEnforcementResult> AddBlockAsync(
        Guid securityRuleId,
        string filePath,
        string expectedSha256,
        CancellationToken cancellationToken = default)
    {
        var backend =
            await GetBackendAsync(
                cancellationToken);

        return await backend.AddBlockAsync(
            securityRuleId,
            filePath,
            expectedSha256,
            cancellationToken);
    }

    public async Task RemoveBlockAsync(
        Guid securityRuleId,
        CancellationToken cancellationToken = default)
    {
        var backend =
            await GetBackendAsync(
                cancellationToken);

        await backend.RemoveBlockAsync(
            securityRuleId,
            cancellationToken);
    }

    public async Task<AlgorithmEnforcementSnapshot> InspectAsync(
        CancellationToken cancellationToken = default)
    {
        var backend =
            await GetBackendAsync(
                cancellationToken);

        return await backend.InspectAsync(
            cancellationToken);
    }

    public async Task<bool> UsesProcessFallbackAsync(
        CancellationToken cancellationToken = default)
    {
        await GetBackendAsync(
            cancellationToken);

        return _backend ==
            Backend.ProcessFallback;
    }

    public async Task<AlgorithmRuntimeEnforcementResult> EnforceAsync(
        AlgorithmExecutionAttempt attempt,
        CancellationToken cancellationToken = default)
    {
        var backend =
            await GetBackendAsync(
                cancellationToken);

        if (ReferenceEquals(
                backend,
                _processFallback))
        {
            return await _processFallback.EnforceAsync(
                attempt,
                cancellationToken);
        }

        return new AlgorithmRuntimeEnforcementResult(
            false,
            false,
            "AppLocker backend does not require reactive process termination.");
    }

    private async Task<IAlgorithmEnforcementService> GetBackendAsync(
        CancellationToken cancellationToken)
    {
        if (_backend !=
            Backend.Unknown)
        {
            return GetSelectedBackend();
        }

        await _selectionGate.WaitAsync(
            cancellationToken);

        try
        {
            if (_backend !=
                Backend.Unknown)
            {
                return GetSelectedBackend();
            }

            var health =
                await _healthService.EnsureReadyAsync(
                    cancellationToken);

            if (health.EnforcementReady)
            {
                _backend =
                    Backend.AppLocker;

                return _appLocker;
            }

            if (health.IsWindows)
            {
                _backend =
                    Backend.ProcessFallback;

                return _processFallback;
            }

            throw new InvalidOperationException(
                "No AlgorithmGuard enforcement backend is available.");
        }
        finally
        {
            _selectionGate.Release();
        }
    }

    private IAlgorithmEnforcementService GetSelectedBackend()
    {
        return _backend switch
        {
            Backend.AppLocker =>
                _appLocker,

            Backend.ProcessFallback =>
                _processFallback,

            _ =>
                throw new InvalidOperationException(
                    "AlgorithmGuard enforcement backend has not been selected.")
        };
    }

    private enum Backend
    {
        Unknown = 0,
        AppLocker = 1,
        ProcessFallback = 2
    }
}