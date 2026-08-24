using Microsoft.Extensions.Hosting;
using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.AlgorithmGuard.Enums;
using SecurityGuard.AlgorithmGuard.Models;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.Service.Hosting;

public sealed class AlgorithmGuardHostedService
    : BackgroundService,
      IAlgorithmGuardRuntimeController
{
    private readonly IAlgorithmGuardMonitor _monitor;
    private readonly IAlgorithmEnforcementSynchronizer _synchronizer;
    private readonly IAlgorithmGuardSettingsService _settingsService;
    private readonly IModuleRegistry _moduleRegistry;
    private readonly IAuditService _auditService;

    private readonly SemaphoreSlim _gate =
        new(1, 1);

    private CancellationTokenSource? _monitorCancellation;
    private Task? _monitorTask;

    private CancellationToken _hostStoppingToken;

    private AlgorithmGuardSettings _currentSettings =
        AlgorithmGuardSettings.Default;

    public AlgorithmGuardSettings CurrentSettings =>
        _currentSettings;

    public AlgorithmGuardHostedService(
        IAlgorithmGuardMonitor monitor,
        IAlgorithmEnforcementSynchronizer synchronizer,
        IAlgorithmGuardSettingsService settingsService,
        IModuleRegistry moduleRegistry,
        IAuditService auditService)
    {
        _monitor =
            monitor;

        _synchronizer =
            synchronizer;

        _settingsService =
            settingsService;

        _moduleRegistry =
            moduleRegistry;

        _auditService =
            auditService;
    }

    protected override async Task ExecuteAsync(
        CancellationToken stoppingToken)
    {
        _hostStoppingToken =
            stoppingToken;

        try
        {
            var settings =
                await _settingsService.GetAsync(
                    stoppingToken);

            await ApplyAsync(
                settings,
                stoppingToken);

            await Task.Delay(
                Timeout.InfiniteTimeSpan,
                stoppingToken);
        }
        catch (OperationCanceledException)
            when (stoppingToken.IsCancellationRequested)
        {
        }
        finally
        {
            await _gate.WaitAsync(
                CancellationToken.None);

            try
            {
                await StopMonitorAsync();

                _moduleRegistry.Set(
                    SecurityModuleKind.AlgorithmGuard,
                    ModuleOperationalState.Disabled,
                    "AlgorithmGuard is stopped");
            }
            finally
            {
                _gate.Release();
            }
        }
    }

    public async Task ApplyAsync(
        AlgorithmGuardSettings settings,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            settings);

        await _gate.WaitAsync(
            cancellationToken);

        try
        {
            _currentSettings =
                settings;

            if (!settings.Enabled)
            {
                await StopMonitorAsync();

                try
                {
                    await _synchronizer.DisableManagedRulesAsync(
                        cancellationToken);
                }
                catch
                {
                    _moduleRegistry.Set(
                        SecurityModuleKind.AlgorithmGuard,
                        ModuleOperationalState.Faulted,
                        "AlgorithmGuard could not remove enforcement rules");

                    throw;
                }

                _moduleRegistry.Set(
                    SecurityModuleKind.AlgorithmGuard,
                    ModuleOperationalState.Disabled,
                    "AlgorithmGuard is disabled");

                return;
            }

            if (settings.Mode ==
                AlgorithmGuardMode.Monitor)
            {
                try
                {
                    await _synchronizer.DisableManagedRulesAsync(
                        cancellationToken);
                }
                catch
                {
                    _moduleRegistry.Set(
                        SecurityModuleKind.AlgorithmGuard,
                        ModuleOperationalState.Faulted,
                        "Unable to enter Monitor mode");

                    throw;
                }

                StartMonitor();

                _moduleRegistry.Set(
                    SecurityModuleKind.AlgorithmGuard,
                    ModuleOperationalState.Active,
                    "Monitor mode is active");

                await WriteModeChangedAsync(
                    settings,
                    cancellationToken);

                return;
            }

            var sync =
                await _synchronizer.SynchronizeAsync(
                    cancellationToken);

            if (sync.Healthy)
            {
                StartMonitor();

                _moduleRegistry.Set(
                    SecurityModuleKind.AlgorithmGuard,
                    ModuleOperationalState.Active,
                    "Enforce mode is active");

                await WriteModeChangedAsync(
                    settings,
                    cancellationToken);

                return;
            }

            if (settings.FailurePolicy ==
                EnforcementFailurePolicy.FailOpen)
            {
                StartMonitor();

                _moduleRegistry.Set(
                    SecurityModuleKind.AlgorithmGuard,
                    ModuleOperationalState.Degraded,
                    "Enforcement has warnings; monitoring remains active");

                return;
            }

            await StopMonitorAsync();

            _moduleRegistry.Set(
                SecurityModuleKind.AlgorithmGuard,
                ModuleOperationalState.Faulted,
                "Enforcement validation failed");

            await _auditService.WriteAsync(
                SecurityModuleKind.AlgorithmGuard,
                SecurityEventType.System,
                SecuritySeverity.Critical,
                "AlgorithmGuard fail-closed",
                "Enforcement validation failed. AlgorithmGuard monitoring was stopped.",
                cancellationToken: cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task ReportEnforcementFailureAsync(
        string message,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            message);

        await _gate.WaitAsync(
            cancellationToken);

        try
        {
            await _auditService.WriteAsync(
                SecurityModuleKind.AlgorithmGuard,
                SecurityEventType.System,
                SecuritySeverity.Critical,
                "AlgorithmGuard enforcement failure",
                message,
                cancellationToken: cancellationToken);

            if (_currentSettings.FailurePolicy ==
                EnforcementFailurePolicy.FailOpen)
            {
                _moduleRegistry.Set(
                    SecurityModuleKind.AlgorithmGuard,
                    ModuleOperationalState.Degraded,
                    "Enforcement failure; monitoring remains active");

                StartMonitor();

                return;
            }

            await StopMonitorAsync();

            _moduleRegistry.Set(
                SecurityModuleKind.AlgorithmGuard,
                ModuleOperationalState.Faulted,
                "Enforcement failure");
        }
        finally
        {
            _gate.Release();
        }
    }

    private void StartMonitor()
    {
        if (_monitorTask is
            {
                IsCompleted: false
            })
        {
            return;
        }

        _monitorCancellation?.Dispose();

        _monitorCancellation =
            CancellationTokenSource.CreateLinkedTokenSource(
                _hostStoppingToken);

        var token =
            _monitorCancellation.Token;

        _monitorTask =
            Task.Run(
                () =>
                    _monitor.RunAsync(
                        token),
                CancellationToken.None);
    }

    private async Task StopMonitorAsync()
    {
        if (_monitorCancellation is null)
        {
            return;
        }

        await _monitorCancellation.CancelAsync();

        if (_monitorTask is not null)
        {
            try
            {
                await _monitorTask;
            }
            catch (OperationCanceledException)
            {
            }
        }

        _monitorCancellation.Dispose();

        _monitorCancellation =
            null;

        _monitorTask =
            null;
    }

    private Task WriteModeChangedAsync(
        AlgorithmGuardSettings settings,
        CancellationToken cancellationToken)
    {
        return _auditService.WriteAsync(
            SecurityModuleKind.AlgorithmGuard,
            SecurityEventType.System,
            SecuritySeverity.Info,
            "AlgorithmGuard mode applied",
            $"Enabled={settings.Enabled}; Mode={settings.Mode}; FailurePolicy={settings.FailurePolicy}",
            cancellationToken: cancellationToken);
    }
}