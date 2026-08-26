using Microsoft.Extensions.Hosting;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.TransferGuard.Configuration;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Enums;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.Service.Hosting;

public sealed class TransferGuardHostedService
    : BackgroundService,
      ITransferGuardRuntimeController
{
    private readonly ITransferGuardMonitor _monitor;
    private readonly IFilteringPlatformAuditPolicyService _auditPolicyService;
    private readonly ITransferEnforcementSynchronizer _synchronizer;
    private readonly ITransferGuardSettingsService _settingsService;
    private readonly TransferGuardOptions _options;
    private readonly IModuleRegistry _moduleRegistry;
    private readonly IAuditService _auditService;

    private readonly SemaphoreSlim _gate =
        new(1, 1);

    private CancellationTokenSource? _monitorCancellation;
    private Task? _monitorTask;

    private CancellationToken _hostStoppingToken =
        CancellationToken.None;

    private TransferGuardSettings _currentSettings =
        TransferGuardSettings.Default;

    public TransferGuardSettings CurrentSettings =>
        _currentSettings;

    public TransferGuardHostedService(
        ITransferGuardMonitor monitor,
        IFilteringPlatformAuditPolicyService auditPolicyService,
        ITransferEnforcementSynchronizer synchronizer,
        ITransferGuardSettingsService settingsService,
        TransferGuardOptions options,
        IModuleRegistry moduleRegistry,
        IAuditService auditService)
    {
        _monitor =
            monitor;

        _auditPolicyService =
            auditPolicyService;

        _synchronizer =
            synchronizer;

        _settingsService =
            settingsService;

        _options =
            options;

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
        catch (Exception exception)
        {
            _moduleRegistry.Set(
                SecurityModuleKind.TransferGuard,
                ModuleOperationalState.Faulted,
                exception.Message);

            try
            {
                await _auditService.WriteAsync(
                    SecurityModuleKind.TransferGuard,
                    SecurityEventType.System,
                    SecuritySeverity.Critical,
                    "TransferGuard startup failed",
                    exception.Message,
                    cancellationToken:
                        CancellationToken.None);
            }
            catch
            {
            }

            try
            {
                await Task.Delay(
                    Timeout.InfiniteTimeSpan,
                    stoppingToken);
            }
            catch (OperationCanceledException)
                when (stoppingToken.IsCancellationRequested)
            {
            }
        }
        finally
        {
            await _gate.WaitAsync(
                CancellationToken.None);

            try
            {
                await StopMonitorAsync();

                _moduleRegistry.Set(
                    SecurityModuleKind.TransferGuard,
                    ModuleOperationalState.Disabled,
                    "TransferGuard is stopped");
            }
            finally
            {
                _gate.Release();
            }
        }
    }

    public async Task ApplyAsync(
        TransferGuardSettings settings,
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

                await DisableEnforcementAsync(
                    "TransferGuard is disabled",
                    cancellationToken);

                _moduleRegistry.Set(
                    SecurityModuleKind.TransferGuard,
                    ModuleOperationalState.Disabled,
                    "TransferGuard is disabled");

                await WriteModeChangedAsync(
                    settings,
                    cancellationToken);

                return;
            }

            await EnsureMonitoringPrerequisitesAsync(
                cancellationToken);

            if (settings.Mode ==
                TransferGuardMode.Monitor)
            {
                await StopMonitorAsync();

                await DisableEnforcementAsync(
                    "TransferGuard Monitor mode",
                    cancellationToken);

                StartMonitor();

                _moduleRegistry.Set(
                    SecurityModuleKind.TransferGuard,
                    ModuleOperationalState.Active,
                    "Monitor mode is active");

                await WriteModeChangedAsync(
                    settings,
                    cancellationToken);

                return;
            }

            var synchronization =
                await _synchronizer.SynchronizeAsync(
                    cancellationToken);

            if (synchronization.Healthy)
            {
                StartMonitor();

                _moduleRegistry.Set(
                    SecurityModuleKind.TransferGuard,
                    ModuleOperationalState.Active,
                    "Enforce mode is active");

                await WriteModeChangedAsync(
                    settings,
                    cancellationToken);

                return;
            }

            if (settings.FailurePolicy ==
                TransferEnforcementFailurePolicy.FailOpen)
            {
                StartMonitor();

                _moduleRegistry.Set(
                    SecurityModuleKind.TransferGuard,
                    ModuleOperationalState.Degraded,
                    "Firewall enforcement has warnings; monitoring remains active");

                await _auditService.WriteAsync(
                    SecurityModuleKind.TransferGuard,
                    SecurityEventType.System,
                    SecuritySeverity.High,
                    "TransferGuard enforcement degraded",
                    string.Join(
                        Environment.NewLine,
                        synchronization.Warnings),
                    cancellationToken:
                        cancellationToken);

                return;
            }

            await StopMonitorAsync();

            _moduleRegistry.Set(
                SecurityModuleKind.TransferGuard,
                ModuleOperationalState.Faulted,
                "Firewall enforcement validation failed");

            await _auditService.WriteAsync(
                SecurityModuleKind.TransferGuard,
                SecurityEventType.System,
                SecuritySeverity.Critical,
                "TransferGuard fail-closed",
                string.Join(
                    Environment.NewLine,
                    synchronization.Warnings),
                cancellationToken:
                    cancellationToken);
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
                SecurityModuleKind.TransferGuard,
                SecurityEventType.System,
                SecuritySeverity.Critical,
                "TransferGuard enforcement failure",
                message,
                cancellationToken:
                    cancellationToken);

            if (_currentSettings.FailurePolicy ==
                TransferEnforcementFailurePolicy.FailOpen)
            {
                StartMonitor();

                _moduleRegistry.Set(
                    SecurityModuleKind.TransferGuard,
                    ModuleOperationalState.Degraded,
                    "Firewall enforcement failure; monitoring remains active");

                return;
            }

            await StopMonitorAsync();

            _moduleRegistry.Set(
                SecurityModuleKind.TransferGuard,
                ModuleOperationalState.Faulted,
                "Firewall enforcement failure");
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task EnsureMonitoringPrerequisitesAsync(
        CancellationToken cancellationToken)
    {
        var state =
            _options.AutoEnableFilteringPlatformAudit
                ? await _auditPolicyService.EnsureSuccessEnabledAsync(
                    cancellationToken)
                : await _auditPolicyService.GetAsync(
                    cancellationToken);

        if (!state.SuccessEnabled)
        {
            throw new InvalidOperationException(
                "Filtering Platform Connection success auditing is disabled.");
        }

        if (!state.Changed)
        {
            return;
        }

        await _auditService.WriteAsync(
            SecurityModuleKind.TransferGuard,
            SecurityEventType.System,
            SecuritySeverity.Info,
            "WFP connection auditing enabled",
            "Filtering Platform Connection success auditing was enabled.",
            cancellationToken:
                cancellationToken);
    }

    private async Task DisableEnforcementAsync(
        string reason,
        CancellationToken cancellationToken)
    {
        try
        {
            await _synchronizer.DisableManagedRulesAsync(
                cancellationToken);
        }
        catch (Exception exception)
        {
            _moduleRegistry.Set(
                SecurityModuleKind.TransferGuard,
                ModuleOperationalState.Faulted,
                "Unable to disable Windows Firewall enforcement");

            await _auditService.WriteAsync(
                SecurityModuleKind.TransferGuard,
                SecurityEventType.System,
                SecuritySeverity.Critical,
                "Unable to disable TransferGuard enforcement",
                $"{reason}: {exception.Message}",
                cancellationToken:
                    cancellationToken);

            throw;
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
                    RunMonitorAsync(
                        token),
                CancellationToken.None);
    }

    private async Task RunMonitorAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            await _monitor.RunAsync(
                cancellationToken);
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            _moduleRegistry.Set(
                SecurityModuleKind.TransferGuard,
                ModuleOperationalState.Faulted,
                "TransferGuard monitoring failed");

            try
            {
                await _auditService.WriteAsync(
                    SecurityModuleKind.TransferGuard,
                    SecurityEventType.System,
                    SecuritySeverity.Critical,
                    "TransferGuard monitoring failed",
                    exception.Message,
                    cancellationToken:
                        CancellationToken.None);
            }
            catch
            {
            }
        }
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
        TransferGuardSettings settings,
        CancellationToken cancellationToken)
    {
        return _auditService.WriteAsync(
            SecurityModuleKind.TransferGuard,
            SecurityEventType.System,
            SecuritySeverity.Info,
            "TransferGuard mode applied",
            $"Enabled={settings.Enabled}; Mode={settings.Mode}; FailurePolicy={settings.FailurePolicy}",
            cancellationToken:
                cancellationToken);
    }
}