using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.AlgorithmGuard.Enums;
using SecurityGuard.AlgorithmGuard.Models;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.Service.Hosting;

namespace SecurityGuard.Service.Tests;

public sealed class AlgorithmGuardHostedServiceTests
{
    [Fact]
    public async Task Enforce_with_unavailable_management_and_fail_open_enters_degraded_monitor()
    {
        var monitor =
            new FakeAlgorithmGuardMonitor();

        var synchronizer =
            new FakeAlgorithmEnforcementSynchronizer();

        var settings =
            new AlgorithmGuardSettings(
                true,
                AlgorithmGuardMode.Enforce,
                EnforcementFailurePolicy.FailOpen);

        var health =
            new FakeAppLockerHealthService(
                CreateManagementUnavailableHealth());

        var registry =
            new FakeModuleRegistry();

        var audit =
            new FakeAuditService();

        var service =
            new AlgorithmGuardHostedService(
                monitor,
                synchronizer,
                health,
                new FakeAlgorithmGuardSettingsService(
                    settings),
                registry,
                audit);

        try
        {
            await service.ApplyAsync(
                settings);

            await monitor.Started.Task.WaitAsync(
                TimeSpan.FromSeconds(2));

            Assert.Equal(
                ModuleOperationalState.Degraded,
                registry.LastState);

            Assert.Contains(
                "management cmdlets are unavailable",
                registry.LastMessage,
                StringComparison.OrdinalIgnoreCase);

            Assert.Equal(
                0,
                synchronizer.SynchronizeCalls);

            Assert.Equal(
                1,
                monitor.RunCalls);

            Assert.Equal(
                SecuritySeverity.Info,
                audit.LastSeverity);

            Assert.Equal(
                "AlgorithmGuard enforcement unavailable",
                audit.LastTitle);
        }
        finally
        {
            await service.ApplyAsync(
                new AlgorithmGuardSettings(
                    false,
                    AlgorithmGuardMode.Monitor,
                    EnforcementFailurePolicy.FailOpen));
        }
    }

    [Fact]
    public async Task Enforce_with_unavailable_management_and_fail_closed_enters_faulted_without_monitor()
    {
        var monitor =
            new FakeAlgorithmGuardMonitor();

        var synchronizer =
            new FakeAlgorithmEnforcementSynchronizer();

        var settings =
            new AlgorithmGuardSettings(
                true,
                AlgorithmGuardMode.Enforce,
                EnforcementFailurePolicy.FailClosed);

        var health =
            new FakeAppLockerHealthService(
                CreateManagementUnavailableHealth());

        var registry =
            new FakeModuleRegistry();

        var audit =
            new FakeAuditService();

        var service =
            new AlgorithmGuardHostedService(
                monitor,
                synchronizer,
                health,
                new FakeAlgorithmGuardSettingsService(
                    settings),
                registry,
                audit);

        await service.ApplyAsync(
            settings);

        Assert.Equal(
            ModuleOperationalState.Faulted,
            registry.LastState);

        Assert.Contains(
            "management cmdlets are unavailable",
            registry.LastMessage,
            StringComparison.OrdinalIgnoreCase);

        Assert.Equal(
            0,
            synchronizer.SynchronizeCalls);

        Assert.Equal(
            0,
            monitor.RunCalls);

        Assert.Equal(
            SecuritySeverity.Critical,
            audit.LastSeverity);

        Assert.Equal(
            "AlgorithmGuard enforcement unavailable",
            audit.LastTitle);
    }

    private static AppLockerHealthSnapshot CreateManagementUnavailableHealth()
    {
        return new AppLockerHealthSnapshot(
            true,
            true,
            true,
            true,
            true,
            true,
            false,
            false,
            "AppLocker management cmdlets are unavailable.");
    }

    private sealed class FakeAlgorithmGuardMonitor
        : IAlgorithmGuardMonitor
    {
        public int RunCalls { get; private set; }

        public TaskCompletionSource<bool> Started { get; } =
            new(
                TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task RunAsync(
            CancellationToken cancellationToken = default)
        {
            RunCalls++;

            Started.TrySetResult(
                true);

            await Task.Delay(
                Timeout.InfiniteTimeSpan,
                cancellationToken);
        }
    }

    private sealed class FakeAlgorithmEnforcementSynchronizer
        : IAlgorithmEnforcementSynchronizer
    {
        public int SynchronizeCalls { get; private set; }

        public int DisableCalls { get; private set; }

        public Task<AlgorithmEnforcementSyncResult> SynchronizeAsync(
            CancellationToken cancellationToken = default)
        {
            SynchronizeCalls++;

            return Task.FromResult(
                new AlgorithmEnforcementSyncResult(
                    0,
                    0,
                    true,
                    Array.Empty<string>()));
        }

        public Task<int> DisableManagedRulesAsync(
            CancellationToken cancellationToken = default)
        {
            DisableCalls++;

            return Task.FromResult(
                0);
        }
    }

    private sealed class FakeAppLockerHealthService
        : IAppLockerHealthService
    {
        private readonly AppLockerHealthSnapshot _snapshot;

        public FakeAppLockerHealthService(
            AppLockerHealthSnapshot snapshot)
        {
            _snapshot =
                snapshot;
        }

        public Task<AppLockerHealthSnapshot> GetHealthAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                _snapshot);
        }

        public Task<AppLockerHealthSnapshot> EnsureReadyAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                _snapshot);
        }
    }

    private sealed class FakeAlgorithmGuardSettingsService
        : IAlgorithmGuardSettingsService
    {
        private AlgorithmGuardSettings _settings;

        public FakeAlgorithmGuardSettingsService(
            AlgorithmGuardSettings settings)
        {
            _settings =
                settings;
        }

        public Task<AlgorithmGuardSettings> GetAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                _settings);
        }

        public Task SaveAsync(
            AlgorithmGuardSettings settings,
            CancellationToken cancellationToken = default)
        {
            _settings =
                settings;

            return Task.CompletedTask;
        }
    }

    private sealed class FakeModuleRegistry
        : IModuleRegistry
    {
        public ModuleOperationalState LastState { get; private set; } =
            ModuleOperationalState.Disabled;

        public string LastMessage { get; private set; } =
            "AlgorithmGuard is disabled";

        public IReadOnlyList<ModuleStatus> GetAll()
        {
            return
            [
                Get(
                    SecurityModuleKind.AlgorithmGuard)
            ];
        }

        public ModuleStatus Get(
            SecurityModuleKind module)
        {
            return new ModuleStatus(
                module,
                LastState,
                LastMessage,
                DateTimeOffset.UtcNow);
        }

        public void Set(
            SecurityModuleKind module,
            ModuleOperationalState state,
            string message)
        {
            LastState =
                state;

            LastMessage =
                message;
        }
    }

    private sealed class FakeAuditService
        : IAuditService
    {
        public SecuritySeverity? LastSeverity { get; private set; }

        public string? LastTitle { get; private set; }

        public string? LastDetails { get; private set; }

        public Task WriteAsync(
            SecurityModuleKind module,
            SecurityEventType type,
            SecuritySeverity severity,
            string title,
            string details,
            SecurityAction action = SecurityAction.None,
            Guid? correlationId = null,
            CancellationToken cancellationToken = default)
        {
            LastSeverity =
                severity;

            LastTitle =
                title;

            LastDetails =
                details;

            return Task.CompletedTask;
        }
    }
}