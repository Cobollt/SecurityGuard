using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.UI.ViewModels;

namespace SecurityGuard.UI.Tests;

public sealed class MainViewModelTests
{
    [Fact]
    public async Task Refresh_loads_snapshot()
    {
        var client =
            new FakeSecurityGuardClient();

        client.Snapshot =
            CreateSnapshot();

        var viewModel =
            new MainViewModel(client);

        await viewModel.RefreshAsync();

        Assert.True(
            viewModel.IsConnected);

        Assert.Equal(
            "Служба подключена",
            viewModel.ServiceStatus);

        Assert.Equal(
            4,
            viewModel.Modules.Count);

        Assert.Equal(
            3,
            viewModel.RecentEvents.Count);

        Assert.Single(
            viewModel.AlgorithmEvents);

        Assert.Single(
            viewModel.TransferEvents);

        Assert.Single(
            viewModel.ArchiveEvents);

        Assert.Single(
            viewModel.PendingRequests);

        Assert.Equal(
            2,
            viewModel.QuarantineCount);

        Assert.Null(
            viewModel.LastError);
    }

    [Fact]
    public async Task Disconnected_service_is_reported()
    {
        var client =
            new FakeSecurityGuardClient
            {
                Connected = false
            };

        var viewModel =
            new MainViewModel(client);

        await viewModel.RefreshAsync();

        Assert.False(
            viewModel.IsConnected);

        Assert.True(
            viewModel.HasError);

        Assert.Equal(
            "SecurityGuard.Service не отвечает.",
            viewModel.LastError);
    }

    [Fact]
    public async Task Connection_exception_is_reported()
    {
        var client =
            new FakeSecurityGuardClient
            {
                ExceptionToThrow =
                    new IOException(
                        "Pipe unavailable")
            };

        var viewModel =
            new MainViewModel(client);

        await viewModel.RefreshAsync();

        Assert.False(
            viewModel.IsConnected);

        Assert.True(
            viewModel.HasError);

        Assert.Equal(
            "Pipe unavailable",
            viewModel.LastError);
    }

    [Fact]
    public void Navigation_changes_page()
    {
        var viewModel =
            new MainViewModel(
                new FakeSecurityGuardClient());

        viewModel.NavigateCommand.Execute("3");

        Assert.Equal(
            3,
            viewModel.SelectedPageIndex);

        viewModel.NavigateCommand.Execute("7");

        Assert.Equal(
            7,
            viewModel.SelectedPageIndex);
    }

    private static SecuritySnapshot CreateSnapshot()
    {
        var modules =
            new[]
            {
                new ModuleStatus(
                    SecurityModuleKind.Core,
                    ModuleOperationalState.Active,
                    "Ready",
                    DateTimeOffset.UtcNow),

                new ModuleStatus(
                    SecurityModuleKind.AlgorithmGuard,
                    ModuleOperationalState.Disabled,
                    "Not implemented",
                    DateTimeOffset.UtcNow),

                new ModuleStatus(
                    SecurityModuleKind.TransferGuard,
                    ModuleOperationalState.Disabled,
                    "Not implemented",
                    DateTimeOffset.UtcNow),

                new ModuleStatus(
                    SecurityModuleKind.ArchiveGuard,
                    ModuleOperationalState.Disabled,
                    "Not implemented",
                    DateTimeOffset.UtcNow)
            };

        var events =
            new[]
            {
                SecurityEvent.Create(
                    SecurityModuleKind.AlgorithmGuard,
                    SecurityEventType.AlgorithmExecution,
                    SecuritySeverity.High,
                    "Algorithm event",
                    "test"),

                SecurityEvent.Create(
                    SecurityModuleKind.TransferGuard,
                    SecurityEventType.FileTransfer,
                    SecuritySeverity.Medium,
                    "Transfer event",
                    "test"),

                SecurityEvent.Create(
                    SecurityModuleKind.ArchiveGuard,
                    SecurityEventType.ArchiveScan,
                    SecuritySeverity.Low,
                    "Archive event",
                    "test")
            };

        var requests =
            new[]
            {
                new SecurityDecisionRequest(
                    Guid.NewGuid(),
                    SecurityModuleKind.AlgorithmGuard,
                    SecurityEventType.AlgorithmExecution,
                    "Unknown script",
                    "Script execution blocked",
                    @"C:\Temp\test.ps1",
                    "powershell.exe",
                    [
                        SecurityAction.AllowOnce,
                        SecurityAction.Quarantine
                    ],
                    DateTimeOffset.UtcNow)
            };

        return new SecuritySnapshot(
            modules,
            events,
            requests,
            2,
            DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task Refresh_loads_security_rules()
    {
        var client =
            new FakeSecurityGuardClient
            {
                Rules =
                [
                    new SecurityRule(
                        Guid.NewGuid(),
                        "Allow script",
                        SecurityModuleKind.AlgorithmGuard,
                        RuleDecision.Allow,
                        RuleScope.FileHash,
                        "AAA",
                        true,
                        100,
                        DateTimeOffset.UtcNow,
                        null),

                    new SecurityRule(
                        Guid.NewGuid(),
                        "Block script",
                        SecurityModuleKind.AlgorithmGuard,
                        RuleDecision.Block,
                        RuleScope.FileHash,
                        "BBB",
                        true,
                        200,
                        DateTimeOffset.UtcNow,
                        null)
                ]
            };

        var viewModel =
            new MainViewModel(
                client);

        await viewModel.RefreshAsync();

        Assert.Equal(
            2,
            viewModel.Rules.Count);

        Assert.Single(
            viewModel.AllowRules);

        Assert.Single(
            viewModel.BlockRules);
    }

    [Fact]
    public async Task Refresh_loads_algorithm_guard_settings()
    {
        var client =
            new FakeSecurityGuardClient
            {
                AlgorithmGuardSettings =
                    new SecurityGuard.AlgorithmGuard.Models.AlgorithmGuardSettings(
                        true,
                        SecurityGuard.AlgorithmGuard.Enums.AlgorithmGuardMode.Enforce,
                        SecurityGuard.AlgorithmGuard.Enums.EnforcementFailurePolicy.FailClosed)
            };

        var viewModel =
            new MainViewModel(
                client);

        await viewModel.RefreshAsync();

        Assert.True(
            viewModel.AlgorithmGuardEnabled);

        Assert.Equal(
            SecurityGuard.AlgorithmGuard.Enums.AlgorithmGuardMode.Enforce,
            viewModel.AlgorithmGuardMode);

        Assert.Equal(
            SecurityGuard.AlgorithmGuard.Enums.EnforcementFailurePolicy.FailClosed,
            viewModel.AlgorithmGuardFailurePolicy);
    }
}