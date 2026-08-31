using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Enums;
using SecurityGuard.TransferGuard.Models;
using SecurityGuard.TransferGuard.Services;

namespace SecurityGuard.TransferGuard.Tests;

public sealed class TransferManualRuleServiceTests
{
    [Fact]
    public async Task Network_block_in_enforce_mode_is_saved_and_applied()
    {
        var repository =
            new FakeRuleRepository();

        var enforcement =
            new FakeEnforcementService();

        var runtime =
            new FakeRuntimeController
            {
                CurrentSettings =
                    new TransferGuardSettings(
                        true,
                        TransferGuardMode.Enforce,
                        TransferEnforcementFailurePolicy.FailClosed)
            };

        var service =
            new TransferManualRuleService(
                repository,
                enforcement,
                new TransferEnforcementRuleFactory(
                    new FakePathNormalizer()),
                runtime);

        var request =
            new TransferManualRuleRequest(
                "Block client connection",
                TransferActivityKind.NetworkConnection,
                RuleDecision.Block,
                [
                    new TransferManualRuleCondition(
                        RuleScope.ProcessPath,
                        @"C:\Apps\client.exe"),

                    new TransferManualRuleCondition(
                        RuleScope.RemoteAddress,
                        "1.1.1.1"),

                    new TransferManualRuleCondition(
                        RuleScope.RemotePort,
                        "443"),

                    new TransferManualRuleCondition(
                        RuleScope.Protocol,
                        "Tcp")
                ],
                200,
                null);

        var rule =
            await service.CreateAsync(
                request);

        Assert.Equal(
            SecurityModuleKind.TransferGuard,
            rule.Module);

        Assert.Equal(
            RuleDecision.Block,
            rule.Decision);

        Assert.Equal(
            "Block client connection",
            rule.Name);

        Assert.True(
            rule.Enabled);

        Assert.Equal(
            200,
            rule.Priority);

        Assert.Single(
            repository.Rules);

        Assert.True(
            enforcement.AddBlockWasCalled);

        Assert.NotNull(
            enforcement.LastAddedRule);

        Assert.Equal(
            rule.Id,
            enforcement.LastAddedRule.SecurityRuleId);

        Assert.Equal(
            @"C:\Apps\client.exe",
            enforcement.LastAddedRule.ProgramPath);

        Assert.Equal(
            "1.1.1.1",
            enforcement.LastAddedRule.RemoteAddress);

        Assert.Equal(
            443,
            enforcement.LastAddedRule.RemotePort);

        Assert.Equal(
            TransferProtocol.Tcp,
            enforcement.LastAddedRule.Protocol);
    }

    [Fact]
    public async Task Network_block_in_monitor_mode_is_saved_without_firewall()
    {
        var repository =
            new FakeRuleRepository();

        var enforcement =
            new FakeEnforcementService();

        var runtime =
            new FakeRuntimeController
            {
                CurrentSettings =
                    new TransferGuardSettings(
                        true,
                        TransferGuardMode.Monitor,
                        TransferEnforcementFailurePolicy.FailOpen)
            };

        var service =
            new TransferManualRuleService(
                repository,
                enforcement,
                new TransferEnforcementRuleFactory(
                    new FakePathNormalizer()),
                runtime);

        var request =
            new TransferManualRuleRequest(
                "Monitor client connection",
                TransferActivityKind.NetworkConnection,
                RuleDecision.Block,
                [
                    new TransferManualRuleCondition(
                        RuleScope.ProcessPath,
                        @"C:\Apps\client.exe"),

                    new TransferManualRuleCondition(
                        RuleScope.RemoteAddress,
                        "8.8.8.8"),

                    new TransferManualRuleCondition(
                        RuleScope.RemotePort,
                        "53"),

                    new TransferManualRuleCondition(
                        RuleScope.Protocol,
                        "Udp")
                ],
                200,
                null);

        var rule =
            await service.CreateAsync(
                request);

        Assert.Equal(
            RuleDecision.Block,
            rule.Decision);

        Assert.Single(
            repository.Rules);

        Assert.False(
            enforcement.AddBlockWasCalled);
    }

    [Fact]
    public async Task File_transfer_block_is_saved_without_permanent_firewall_rule()
    {
        var repository =
            new FakeRuleRepository();

        var enforcement =
            new FakeEnforcementService();

        var runtime =
            new FakeRuntimeController
            {
                CurrentSettings =
                    new TransferGuardSettings(
                        true,
                        TransferGuardMode.Enforce,
                        TransferEnforcementFailurePolicy.FailClosed)
            };

        var service =
            new TransferManualRuleService(
                repository,
                enforcement,
                new TransferEnforcementRuleFactory(
                    new FakePathNormalizer()),
                runtime);

        var request =
            new TransferManualRuleRequest(
                "Block secret file transfer",
                TransferActivityKind.FileTransfer,
                RuleDecision.Block,
                [
                    new TransferManualRuleCondition(
                        RuleScope.ProcessPath,
                        @"C:\Apps\client.exe"),

                    new TransferManualRuleCondition(
                        RuleScope.FilePath,
                        @"C:\Secret\data.zip")
                ],
                250,
                null);

        var rule =
            await service.CreateAsync(
                request);

        Assert.Equal(
            SecurityModuleKind.TransferGuard,
            rule.Module);

        Assert.Equal(
            RuleDecision.Block,
            rule.Decision);

        Assert.Equal(
            250,
            rule.Priority);

        Assert.Single(
            repository.Rules);

        Assert.False(
            enforcement.AddBlockWasCalled);

        Assert.Contains(
            GetAllConditions(
                rule),
            condition =>
                condition.Scope ==
                    RuleScope.FilePath &&
                condition.Value ==
                    @"C:\Secret\data.zip");
    }

    [Fact]
    public async Task Allow_rule_is_saved_without_firewall()
    {
        var repository =
            new FakeRuleRepository();

        var enforcement =
            new FakeEnforcementService();

        var runtime =
            new FakeRuntimeController
            {
                CurrentSettings =
                    new TransferGuardSettings(
                        true,
                        TransferGuardMode.Enforce,
                        TransferEnforcementFailurePolicy.FailClosed)
            };

        var service =
            new TransferManualRuleService(
                repository,
                enforcement,
                new TransferEnforcementRuleFactory(
                    new FakePathNormalizer()),
                runtime);

        var request =
            new TransferManualRuleRequest(
                "Allow trusted client",
                TransferActivityKind.NetworkConnection,
                RuleDecision.Allow,
                [
                    new TransferManualRuleCondition(
                        RuleScope.ProcessPath,
                        @"C:\Trusted\client.exe"),

                    new TransferManualRuleCondition(
                        RuleScope.RemoteAddress,
                        "10.0.0.10"),

                    new TransferManualRuleCondition(
                        RuleScope.RemotePort,
                        "443"),

                    new TransferManualRuleCondition(
                        RuleScope.Protocol,
                        "Tcp")
                ],
                100,
                null);

        var rule =
            await service.CreateAsync(
                request);

        Assert.Equal(
            RuleDecision.Allow,
            rule.Decision);

        Assert.Single(
            repository.Rules);

        Assert.False(
            enforcement.AddBlockWasCalled);
    }

    [Fact]
    public async Task Expiration_is_preserved()
    {
        var repository =
            new FakeRuleRepository();

        var enforcement =
            new FakeEnforcementService();

        var runtime =
            new FakeRuntimeController();

        var service =
            new TransferManualRuleService(
                repository,
                enforcement,
                new TransferEnforcementRuleFactory(
                    new FakePathNormalizer()),
                runtime);

        var expiresAt =
            DateTimeOffset.UtcNow.AddHours(
                2);

        var request =
            new TransferManualRuleRequest(
                "Temporary allow",
                TransferActivityKind.NetworkConnection,
                RuleDecision.Allow,
                [
                    new TransferManualRuleCondition(
                        RuleScope.ProcessPath,
                        @"C:\Apps\client.exe"),

                    new TransferManualRuleCondition(
                        RuleScope.RemoteAddress,
                        "1.1.1.1")
                ],
                100,
                expiresAt);

        var rule =
            await service.CreateAsync(
                request);

        Assert.Equal(
            expiresAt,
            rule.ExpiresAtUtc);
    }

    private static IReadOnlyList<SecurityRuleCondition> GetAllConditions(
        SecurityRule rule)
    {
        var conditions =
            new List<SecurityRuleCondition>
            {
                new(
                    rule.Scope,
                    rule.Value)
            };

        if (rule.Conditions is not null)
        {
            conditions.AddRange(
                rule.Conditions);
        }

        return conditions;
    }

    private sealed class FakeRuleRepository
        : IRuleRepository
    {
        public List<SecurityRule> Rules { get; } =
            [];

        public Task<IReadOnlyList<SecurityRule>> GetAllAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult<
                IReadOnlyList<SecurityRule>>(
                Rules);
        }

        public Task<IReadOnlyList<SecurityRule>> GetEnabledAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult<
                IReadOnlyList<SecurityRule>>(
                Rules
                    .Where(
                        rule =>
                            rule.Enabled)
                    .ToArray());
        }

        public Task<SecurityRule?> GetByIdAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                Rules.FirstOrDefault(
                    rule =>
                        rule.Id ==
                        id));
        }

        public Task UpsertAsync(
            SecurityRule rule,
            CancellationToken cancellationToken = default)
        {
            var index =
                Rules.FindIndex(
                    existing =>
                        existing.Id ==
                        rule.Id);

            if (index >= 0)
            {
                Rules[index] =
                    rule;
            }
            else
            {
                Rules.Add(
                    rule);
            }

            return Task.CompletedTask;
        }

        public Task DeleteAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            Rules.RemoveAll(
                rule =>
                    rule.Id ==
                    id);

            return Task.CompletedTask;
        }
    }

    private sealed class FakeEnforcementService
        : ITransferEnforcementService
    {
        public bool AddBlockWasCalled { get; private set; }

        public TransferEnforcementRule? LastAddedRule { get; private set; }

        public Task<TransferEnforcementResult> AddBlockAsync(
            TransferEnforcementRule rule,
            CancellationToken cancellationToken = default)
        {
            AddBlockWasCalled =
                true;

            LastAddedRule =
                rule;

            return Task.FromResult(
                new TransferEnforcementResult(
                    true,
                    "Applied"));
        }

        public Task RemoveBlockAsync(
            Guid securityRuleId,
            CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }

        public Task<TransferEnforcementSnapshot> InspectAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                new TransferEnforcementSnapshot(
                    new HashSet<Guid>(),
                    new HashSet<Guid>()));
        }
    }

    private sealed class FakeRuntimeController
        : ITransferGuardRuntimeController
    {
        public TransferGuardSettings CurrentSettings { get; set; } =
            TransferGuardSettings.Default;

        public string? EnforcementFailure { get; private set; }

        public Task ApplyAsync(
            TransferGuardSettings settings,
            CancellationToken cancellationToken = default)
        {
            CurrentSettings =
                settings;

            return Task.CompletedTask;
        }

        public Task ReportEnforcementFailureAsync(
            string message,
            CancellationToken cancellationToken = default)
        {
            EnforcementFailure =
                message;

            return Task.CompletedTask;
        }
    }

    private sealed class FakePathNormalizer
        : ITransferPathNormalizer
    {
        public string? Normalize(
            string? path)
        {
            return path;
        }
    }
}