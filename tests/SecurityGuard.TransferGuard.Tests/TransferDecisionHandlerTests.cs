using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Enums;
using SecurityGuard.TransferGuard.Models;
using SecurityGuard.TransferGuard.Services;

namespace SecurityGuard.TransferGuard.Tests;

public sealed class TransferDecisionHandlerTests
{
    [Fact]
    public async Task Block_in_monitor_mode_does_not_apply_firewall()
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

        var handler =
            new TransferDecisionHandler(
                repository,
                enforcement,
                new TransferEnforcementRuleFactory(
                    new FakePathNormalizer()),
                runtime);

        var request =
            CreateRequest();

        await handler.HandleAsync(
            request,
            new SecurityDecision(
                request.Id,
                SecurityAction.Block,
                true,
                DateTimeOffset.UtcNow));

        Assert.False(
            enforcement.WasCalled);

        var rule =
            Assert.Single(
                repository.Rules);

        Assert.Equal(
            RuleDecision.Block,
            rule.Decision);
    }

    [Fact]
    public async Task Block_in_enforce_mode_applies_firewall()
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

        var handler =
            new TransferDecisionHandler(
                repository,
                enforcement,
                new TransferEnforcementRuleFactory(
                    new FakePathNormalizer()),
                runtime);

        var request =
            CreateRequest();

        await handler.HandleAsync(
            request,
            new SecurityDecision(
                request.Id,
                SecurityAction.Block,
                true,
                DateTimeOffset.UtcNow));

        Assert.True(
            enforcement.WasCalled);

        Assert.Single(
            repository.Rules);
    }

    private static SecurityDecisionRequest CreateRequest()
    {
        return new SecurityDecisionRequest(
            Guid.NewGuid(),
            SecurityModuleKind.TransferGuard,
            SecurityEventType.NetworkConnection,
            "Unknown outbound connection",
            "client.exe → 1.1.1.1:443",
            null,
            "client.exe",
            [
                SecurityAction.Allow,
                SecurityAction.Block
            ],
            DateTimeOffset.UtcNow,
            new RuleMatchContext(
                Process:
                    "client.exe",
                ProcessPath:
                    @"C:\Apps\client.exe",
                RemoteAddress:
                    "1.1.1.1",
                RemotePort:
                    443,
                Protocol:
                    "Tcp"),
            "NET:TEST");
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

    private sealed class FakeEnforcementService
        : ITransferEnforcementService
    {
        public bool WasCalled { get; private set; }

        public Task<TransferEnforcementResult> AddBlockAsync(
            TransferEnforcementRule rule,
            CancellationToken cancellationToken = default)
        {
            WasCalled =
                true;

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

    private sealed class FakePathNormalizer
        : ITransferPathNormalizer
    {
        public string? Normalize(
            string? path)
        {
            return path;
        }
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
                        rule.Id == id));
        }

        public Task UpsertAsync(
            SecurityRule rule,
            CancellationToken cancellationToken = default)
        {
            Rules.RemoveAll(
                existing =>
                    existing.Id ==
                    rule.Id);

            Rules.Add(
                rule);

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

    [Fact]
    public async Task File_transfer_block_creates_file_rule_without_firewall()
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

        var handler =
            new TransferDecisionHandler(
                repository,
                enforcement,
                new TransferEnforcementRuleFactory(
                    new FakePathNormalizer()),
                runtime);

        var request =
            new SecurityDecisionRequest(
                Guid.NewGuid(),
                SecurityModuleKind.TransferGuard,
                SecurityEventType.FileTransfer,
                "Possible file transfer",
                "report.pdf → 1.1.1.1:443",
                @"C:\Users\Ivan\Documents\report.pdf",
                "client.exe",
                [
                    SecurityAction.Allow,
                    SecurityAction.Block
                ],
                DateTimeOffset.UtcNow,
                new RuleMatchContext(
                    FileHash:
                        "ABC123",
                    FilePath:
                        @"C:\Users\Ivan\Documents\report.pdf",
                    FileName:
                        "report.pdf",
                    FileExtension:
                        ".pdf",
                    FileCategory:
                        "Document",
                    Process:
                        "client.exe",
                    ProcessPath:
                        @"C:\Apps\client.exe",
                    RemoteAddress:
                        "1.1.1.1",
                    RemotePort:
                        443,
                    Protocol:
                        "Tcp",
                    TransferActivityKind:
                        "FileTransfer"),
                "FILEXFER:TEST");

        await handler.HandleAsync(
            request,
            new SecurityDecision(
                request.Id,
                SecurityAction.Block,
                true,
                DateTimeOffset.UtcNow));

        Assert.False(
            enforcement.WasCalled);

        var rule =
            Assert.Single(
                repository.Rules);

        Assert.Equal(
            RuleDecision.Block,
            rule.Decision);

        Assert.Equal(
            RuleScope.FileHash,
            rule.Scope);

        Assert.Equal(
            "ABC123",
            rule.Value);

        Assert.Contains(
            rule.Conditions!,
            condition =>
                condition.Scope ==
                    RuleScope.TransferActivityKind &&
                condition.Value ==
                    "FileTransfer");

        Assert.Contains(
            rule.Conditions!,
            condition =>
                condition.Scope ==
                    RuleScope.ProcessPath &&
                condition.Value ==
                    @"C:\Apps\client.exe");
    }
}