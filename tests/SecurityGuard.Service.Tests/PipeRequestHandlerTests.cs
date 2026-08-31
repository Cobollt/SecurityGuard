using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Ipc;
using SecurityGuard.Core.Models;
using SecurityGuard.Service.Ipc;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Enums;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.Service.Tests;

public sealed class PipeRequestHandlerTests
{
    [Fact]
    public async Task Ping_returns_pong()
    {
        var handler =
            CreateHandler();

        var request =
            PipeRequest.Create(
                PipeMessageType.Ping);

        var response =
            await handler.HandleAsync(
                request);

        Assert.True(
            response.Success);

        Assert.Equal(
            "PONG",
            response.Payload);

        Assert.Equal(
            request.Id,
            response.RequestId);
    }

    [Fact]
    public async Task Snapshot_is_serialized()
    {
        var snapshot =
            new SecuritySnapshot(
                [],
                [],
                [],
                3,
                DateTimeOffset.UtcNow);

        var handler =
            new PipeRequestHandler(
                new FakeSnapshotService(
                    snapshot),
                new FakeDecisionService(),
                new FakeRuleManagementService(),
                new FakeAlgorithmGuardSettingsCoordinator(),
                new FakeTransferGuardSettingsCoordinator(),
                new FakeTransferManualRuleService());

        var request =
            PipeRequest.Create(
                PipeMessageType.GetSnapshot);

        var response =
            await handler.HandleAsync(
                request);

        Assert.True(
            response.Success);

        Assert.NotNull(
            response.Payload);

        var restored =
            PipeJsonSerializer.Deserialize<SecuritySnapshot>(
                response.Payload);

        Assert.Equal(
            3,
            restored.QuarantineCount);
    }

    [Fact]
    public async Task Decision_is_forwarded()
    {
        var decisionService =
            new FakeDecisionService();

        var handler =
            new PipeRequestHandler(
                new FakeSnapshotService(
                    CreateEmptySnapshot()),
                decisionService,
                new FakeRuleManagementService(),
                new FakeAlgorithmGuardSettingsCoordinator(),
                new FakeTransferGuardSettingsCoordinator(),
                new FakeTransferManualRuleService());

        var decision =
            new SecurityDecision(
                Guid.NewGuid(),
                SecurityGuard.Core.Enums.SecurityAction.AllowOnce,
                false,
                DateTimeOffset.UtcNow);

        var request =
            PipeRequest.Create(
                PipeMessageType.SubmitDecision,
                PipeJsonSerializer.Serialize(
                    decision));

        var response =
            await handler.HandleAsync(
                request);

        Assert.True(
            response.Success);

        Assert.NotNull(
            decisionService.Decision);

        Assert.Equal(
            decision.RequestId,
            decisionService.Decision.RequestId);
    }

    [Fact]
    public async Task Missing_decision_payload_is_rejected()
    {
        var handler =
            CreateHandler();

        var request =
            PipeRequest.Create(
                PipeMessageType.SubmitDecision);

        var response =
            await handler.HandleAsync(
                request);

        Assert.False(
            response.Success);

        Assert.Equal(
            "Decision payload is required.",
            response.Error);
    }

    [Fact]
    public async Task Rules_are_returned()
    {
        var rule =
            new SecurityRule(
                Guid.NewGuid(),
                "Blocked script",
                SecurityGuard.Core.Enums.SecurityModuleKind.AlgorithmGuard,
                SecurityGuard.Core.Enums.RuleDecision.Block,
                SecurityGuard.Core.Enums.RuleScope.FileHash,
                "ABC",
                true,
                200,
                DateTimeOffset.UtcNow,
                null);

        var ruleService =
            new FakeRuleManagementService
            {
                Rules =
                [
                    rule
                ]
            };

        var handler =
            new PipeRequestHandler(
                new FakeSnapshotService(
                    CreateEmptySnapshot()),
                new FakeDecisionService(),
                ruleService,
                new FakeAlgorithmGuardSettingsCoordinator(),
                new FakeTransferGuardSettingsCoordinator(),
                new FakeTransferManualRuleService());

        var request =
            PipeRequest.Create(
                PipeMessageType.GetRules);

        var response =
            await handler.HandleAsync(
                request);

        Assert.True(
            response.Success);

        Assert.NotNull(
            response.Payload);

        var rules =
            PipeJsonSerializer.Deserialize<List<SecurityRule>>(
                response.Payload);

        var restored =
            Assert.Single(
                rules);

        Assert.Equal(
            rule.Id,
            restored.Id);
    }

    [Fact]
    public async Task Delete_rule_is_forwarded()
    {
        var ruleId =
            Guid.NewGuid();

        var ruleService =
            new FakeRuleManagementService();

        var handler =
            new PipeRequestHandler(
                new FakeSnapshotService(
                    CreateEmptySnapshot()),
                new FakeDecisionService(),
                ruleService,
                new FakeAlgorithmGuardSettingsCoordinator(),
                new FakeTransferGuardSettingsCoordinator(),
                new FakeTransferManualRuleService());

        var payload =
            new DeleteSecurityRuleRequest(
                ruleId);

        var request =
            PipeRequest.Create(
                PipeMessageType.DeleteRule,
                PipeJsonSerializer.Serialize(
                    payload));

        var response =
            await handler.HandleAsync(
                request);

        Assert.True(
            response.Success);

        Assert.Equal(
            ruleId,
            ruleService.DeletedRuleId);
    }

    [Fact]
    public async Task Algorithm_guard_settings_are_returned()
    {
        var settings =
            new SecurityGuard.AlgorithmGuard.Models.AlgorithmGuardSettings(
                true,
                SecurityGuard.AlgorithmGuard.Enums.AlgorithmGuardMode.Enforce,
                SecurityGuard.AlgorithmGuard.Enums.EnforcementFailurePolicy.FailClosed);

        var coordinator =
            new FakeAlgorithmGuardSettingsCoordinator
            {
                Settings =
                    settings
            };

        var handler =
            new PipeRequestHandler(
                new FakeSnapshotService(
                    CreateEmptySnapshot()),
                new FakeDecisionService(),
                new FakeRuleManagementService(),
                coordinator,
                new FakeTransferGuardSettingsCoordinator(),
                new FakeTransferManualRuleService());

        var request =
            PipeRequest.Create(
                PipeMessageType.GetAlgorithmGuardSettings);

        var response =
            await handler.HandleAsync(
                request);

        Assert.True(
            response.Success);

        Assert.NotNull(
            response.Payload);

        var restored =
            PipeJsonSerializer.Deserialize<
                SecurityGuard.AlgorithmGuard.Models.AlgorithmGuardSettings>(
                    response.Payload);

        Assert.Equal(
            settings,
            restored);
    }

    [Fact]
    public async Task Transfer_guard_settings_are_returned()
    {
        var expected =
            new TransferGuardSettings(
                true,
                TransferGuardMode.Enforce,
                TransferEnforcementFailurePolicy.FailClosed);

        var transferSettings =
            new FakeTransferGuardSettingsCoordinator
            {
                Settings =
                    expected
            };

        var handler =
            new PipeRequestHandler(
                new FakeSnapshotService(
                    CreateEmptySnapshot()),
                new FakeDecisionService(),
                new FakeRuleManagementService(),
                new FakeAlgorithmGuardSettingsCoordinator(),
                transferSettings,
                new FakeTransferManualRuleService());

        var request =
            PipeRequest.Create(
                PipeMessageType.GetTransferGuardSettings);

        var response =
            await handler.HandleAsync(
                request);

        Assert.True(
            response.Success);

        Assert.NotNull(
            response.Payload);

        var restored =
            PipeJsonSerializer.Deserialize<TransferGuardSettings>(
                response.Payload);

        Assert.Equal(
            expected,
            restored);
    }

    private static PipeRequestHandler CreateHandler()
    {
        return new PipeRequestHandler(
            new FakeSnapshotService(
                CreateEmptySnapshot()),
            new FakeDecisionService(),
            new FakeRuleManagementService(),
            new FakeAlgorithmGuardSettingsCoordinator(),
            new FakeTransferGuardSettingsCoordinator(),
            new FakeTransferManualRuleService());
    }

    private static SecuritySnapshot CreateEmptySnapshot()
    {
        return new SecuritySnapshot(
            [],
            [],
            [],
            0,
            DateTimeOffset.UtcNow);
    }

    private sealed class FakeSnapshotService
        : ISecuritySnapshotService
    {
        private readonly SecuritySnapshot _snapshot;

        public FakeSnapshotService(
            SecuritySnapshot snapshot)
        {
            _snapshot =
                snapshot;
        }

        public Task<SecuritySnapshot> GetAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                _snapshot);
        }
    }

    private sealed class FakeDecisionService
        : ISecurityDecisionService
    {
        public SecurityDecision? Decision { get; private set; }

        public Task ApplyAsync(
            SecurityDecision decision,
            CancellationToken cancellationToken = default)
        {
            Decision =
                decision;

            return Task.CompletedTask;
        }
    }

    private sealed class FakeRuleManagementService
        : IRuleManagementService
    {
        public IReadOnlyList<SecurityRule> Rules { get; set; } =
            [];

        public Guid? DeletedRuleId { get; private set; }

        public Task<IReadOnlyList<SecurityRule>> GetAllAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                Rules);
        }

        public Task DeleteAsync(
            Guid ruleId,
            CancellationToken cancellationToken = default)
        {
            DeletedRuleId =
                ruleId;

            return Task.CompletedTask;
        }
    }

    private sealed class FakeAlgorithmGuardSettingsCoordinator
        : SecurityGuard.AlgorithmGuard.Contracts.IAlgorithmGuardSettingsCoordinator
    {
        public SecurityGuard.AlgorithmGuard.Models.AlgorithmGuardSettings Settings { get; set; } =
            SecurityGuard.AlgorithmGuard.Models.AlgorithmGuardSettings.Default;

        public Task<SecurityGuard.AlgorithmGuard.Models.AlgorithmGuardSettings> GetAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                Settings);
        }

        public Task UpdateAsync(
            SecurityGuard.AlgorithmGuard.Models.AlgorithmGuardSettings settings,
            CancellationToken cancellationToken = default)
        {
            Settings =
                settings;

            return Task.CompletedTask;
        }
    }

    private sealed class FakeTransferGuardSettingsCoordinator
        : ITransferGuardSettingsCoordinator
    {
        public TransferGuardSettings Settings { get; set; } =
            TransferGuardSettings.Default;

        public Task<TransferGuardSettings> GetAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                Settings);
        }

        public Task UpdateAsync(
            TransferGuardSettings settings,
            CancellationToken cancellationToken = default)
        {
            Settings =
                settings;

            return Task.CompletedTask;
        }
    }

    private sealed class FakeTransferManualRuleService
        : ITransferManualRuleService
    {
        public TransferManualRuleRequest? LastRequest { get; private set; }

        public Task<SecurityRule> CreateAsync(
            TransferManualRuleRequest request,
            CancellationToken cancellationToken = default)
        {
            LastRequest =
                request;

            var primary =
                request.Conditions[0];

            return Task.FromResult(
                new SecurityRule(
                    Guid.NewGuid(),
                    request.Name,
                    SecurityModuleKind.TransferGuard,
                    request.Decision,
                    primary.Scope,
                    primary.Value,
                    true,
                    request.Priority,
                    DateTimeOffset.UtcNow,
                    request.ExpiresAtUtc));
        }
    }

    [Fact]
    public async Task Transfer_rule_can_be_created()
    {
        var service =
            new FakeTransferManualRuleService();

        var handler =
            new PipeRequestHandler(
                new FakeSnapshotService(
                    CreateEmptySnapshot()),
                new FakeDecisionService(),
                new FakeRuleManagementService(),
                new FakeAlgorithmGuardSettingsCoordinator(),
                new FakeTransferGuardSettingsCoordinator(),
                service);

        var model =
            new TransferManualRuleRequest(
                "Block DOCX",
                TransferActivityKind.FileTransfer,
                RuleDecision.Block,
                [
                    new TransferManualRuleCondition(
                        RuleScope.FileExtension,
                        ".docx")
                ],
                300,
                null);

        var request =
            PipeRequest.Create(
                PipeMessageType.CreateTransferGuardRule,
                PipeJsonSerializer.Serialize(
                    model));

        var response =
            await handler.HandleAsync(
                request);

        Assert.True(
            response.Success);

        Assert.NotNull(
            service.LastRequest);

        Assert.Equal(
            "Block DOCX",
            service.LastRequest.Name);
    }
}