using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Ipc;
using SecurityGuard.Core.Models;
using SecurityGuard.Service.Ipc;

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
                new FakeSnapshotService(snapshot),
                new FakeDecisionService(),
                new FakeRuleManagementService());

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
                decisionService);

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

    private static PipeRequestHandler CreateHandler()
    {
        return new PipeRequestHandler(
            new FakeSnapshotService(
                CreateEmptySnapshot()),
            new FakeDecisionService());
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
            _snapshot = snapshot;
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
            Decision = decision;

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
                ruleService);

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
            Assert.Single(rules);

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
                ruleService);

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
}