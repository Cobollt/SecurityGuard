using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.AlgorithmGuard.Enums;
using SecurityGuard.AlgorithmGuard.Models;
using SecurityGuard.AlgorithmGuard.Services;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;

namespace SecurityGuard.AlgorithmGuard.Tests;

public sealed class AlgorithmRuleLifecycleHandlerTests
{
    [Fact]
    public async Task Block_rule_removes_enforcement()
    {
        var enforcement =
            new RecordingEnforcementService();

        var handler =
            new AlgorithmRuleLifecycleHandler(
                enforcement);

        var rule =
            new SecurityRule(
                Guid.NewGuid(),
                "Blocked",
                SecurityModuleKind.AlgorithmGuard,
                RuleDecision.Block,
                RuleScope.FileHash,
                "ABC",
                true,
                200,
                DateTimeOffset.UtcNow,
                null);

        await handler.BeforeDeleteAsync(
            rule);

        Assert.Equal(
            rule.Id,
            enforcement.RemovedRuleId);
    }

    [Fact]
    public async Task Allow_rule_does_not_remove_enforcement()
    {
        var enforcement =
            new RecordingEnforcementService();

        var handler =
            new AlgorithmRuleLifecycleHandler(
                enforcement);

        var rule =
            new SecurityRule(
                Guid.NewGuid(),
                "Allowed",
                SecurityModuleKind.AlgorithmGuard,
                RuleDecision.Allow,
                RuleScope.FileHash,
                "ABC",
                true,
                100,
                DateTimeOffset.UtcNow,
                null);

        await handler.BeforeDeleteAsync(
            rule);

        Assert.Null(
            enforcement.RemovedRuleId);
    }

    private sealed class RecordingEnforcementService
        : IAlgorithmEnforcementService
    {
        public Guid? RemovedRuleId { get; private set; }

        public AlgorithmEnforcementLevel GetLevel(
            string? filePath)
        {
            return AlgorithmEnforcementLevel.AppLockerBlocked;
        }

        public Task<AlgorithmEnforcementResult> AddBlockAsync(
            Guid securityRuleId,
            string filePath,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                new AlgorithmEnforcementResult(
                    true,
                    AlgorithmEnforcementLevel.AppLockerBlocked,
                    "Applied"));
        }

        public Task RemoveBlockAsync(
            Guid securityRuleId,
            CancellationToken cancellationToken = default)
        {
            RemovedRuleId =
                securityRuleId;

            return Task.CompletedTask;
        }

        public Task<AlgorithmEnforcementSnapshot> InspectAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                new AlgorithmEnforcementSnapshot(
                    new HashSet<Guid>(),
                    new HashSet<Guid>(),
                    false,
                    false));
        }
    }
}