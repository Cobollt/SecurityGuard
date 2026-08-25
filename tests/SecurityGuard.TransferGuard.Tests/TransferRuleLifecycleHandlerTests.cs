using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Models;
using SecurityGuard.TransferGuard.Services;

namespace SecurityGuard.TransferGuard.Tests;

public sealed class TransferRuleLifecycleHandlerTests
{
    [Fact]
    public async Task Block_rule_removes_firewall_enforcement()
    {
        var enforcement =
            new RecordingEnforcementService();

        var handler =
            new TransferRuleLifecycleHandler(
                enforcement);

        var rule =
            new SecurityRule(
                Guid.NewGuid(),
                "Block",
                SecurityModuleKind.TransferGuard,
                RuleDecision.Block,
                RuleScope.ProcessPath,
                @"C:\Apps\client.exe",
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

    private sealed class RecordingEnforcementService
        : ITransferEnforcementService
    {
        public Guid? RemovedRuleId { get; private set; }

        public Task<TransferEnforcementResult> AddBlockAsync(
            TransferEnforcementRule rule,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                new TransferEnforcementResult(
                    true,
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

        public Task<TransferEnforcementSnapshot> InspectAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                new TransferEnforcementSnapshot(
                    new HashSet<Guid>(),
                    new HashSet<Guid>()));
        }
    }
}