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

    private sealed class RecordingTemporaryEnforcementService
        : ITransferTemporaryEnforcementService
    {
        public Guid? RemovedSourceRuleId { get; private set; }

        public Task<TransferTemporaryEnforcementResult> AddOrRefreshAsync(
            TransferTemporaryEnforcementRule rule,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                new TransferTemporaryEnforcementResult(
                    true,
                    "Applied",
                    rule.ExpiresAtUtc));
        }

        public Task RemoveAsync(
            Guid ruleId,
            CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }

        public Task<int> RemoveBySourceRuleIdAsync(
            Guid sourceSecurityRuleId,
            CancellationToken cancellationToken = default)
        {
            RemovedSourceRuleId =
                sourceSecurityRuleId;

            return Task.FromResult(
                1);
        }

        public Task<int> CleanupExpiredAsync(
            DateTimeOffset nowUtc,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                0);
        }

        public Task<int> RemoveAllAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                0);
        }
    }

    [Fact]
    public async Task File_block_removes_linked_temporary_enforcement()
    {
        var permanent =
            new RecordingEnforcementService();

        var temporary =
            new RecordingTemporaryEnforcementService();

        var handler =
            new TransferRuleLifecycleHandler(
                enforcement,
                temporary);

        var rule =
            new SecurityRule(
                Guid.NewGuid(),
                "Block document",
                SecurityModuleKind.TransferGuard,
                RuleDecision.Block,
                RuleScope.FileExtension,
                ".docx",
                true,
                250,
                DateTimeOffset.UtcNow,
                null,
                [
                    new SecurityRuleCondition(
                        RuleScope.TransferActivityKind,
                        "FileTransfer")
                ]);

        await handler.BeforeDeleteAsync(
            rule);

        Assert.Equal(
            rule.Id,
            enforcement.RemovedRuleId);

        Assert.Null(
            temporary.RemovedSourceRuleId);
    }
}