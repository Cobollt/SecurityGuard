using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.Service.Application;

namespace SecurityGuard.Service.Tests;

public sealed class SecurityRuleExpirationServiceTests
{
    [Fact]
    public async Task Only_expired_rules_are_removed()
    {
        var now =
            DateTimeOffset.UtcNow;

        var expired =
            CreateRule(
                now -
                TimeSpan.FromMinutes(1));

        var active =
            CreateRule(
                now +
                TimeSpan.FromMinutes(10));

        var repository =
            new FakeRuleRepository(
                [
                    expired,
                    active
                ]);

        var management =
            new RecordingRuleManagementService();

        var service =
            new SecurityRuleExpirationService(
                repository,
                management,
                new FakeAuditService());

        var removed =
            await service.RemoveExpiredAsync(
                now);

        Assert.Equal(
            1,
            removed);

        Assert.Contains(
            expired.Id,
            management.DeletedRuleIds);

        Assert.DoesNotContain(
            active.Id,
            management.DeletedRuleIds);
    }

    private static SecurityRule CreateRule(
        DateTimeOffset expiresAtUtc)
    {
        return new SecurityRule(
            Guid.NewGuid(),
            "Temporary rule",
            SecurityModuleKind.AlgorithmGuard,
            RuleDecision.Block,
            RuleScope.FileHash,
            Guid.NewGuid().ToString(
                "N"),
            true,
            100,
            DateTimeOffset.UtcNow,
            expiresAtUtc);
    }

    private sealed class FakeRuleRepository
        : IRuleRepository
    {
        private readonly List<SecurityRule> _rules;

        public FakeRuleRepository(
            IEnumerable<SecurityRule> rules)
        {
            _rules =
                rules.ToList();
        }

        public Task<IReadOnlyList<SecurityRule>> GetAllAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult<
                IReadOnlyList<SecurityRule>>(
                _rules.ToArray());
        }

        public Task<IReadOnlyList<SecurityRule>> GetEnabledAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            IReadOnlyList<SecurityRule> result =
                _rules
                    .Where(
                        rule =>
                            rule.Enabled)
                    .ToArray();

            return Task.FromResult(
                result);
        }

        public Task<SecurityRule?> GetByIdAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(
                _rules.FirstOrDefault(
                    rule =>
                        rule.Id ==
                        id));
        }

        public Task UpsertAsync(
            SecurityRule rule,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            _rules.RemoveAll(
                existing =>
                    existing.Id ==
                    rule.Id);

            _rules.Add(
                rule);

            return Task.CompletedTask;
        }

        public Task DeleteAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            _rules.RemoveAll(
                rule =>
                    rule.Id ==
                    id);

            return Task.CompletedTask;
        }
    }

    private sealed class RecordingRuleManagementService
        : IRuleManagementService
    {
        public List<Guid> DeletedRuleIds { get; } =
            [];

        public Task<IReadOnlyList<SecurityRule>> GetAllAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult<
                IReadOnlyList<SecurityRule>>(
                []);
        }

        public Task DeleteAsync(
            Guid ruleId,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            DeletedRuleIds.Add(
                ruleId);

            return Task.CompletedTask;
        }
    }

    private sealed class FakeAuditService
        : IAuditService
    {
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
            cancellationToken.ThrowIfCancellationRequested();

            return Task.CompletedTask;
        }
    }
}