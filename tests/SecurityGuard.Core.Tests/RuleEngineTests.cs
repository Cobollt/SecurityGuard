using Xunit;

using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.Core.Services;

namespace SecurityGuard.Core.Tests;

public sealed class RuleEngineTests
{
    [Fact]
    public async Task No_rules_returns_no_match()
    {
        var repository = new FakeRuleRepository([]);

        var engine = new RuleEngine(repository);

        var result = await engine.EvaluateAsync(
            SecurityModuleKind.AlgorithmGuard,
            new RuleMatchContext(
                FileHash: "ABC"));

        Assert.False(result.Matched);
        Assert.Null(result.Decision);
    }

    [Fact]
    public async Task Higher_priority_rule_wins()
    {
        var rules = new[]
        {
            CreateRule(
                "Allow",
                RuleDecision.Allow,
                100),

            CreateRule(
                "Block",
                RuleDecision.Block,
                200)
        };

        var engine = new RuleEngine(
            new FakeRuleRepository(rules));

        var result = await engine.EvaluateAsync(
            SecurityModuleKind.AlgorithmGuard,
            new RuleMatchContext(
                FileHash: "ABC"));

        Assert.True(result.Matched);

        Assert.Equal(
            RuleDecision.Block,
            result.Decision);
    }

    [Fact]
    public async Task Block_wins_with_equal_priority()
    {
        var rules = new[]
        {
            CreateRule(
                "Allow",
                RuleDecision.Allow,
                100),

            CreateRule(
                "Block",
                RuleDecision.Block,
                100)
        };

        var engine = new RuleEngine(
            new FakeRuleRepository(rules));

        var result = await engine.EvaluateAsync(
            SecurityModuleKind.AlgorithmGuard,
            new RuleMatchContext(
                FileHash: "ABC"));

        Assert.Equal(
            RuleDecision.Block,
            result.Decision);
    }

    private static SecurityRule CreateRule(
        string name,
        RuleDecision decision,
        int priority)
    {
        return new SecurityRule(
            Guid.NewGuid(),
            name,
            SecurityModuleKind.AlgorithmGuard,
            decision,
            RuleScope.FileHash,
            "ABC",
            true,
            priority,
            DateTimeOffset.UtcNow,
            null);
    }

    private sealed class FakeRuleRepository
        : IRuleRepository
    {
        private readonly IReadOnlyList<SecurityRule> _rules;

        public FakeRuleRepository(
            IReadOnlyList<SecurityRule> rules)
        {
            _rules = rules;
        }

        public Task<IReadOnlyList<SecurityRule>>
            GetEnabledAsync(
                CancellationToken cancellationToken = default)
        {
            return Task.FromResult(_rules);
        }

        public Task UpsertAsync(
            SecurityRule rule,
            CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }

        public Task DeleteAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }
    }
}