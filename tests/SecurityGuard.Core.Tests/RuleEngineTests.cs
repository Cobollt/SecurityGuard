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

        public Task<IReadOnlyList<SecurityRule>> GetAllAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                _rules);
        }

        public Task<SecurityRule?> GetByIdAsync(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                _rules.FirstOrDefault(
                    rule =>
                        rule.Id == id));
        }
    }

    [Fact]
    public async Task Command_line_rule_can_match()
    {
        var rule =
            new SecurityRule(
                Guid.NewGuid(),
                "Allowed command",
                SecurityModuleKind.AlgorithmGuard,
                RuleDecision.Allow,
                RuleScope.CommandLine,
                "powershell.exe -Command Get-Date",
                true,
                100,
                DateTimeOffset.UtcNow,
                null);

        var engine =
            new RuleEngine(
                new FakeRuleRepository(
                    [rule]));

        var result =
            await engine.EvaluateAsync(
                SecurityModuleKind.AlgorithmGuard,
                new RuleMatchContext(
                    CommandLine:
                        "powershell.exe -Command Get-Date"));

        Assert.True(
            result.Matched);

        Assert.Equal(
            RuleDecision.Allow,
            result.Decision);
    }

    [Fact]
    public async Task User_rule_can_match()
    {
        var rule =
            new SecurityRule(
                Guid.NewGuid(),
                "Allowed user",
                SecurityModuleKind.AlgorithmGuard,
                RuleDecision.Allow,
                RuleScope.UserName,
                @"DESKTOP\User",
                true,
                100,
                DateTimeOffset.UtcNow,
                null);

        var engine =
            new RuleEngine(
                new FakeRuleRepository(
                    [rule]));

        var result =
            await engine.EvaluateAsync(
                SecurityModuleKind.AlgorithmGuard,
                new RuleMatchContext(
                    UserName:
                        @"DESKTOP\User"));

        Assert.True(
            result.Matched);

        Assert.Equal(
            RuleDecision.Allow,
            result.Decision);
    }

    [Fact]
    public async Task Parent_process_path_rule_can_match()
    {
        var rule =
            new SecurityRule(
                Guid.NewGuid(),
                "Explorer parent",
                SecurityModuleKind.AlgorithmGuard,
                RuleDecision.Allow,
                RuleScope.ParentProcessPath,
                @"C:\Windows\explorer.exe",
                true,
                100,
                DateTimeOffset.UtcNow,
                null);

        var engine =
            new RuleEngine(
                new FakeRuleRepository(
                    [rule]));

        var result =
            await engine.EvaluateAsync(
                SecurityModuleKind.AlgorithmGuard,
                new RuleMatchContext(
                    ParentProcessPath:
                        @"C:\Windows\explorer.exe"));

        Assert.True(
            result.Matched);
    }

    [Fact]
public async Task Compound_rule_matches_when_all_conditions_match()
    {
        var rule =
            new SecurityRule(
                Guid.NewGuid(),
                "Trusted backup script",
                SecurityModuleKind.AlgorithmGuard,
                RuleDecision.Allow,
                RuleScope.FileHash,
                "ABC123",
                true,
                100,
                DateTimeOffset.UtcNow,
                null,
                [
                    new SecurityRuleCondition(
                        RuleScope.UserName,
                        @"DESKTOP\User"),

                    new SecurityRuleCondition(
                        RuleScope.ParentProcess,
                        "backup.exe")
                ]);

        var engine =
            new RuleEngine(
                new FakeRuleRepository(
                    [rule]));

        var result =
            await engine.EvaluateAsync(
                SecurityModuleKind.AlgorithmGuard,
                new RuleMatchContext(
                    FileHash:
                        "ABC123",
                    UserName:
                        @"DESKTOP\User",
                    ParentProcess:
                        "backup.exe"));

        Assert.True(
            result.Matched);

        Assert.Equal(
            RuleDecision.Allow,
            result.Decision);
    }

    [Fact]
    public async Task Compound_rule_does_not_match_when_one_condition_differs()
    {
        var rule =
            new SecurityRule(
                Guid.NewGuid(),
                "Trusted backup script",
                SecurityModuleKind.AlgorithmGuard,
                RuleDecision.Allow,
                RuleScope.FileHash,
                "ABC123",
                true,
                100,
                DateTimeOffset.UtcNow,
                null,
                [
                    new SecurityRuleCondition(
                        RuleScope.UserName,
                        @"DESKTOP\User"),

                    new SecurityRuleCondition(
                        RuleScope.ParentProcess,
                        "backup.exe")
                ]);

        var engine =
            new RuleEngine(
                new FakeRuleRepository(
                    [rule]));

        var result =
            await engine.EvaluateAsync(
                SecurityModuleKind.AlgorithmGuard,
                new RuleMatchContext(
                    FileHash:
                        "ABC123",
                    UserName:
                        @"DESKTOP\User",
                    ParentProcess:
                        "explorer.exe"));

        Assert.False(
            result.Matched);
    }
}