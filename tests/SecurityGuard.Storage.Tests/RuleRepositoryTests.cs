using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.Storage.Repositories;

namespace SecurityGuard.Storage.Tests;

public sealed class RuleRepositoryTests
{
    [Fact]
    public async Task Rule_can_be_saved_and_loaded()
    {
        await using var database =
            await TestDatabase.CreateAsync();

        var repository =
            new SqliteRuleRepository(
                database.ConnectionFactory);

        var rule =
            new SecurityRule(
                Guid.NewGuid(),
                "Trusted script",
                SecurityModuleKind.AlgorithmGuard,
                RuleDecision.Allow,
                RuleScope.FileHash,
                "ABC123",
                true,
                100,
                DateTimeOffset.UtcNow,
                null);

        await repository.UpsertAsync(rule);

        var rules =
            await repository.GetEnabledAsync();

        var stored = Assert.Single(rules);

        Assert.Equal(
            rule.Id,
            stored.Id);

        Assert.Equal(
            "ABC123",
            stored.Value);

        Assert.Equal(
            RuleDecision.Allow,
            stored.Decision);
    }

    [Fact]
    public async Task Disabled_rule_is_not_returned()
    {
        await using var database =
            await TestDatabase.CreateAsync();

        var repository =
            new SqliteRuleRepository(
                database.ConnectionFactory);

        var rule =
            new SecurityRule(
                Guid.NewGuid(),
                "Disabled",
                SecurityModuleKind.AlgorithmGuard,
                RuleDecision.Block,
                RuleScope.FileHash,
                "DEF456",
                false,
                100,
                DateTimeOffset.UtcNow,
                null);

        await repository.UpsertAsync(rule);

        var rules =
            await repository.GetEnabledAsync();

        Assert.Empty(rules);
    }
}