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

        var stored =
            Assert.Single(rules);

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

    [Fact]
    public async Task Rule_can_be_loaded_by_id()
    {
        await using var database =
            await TestDatabase.CreateAsync();

        var repository =
            new SqliteRuleRepository(
                database.ConnectionFactory);

        var ruleId =
            Guid.NewGuid();

        var rule =
            new SecurityRule(
                ruleId,
                "Test rule",
                SecurityModuleKind.AlgorithmGuard,
                RuleDecision.Block,
                RuleScope.FilePath,
                "test.ps1",
                true,
                100,
                DateTimeOffset.UtcNow,
                null);

        await repository.UpsertAsync(rule);

        var loaded =
            await repository.GetByIdAsync(
                ruleId);

        Assert.NotNull(loaded);

        Assert.Equal(
            ruleId,
            loaded.Id);

        Assert.Equal(
            RuleDecision.Block,
            loaded.Decision);

        Assert.Equal(
            RuleScope.FilePath,
            loaded.Scope);

        Assert.Equal(
            "test.ps1",
            loaded.Value);
    }

    [Fact]
    public async Task Get_all_returns_disabled_rules_too()
    {
        await using var database =
            await TestDatabase.CreateAsync();

        var repository =
            new SqliteRuleRepository(
                database.ConnectionFactory);

        var enabledRule =
            new SecurityRule(
                Guid.NewGuid(),
                "Enabled rule",
                SecurityModuleKind.AlgorithmGuard,
                RuleDecision.Block,
                RuleScope.FilePath,
                "enabled.ps1",
                true,
                100,
                DateTimeOffset.UtcNow,
                null);

        var disabledRule =
            new SecurityRule(
                Guid.NewGuid(),
                "Disabled rule",
                SecurityModuleKind.AlgorithmGuard,
                RuleDecision.Block,
                RuleScope.FilePath,
                "disabled.ps1",
                false,
                100,
                DateTimeOffset.UtcNow,
                null);

        await repository.UpsertAsync(
            enabledRule);

        await repository.UpsertAsync(
            disabledRule);

        var rules =
            await repository.GetAllAsync();

        Assert.Contains(
            rules,
            rule =>
                rule.Id ==
                enabledRule.Id);

        Assert.Contains(
            rules,
            rule =>
                rule.Id ==
                disabledRule.Id);
    }

    [Fact]
    public async Task Compound_rule_is_saved_and_loaded()
    {
        await using var database =
            await TestDatabase.CreateAsync();

        var repository =
            new SqliteRuleRepository(
                database.ConnectionFactory);

        var rule =
            new SecurityRule(
                Guid.NewGuid(),
                "Compound allow",
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
                        RuleScope.ParentProcessPath,
                        @"C:\Program Files\Backup\backup.exe")
                ]);

        await repository.UpsertAsync(
            rule);

        var stored =
            await repository.GetByIdAsync(
                rule.Id);

        Assert.NotNull(
            stored);

        Assert.NotNull(
            stored.Conditions);

        Assert.Equal(
            2,
            stored.Conditions.Count);

        Assert.Contains(
            stored.Conditions,
            condition =>
                condition.Scope ==
                RuleScope.UserName &&
                condition.Value ==
                @"DESKTOP\User");
    }
}