using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Lists;
using SecurityGuard.Core.Models;
using SecurityGuard.Storage.Repositories;

namespace SecurityGuard.Storage.Tests;

public sealed class SecurityListImportStoreTests
{
    [Fact]
    public async Task Merge_imports_rules_conditions_and_hashes()
    {
        await using var database =
            await TestDatabase.CreateAsync();

        var store =
            new SqliteSecurityListImportStore(
                database.ConnectionFactory);

        var rules =
            new[]
            {
                new SecurityRule(
                    Guid.NewGuid(),
                    "Imported transfer rule",
                    SecurityModuleKind.TransferGuard,
                    RuleDecision.Block,
                    RuleScope.ProcessPath,
                    @"C:\Apps\sender.exe",
                    true,
                    200,
                    DateTimeOffset.UtcNow,
                    null,
                    [
                        new SecurityRuleCondition(
                            RuleScope.RemotePort,
                            "443"),

                        new SecurityRuleCondition(
                            RuleScope.Protocol,
                            "TCP")
                    ])
            };

        var hashes =
            new[]
            {
                new ThreatHashEntry(
                    new string(
                        'A',
                        64),
                    "Imported",
                    "Imported threat hash",
                    true,
                    DateTimeOffset.UtcNow,
                    DateTimeOffset.UtcNow)
            };

        var result =
            await store.ImportAsync(
                rules,
                hashes,
                SecurityListImportMode.Merge,
                CreateImportRecord(
                    rules.Length,
                    rules.Sum(
                        rule =>
                            rule.Conditions?.Count ??
                            0),
                    hashes.Length));

        Assert.Equal(
            1,
            result.RulesUpserted);

        Assert.Equal(
            1,
            result.ThreatHashesUpserted);

        var ruleRepository =
            new SqliteRuleRepository(
                database.ConnectionFactory);

        var importedRule =
            await ruleRepository.GetByIdAsync(
                rules[0].Id);

        Assert.NotNull(
            importedRule);

        Assert.Equal(
            2,
            importedRule!.Conditions?.Count);

        var threatRepository =
            new SqliteThreatHashRepository(
                database.ConnectionFactory);

        var importedHash =
            await threatRepository.GetBySha256Async(
                hashes[0].Sha256);

        Assert.NotNull(
            importedHash);

        Assert.Equal(
            "Imported",
            importedHash!.Source);
    }

    [Fact]
    public async Task Merge_keeps_unrelated_local_rules()
    {
        await using var database =
            await TestDatabase.CreateAsync();

        var repository =
            new SqliteRuleRepository(
                database.ConnectionFactory);

        var localRule =
            new SecurityRule(
                Guid.NewGuid(),
                "Local rule",
                SecurityModuleKind.ArchiveGuard,
                RuleDecision.Allow,
                RuleScope.FileHash,
                new string(
                    'B',
                    64),
                true,
                100,
                DateTimeOffset.UtcNow,
                null);

        await repository.UpsertAsync(
            localRule);

        var importedRule =
            new SecurityRule(
                Guid.NewGuid(),
                "Imported rule",
                SecurityModuleKind.ArchiveGuard,
                RuleDecision.Block,
                RuleScope.FileHash,
                new string(
                    'C',
                    64),
                true,
                200,
                DateTimeOffset.UtcNow,
                null);

        var store =
            new SqliteSecurityListImportStore(
                database.ConnectionFactory);

        await store.ImportAsync(
            [
                importedRule
            ],
            [],
            SecurityListImportMode.Merge,
            CreateImportRecord(
                1,
                0,
                0));

        Assert.NotNull(
            await repository.GetByIdAsync(
                localRule.Id));

        Assert.NotNull(
            await repository.GetByIdAsync(
                importedRule.Id));
    }

    [Fact]
    public async Task Merge_updates_rule_with_same_id()
    {
        await using var database =
            await TestDatabase.CreateAsync();

        var repository =
            new SqliteRuleRepository(
                database.ConnectionFactory);

        var id =
            Guid.NewGuid();

        var original =
            new SecurityRule(
                id,
                "Original",
                SecurityModuleKind.TransferGuard,
                RuleDecision.Allow,
                RuleScope.Process,
                "sender.exe",
                true,
                100,
                DateTimeOffset.UtcNow,
                null);

        await repository.UpsertAsync(
            original);

        var replacement =
            original with
            {
                Name =
                    "Imported replacement",

                Decision =
                    RuleDecision.Block,

                Priority =
                    500,

                Conditions =
                [
                    new SecurityRuleCondition(
                        RuleScope.RemotePort,
                        "443")
                ]
            };

        var store =
            new SqliteSecurityListImportStore(
                database.ConnectionFactory);

        await store.ImportAsync(
            [
                replacement
            ],
            [],
            SecurityListImportMode.Merge,
            CreateImportRecord(
                1,
                1,
                0));

        var result =
            await repository.GetByIdAsync(
                id);

        Assert.NotNull(
            result);

        Assert.Equal(
            "Imported replacement",
            result!.Name);

        Assert.Equal(
            RuleDecision.Block,
            result.Decision);

        Assert.Equal(
            500,
            result.Priority);

        Assert.Single(
            result.Conditions ??
            []);
    }

    private static SecurityListImportRecord CreateImportRecord(
        int ruleCount,
        int conditionCount,
        int hashCount)
    {
        return new SecurityListImportRecord(
            Guid.NewGuid(),
            Convert.ToHexString(
                Guid.NewGuid()
                    .ToByteArray()
                    .Concat(
                        Guid.NewGuid()
                            .ToByteArray())
                    .ToArray()),
            "test.zip",
            @"C:\ProgramData\SecurityGuard\Lists\Imports\test.zip",
            SecurityListPackageFormat.PackageType,
            SecurityListPackageFormat.CurrentVersion,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow,
            SecurityListImportMode.Merge,
            ruleCount,
            conditionCount,
            hashCount);
    }
}