using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Lists;
using SecurityGuard.Core.Models;
using SecurityGuard.Storage.Repositories;

namespace SecurityGuard.Storage.Tests;

public sealed class SecurityListImportHistoryRepositoryTests
{
    [Fact]
    public async Task Import_creates_history_record()
    {
        await using var database =
            await TestDatabase.CreateAsync();

        var store =
            new SqliteSecurityListImportStore(
                database.ConnectionFactory);

        var history =
            new SqliteSecurityListImportHistoryRepository(
                database.ConnectionFactory);

        var fingerprint =
            new string(
                'A',
                64);

        var record =
            new SecurityListImportRecord(
                Guid.NewGuid(),
                fingerprint,
                "test.zip",
                @"C:\ProgramData\SecurityGuard\Lists\Imports\test.zip",
                SecurityListPackageFormat.PackageType,
                SecurityListPackageFormat.CurrentVersion,
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow,
                SecurityListImportMode.Merge,
                1,
                0,
                0);

        var rule =
            new SecurityRule(
                Guid.NewGuid(),
                "Imported rule",
                SecurityModuleKind.ArchiveGuard,
                RuleDecision.Block,
                RuleScope.FileHash,
                new string(
                    'B',
                    64),
                true,
                100,
                DateTimeOffset.UtcNow,
                null);

        await store.ImportAsync(
            [
                rule
            ],
            [],
            SecurityListImportMode.Merge,
            record);

        var result =
            await history.GetByPackageSha256Async(
                fingerprint);

        Assert.NotNull(
            result);

        Assert.Equal(
            fingerprint,
            result!.PackageSha256);

        Assert.Equal(
            1,
            result.RuleCount);
    }
}