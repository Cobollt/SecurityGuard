using SecurityGuard.Core.Models;
using SecurityGuard.Storage.Repositories;

namespace SecurityGuard.Storage.Tests;

public sealed class SqliteThreatHashRepositoryTests
{
    [Fact]
    public async Task Threat_hash_can_be_saved_and_read()
    {
        await using var database =
            await TestDatabase.CreateAsync();

        var repository =
            new SqliteThreatHashRepository(
                database.ConnectionFactory);

        var now =
            DateTimeOffset.UtcNow;

        var hash =
            new string(
                'A',
                64);

        await repository.UpsertAsync(
            new ThreatHashEntry(
                hash,
                "Manual",
                "Test hash",
                true,
                now,
                now));

        var result =
            await repository.GetBySha256Async(
                hash.ToLowerInvariant());

        Assert.NotNull(
            result);

        Assert.Equal(
            hash,
            result.Sha256);

        Assert.True(
            result.Enabled);

        Assert.Equal(
            "Manual",
            result.Source);
    }

    [Fact]
    public async Task Threat_hash_can_be_deleted()
    {
        await using var database =
            await TestDatabase.CreateAsync();

        var repository =
            new SqliteThreatHashRepository(
                database.ConnectionFactory);

        var now =
            DateTimeOffset.UtcNow;

        var hash =
            new string(
                'B',
                64);

        await repository.UpsertAsync(
            new ThreatHashEntry(
                hash,
                "Manual",
                null,
                true,
                now,
                now));

        await repository.DeleteAsync(
            hash);

        var result =
            await repository.GetBySha256Async(
                hash);

        Assert.Null(
            result);
    }

    [Fact]
    public async Task Threat_hash_upsert_updates_existing_entry()
    {
        await using var database =
            await TestDatabase.CreateAsync();

        var repository =
            new SqliteThreatHashRepository(
                database.ConnectionFactory);

        var hash =
            new string(
                'C',
                64);

        var created =
            DateTimeOffset.UtcNow;

        await repository.UpsertAsync(
            new ThreatHashEntry(
                hash,
                "Initial",
                "First",
                true,
                created,
                created));

        var updated =
            created.AddMinutes(
                5);

        await repository.UpsertAsync(
            new ThreatHashEntry(
                hash,
                "Updated",
                "Second",
                false,
                created,
                updated));

        var result =
            await repository.GetBySha256Async(
                hash);

        Assert.NotNull(
            result);

        Assert.Equal(
            "Updated",
            result.Source);

        Assert.Equal(
            "Second",
            result.Description);

        Assert.False(
            result.Enabled);

        Assert.Equal(
            created,
            result.CreatedAtUtc);

        Assert.Equal(
            updated,
            result.UpdatedAtUtc);
    }

    [Fact]
    public async Task Get_all_returns_all_hashes()
    {
        await using var database =
            await TestDatabase.CreateAsync();

        var repository =
            new SqliteThreatHashRepository(
                database.ConnectionFactory);

        var now =
            DateTimeOffset.UtcNow;

        await repository.UpsertAsync(
            new ThreatHashEntry(
                new string(
                    'D',
                    64),
                "Manual",
                null,
                true,
                now,
                now));

        await repository.UpsertAsync(
            new ThreatHashEntry(
                new string(
                    'E',
                    64),
                "Manual",
                null,
                true,
                now,
                now));

        var results =
            await repository.GetAllAsync();

        Assert.Equal(
            2,
            results.Count);
    }
}