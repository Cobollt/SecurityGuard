using SecurityGuard.Core.Models;
using SecurityGuard.Storage.Repositories;

namespace SecurityGuard.Storage.Tests;

public sealed class SqliteThreatHashRepositoryTests
    : IAsyncLifetime
{
    private readonly string _root =
        Path.Combine(
            Path.GetTempPath(),
            "SecurityGuard.Storage.Tests",
            Guid.NewGuid().ToString("N"));

    private SqliteDatabase _database =
        null!;

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(
            _root);

        _database =
            new SqliteDatabase(
                Path.Combine(
                    _root,
                    "securityguard.db"));

        await _database.InitializeAsync();
    }

    public Task DisposeAsync()
    {
        if (Directory.Exists(
                _root))
        {
            Directory.Delete(
                _root,
                true);
        }

        return Task.CompletedTask;
    }

    [Fact]
    public async Task Threat_hash_can_be_saved_and_read()
    {
        var repository =
            new SqliteThreatHashRepository(
                _database);

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
    }

    [Fact]
    public async Task Threat_hash_can_be_deleted()
    {
        var repository =
            new SqliteThreatHashRepository(
                _database);

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
}