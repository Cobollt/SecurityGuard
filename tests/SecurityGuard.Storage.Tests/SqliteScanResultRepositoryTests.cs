using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.Storage.Repositories;

namespace SecurityGuard.Storage.Tests;

public sealed class SqliteScanResultRepositoryTests
    : IAsyncLifetime
{
    private readonly string _root =
        Path.Combine(
            Path.GetTempPath(),
            "SecurityGuard.ScanResult.Tests",
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
    public async Task Scan_result_can_be_saved()
    {
        var repository =
            new SqliteScanResultRepository(
                _database);

        var now =
            DateTimeOffset.UtcNow;

        var result =
            new ScanResult(
                Guid.NewGuid(),
                SecurityModuleKind.ArchiveGuard,
                @"C:\Test\sample.exe",
                new string(
                    'A',
                    64),
                1024,
                ScanVerdict.Suspicious,
                "Test",
                now,
                now);

        await repository.UpsertAsync(
            result);

        var loaded =
            await repository.GetByIdAsync(
                result.Id);

        Assert.NotNull(
            loaded);

        Assert.Equal(
            result.Id,
            loaded.Id);

        Assert.Equal(
            result.Verdict,
            loaded.Verdict);

        Assert.Equal(
            result.Sha256,
            loaded.Sha256);
    }

    [Fact]
    public async Task Latest_result_can_be_found_by_hash()
    {
        var repository =
            new SqliteScanResultRepository(
                _database);

        var hash =
            new string(
                'B',
                64);

        var firstTime =
            DateTimeOffset.UtcNow -
            TimeSpan.FromMinutes(10);

        var secondTime =
            DateTimeOffset.UtcNow;

        await repository.UpsertAsync(
            new ScanResult(
                Guid.NewGuid(),
                SecurityModuleKind.ArchiveGuard,
                @"C:\Test\old.exe",
                hash,
                100,
                ScanVerdict.Suspicious,
                "Old",
                firstTime,
                firstTime));

        var latest =
            new ScanResult(
                Guid.NewGuid(),
                SecurityModuleKind.ArchiveGuard,
                @"C:\Test\new.exe",
                hash,
                100,
                ScanVerdict.Malicious,
                "New",
                secondTime,
                secondTime);

        await repository.UpsertAsync(
            latest);

        var result =
            await repository.GetLatestBySha256Async(
                hash);

        Assert.NotNull(
            result);

        Assert.Equal(
            latest.Id,
            result.Id);

        Assert.Equal(
            ScanVerdict.Malicious,
            result.Verdict);
    }
}