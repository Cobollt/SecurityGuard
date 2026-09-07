using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.Storage.Repositories;

namespace SecurityGuard.Storage.Tests;

public sealed class ScanResultRepositoryTests
{
    [Fact]
    public async Task Scan_result_can_be_saved_and_read_by_id()
    {
        await using var database =
            await TestDatabase.CreateAsync();

        var repository =
            new SqliteScanResultRepository(
                database.ConnectionFactory);

        var started =
            DateTimeOffset.UtcNow;

        var result =
            new ScanResult(
                Guid.NewGuid(),
                @"C:\Temp\package.zip",
                "ABC123",
                ScanVerdict.Suspicious,
                65,
                [
                    "Nested executable",
                    "Suspicious script"
                ],
                started,
                started.AddSeconds(
                    1));

        await repository.UpsertAsync(
            result);

        var stored =
            await repository.GetByIdAsync(
                result.Id);

        Assert.NotNull(
            stored);

        Assert.Equal(
            result.Id,
            stored.Id);

        Assert.Equal(
            result.FilePath,
            stored.FilePath);

        Assert.Equal(
            result.Sha256,
            stored.Sha256);

        Assert.Equal(
            ScanVerdict.Suspicious,
            stored.Verdict);

        Assert.Equal(
            65,
            stored.RiskScore);

        Assert.Equal(
            2,
            stored.Findings.Count);
    }

    [Fact]
    public async Task Latest_scan_can_be_found_by_sha256()
    {
        await using var database =
            await TestDatabase.CreateAsync();

        var repository =
            new SqliteScanResultRepository(
                database.ConnectionFactory);

        var started =
            DateTimeOffset.UtcNow;

        var first =
            new ScanResult(
                Guid.NewGuid(),
                @"C:\Temp\package.zip",
                "ABC123",
                ScanVerdict.Clean,
                0,
                [],
                started,
                started.AddSeconds(
                    1));

        var second =
            new ScanResult(
                Guid.NewGuid(),
                @"C:\Temp\package.zip",
                "ABC123",
                ScanVerdict.Suspicious,
                65,
                [
                    "Nested executable"
                ],
                started.AddSeconds(
                    2),
                started.AddSeconds(
                    3));

        await repository.UpsertAsync(
            first);

        await repository.UpsertAsync(
            second);

        var stored =
            await repository.GetLatestBySha256Async(
                "ABC123");

        Assert.NotNull(
            stored);

        Assert.Equal(
            second.Id,
            stored.Id);

        Assert.Equal(
            ScanVerdict.Suspicious,
            stored.Verdict);
    }

    [Fact]
    public async Task Upsert_updates_existing_scan()
    {
        await using var database =
            await TestDatabase.CreateAsync();

        var repository =
            new SqliteScanResultRepository(
                database.ConnectionFactory);

        var started =
            DateTimeOffset.UtcNow;

        var id =
            Guid.NewGuid();

        await repository.UpsertAsync(
            new ScanResult(
                id,
                @"C:\Temp\package.zip",
                "ABC123",
                ScanVerdict.Clean,
                0,
                [],
                started,
                started.AddSeconds(
                    1)));

        await repository.UpsertAsync(
            new ScanResult(
                id,
                @"C:\Temp\package.zip",
                "ABC123",
                ScanVerdict.Malicious,
                100,
                [
                    "Known malicious hash"
                ],
                started,
                started.AddSeconds(
                    2)));

        var stored =
            await repository.GetByIdAsync(
                id);

        Assert.NotNull(
            stored);

        Assert.Equal(
            ScanVerdict.Malicious,
            stored.Verdict);

        Assert.Equal(
            100,
            stored.RiskScore);

        Assert.Single(
            stored.Findings);
    }

    [Fact]
    public async Task Recent_scans_are_returned_newest_first()
    {
        await using var database =
            await TestDatabase.CreateAsync();

        var repository =
            new SqliteScanResultRepository(
                database.ConnectionFactory);

        var started =
            DateTimeOffset.UtcNow;

        for (var index = 0;
             index < 3;
             index++)
        {
            await repository.UpsertAsync(
                new ScanResult(
                    Guid.NewGuid(),
                    $@"C:\Temp\file{index}.zip",
                    $"HASH{index}",
                    ScanVerdict.Clean,
                    0,
                    [],
                    started.AddSeconds(
                        index),
                    started.AddSeconds(
                        index)));
        }

        var results =
            await repository.GetRecentAsync(
                2);

        Assert.Equal(
            2,
            results.Count);

        Assert.Equal(
            "HASH2",
            results[0].Sha256);

        Assert.Equal(
            "HASH1",
            results[1].Sha256);
    }
}