using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.Storage.Repositories;

namespace SecurityGuard.Storage.Tests;

public sealed class ScanResultRepositoryTests
{
    [Fact]
    public async Task Latest_scan_can_be_found_by_hash()
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
                started.AddSeconds(1));

        await repository.AddAsync(result);

        var stored =
            await repository.GetLatestByHashAsync(
                "ABC123");

        Assert.NotNull(stored);

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
}