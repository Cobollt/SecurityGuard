using SecurityGuard.Core.Models;
using SecurityGuard.Storage.Repositories;

namespace SecurityGuard.Storage.Tests;

public sealed class QuarantineRepositoryTests
{
    [Fact]
    public async Task Quarantine_record_can_be_saved()
    {
        await using var database =
            await TestDatabase.CreateAsync();

        var repository =
            new SqliteQuarantineRepository(
                database.ConnectionFactory);

        var record =
            new QuarantineRecord(
                Guid.NewGuid(),
                @"C:\Downloads\test.ps1",
                @"C:\ProgramData\SecurityGuard\Quarantine\Q001.sgq",
                "test.ps1",
                "ABC123",
                512,
                "AlgorithmGuard",
                "Unauthorized execution",
                DateTimeOffset.UtcNow);

        await repository.AddAsync(record);

        var stored =
            await repository.GetByIdAsync(
                record.Id);

        Assert.NotNull(stored);

        Assert.Equal(
            record.Sha256,
            stored.Sha256);

        Assert.Equal(
            "AlgorithmGuard",
            stored.SourceModule);
    }
}