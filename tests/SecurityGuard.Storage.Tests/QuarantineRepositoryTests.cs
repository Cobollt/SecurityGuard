using SecurityGuard.Core.Models;
using SecurityGuard.Storage.Repositories;

namespace SecurityGuard.Storage.Tests;

public sealed class QuarantineRepositoryTests
{
    [Fact]
    public async Task Record_can_be_added_and_loaded()
    {
        await using var database =
            await TestDatabase.CreateAsync();

        var repository =
            new SqliteQuarantineRepository(
                database.ConnectionFactory);

        var record =
            CreateRecord();

        await repository.AddAsync(
            record);

        var loaded =
            await repository.GetByIdAsync(
                record.Id);

        Assert.NotNull(
            loaded);

        Assert.Equal(
            record,
            loaded);
    }

    [Fact]
    public async Task Get_all_returns_saved_records()
    {
        await using var database =
            await TestDatabase.CreateAsync();

        var repository =
            new SqliteQuarantineRepository(
                database.ConnectionFactory);

        var first =
            CreateRecord();

        var second =
            CreateRecord();

        await repository.AddAsync(
            first);

        await repository.AddAsync(
            second);

        var records =
            await repository.GetAllAsync();

        Assert.Contains(
            records,
            record => record.Id == first.Id);

        Assert.Contains(
            records,
            record => record.Id == second.Id);
    }

    [Fact]
    public async Task Count_returns_number_of_records()
    {
        await using var database =
            await TestDatabase.CreateAsync();

        var repository =
            new SqliteQuarantineRepository(
                database.ConnectionFactory);

        await repository.AddAsync(
            CreateRecord());

        await repository.AddAsync(
            CreateRecord());

        var count =
            await repository.CountAsync();

        Assert.Equal(
            2,
            count);
    }

    [Fact]
    public async Task Delete_removes_record()
    {
        await using var database =
            await TestDatabase.CreateAsync();

        var repository =
            new SqliteQuarantineRepository(
                database.ConnectionFactory);

        var record =
            CreateRecord();

        await repository.AddAsync(
            record);

        await repository.DeleteAsync(
            record.Id);

        var loaded =
            await repository.GetByIdAsync(
                record.Id);

        Assert.Null(
            loaded);
    }

    private static QuarantineRecord CreateRecord()
    {
        var id =
            Guid.NewGuid();

        return new QuarantineRecord(
            id,
            $"/tmp/source-{id:N}.bin",
            $"/tmp/quarantine/{id:N}.bin",
            $"source-{id:N}.bin",
            id.ToString("N").ToUpperInvariant(),
            128,
            "Test",
            "Test quarantine",
            DateTimeOffset.UtcNow);
    }
}