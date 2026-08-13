using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.Storage.Repositories;

namespace SecurityGuard.Storage.Tests;

public sealed class ProtectedObjectRepositoryTests
{
    [Fact]
    public async Task Object_can_be_found_by_hash()
    {
        await using var database =
            await TestDatabase.CreateAsync();

        var repository =
            new SqliteProtectedObjectRepository(
                database.ConnectionFactory);

        var now = DateTimeOffset.UtcNow;

        var protectedObject =
            new ProtectedObject(
                Guid.NewGuid(),
                @"C:\Temp\test.ps1",
                "test.ps1",
                ".ps1",
                "ABC123",
                128,
                ObjectTrustStatus.Suspicious,
                now,
                now);

        await repository.UpsertAsync(
            protectedObject);

        var stored =
            await repository.FindByHashAsync(
                "ABC123");

        Assert.NotNull(stored);

        Assert.Equal(
            protectedObject.Id,
            stored.Id);

        Assert.Equal(
            ObjectTrustStatus.Suspicious,
            stored.TrustStatus);
    }
}