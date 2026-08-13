using SecurityGuard.Storage.Repositories;

namespace SecurityGuard.Storage.Tests;

public sealed class SettingsRepositoryTests
{
    [Fact]
    public async Task Setting_can_be_saved_and_updated()
    {
        await using var database =
            await TestDatabase.CreateAsync();

        var repository =
            new SqliteSettingsRepository(
                database.ConnectionFactory);

        await repository.SetAsync(
            "Protection.Enabled",
            "true");

        var first =
            await repository.GetAsync(
                "Protection.Enabled");

        Assert.Equal(
            "true",
            first);

        await repository.SetAsync(
            "Protection.Enabled",
            "false");

        var second =
            await repository.GetAsync(
                "Protection.Enabled");

        Assert.Equal(
            "false",
            second);
    }
}