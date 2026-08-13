namespace SecurityGuard.Storage.Tests;

public sealed class DatabaseInitializerTests
{
    [Fact]
    public async Task Database_is_created()
    {
        await using var database =
            await TestDatabase.CreateAsync();

        Assert.True(
            File.Exists(database.DatabasePath));
    }
}