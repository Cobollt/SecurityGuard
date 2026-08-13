using SecurityGuard.Storage.Configuration;
using SecurityGuard.Storage.Database;

namespace SecurityGuard.Storage.Tests;

internal sealed class TestDatabase : IAsyncDisposable
{
    public string DirectoryPath { get; }

    public string DatabasePath { get; }

    public SqliteConnectionFactory ConnectionFactory { get; }

    private TestDatabase(
        string directoryPath,
        string databasePath,
        SqliteConnectionFactory connectionFactory)
    {
        DirectoryPath = directoryPath;
        DatabasePath = databasePath;
        ConnectionFactory = connectionFactory;
    }

    public static async Task<TestDatabase> CreateAsync()
    {
        var directory =
            Path.Combine(
                Path.GetTempPath(),
                "SecurityGuard.Tests",
                Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(directory);

        var databasePath =
            Path.Combine(
                directory,
                "securityguard-test.db");

        var options =
            new StorageOptions(databasePath);

        var factory =
            new SqliteConnectionFactory(options);

        var initializer =
            new DatabaseInitializer(factory);

        await initializer.InitializeAsync();

        return new TestDatabase(
            directory,
            databasePath,
            factory);
    }

    public ValueTask DisposeAsync()
    {
        if (Directory.Exists(DirectoryPath))
        {
            Directory.Delete(
                DirectoryPath,
                true);
        }

        return ValueTask.CompletedTask;
    }
}