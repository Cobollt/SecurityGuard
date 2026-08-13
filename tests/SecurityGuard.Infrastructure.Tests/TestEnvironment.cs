using SecurityGuard.Infrastructure.Configuration;
using SecurityGuard.Storage.Configuration;
using SecurityGuard.Storage.Database;

namespace SecurityGuard.Infrastructure.Tests;

internal sealed class TestEnvironment
    : IAsyncDisposable
{
    public string RootDirectory { get; }

    public SecurityGuardPaths Paths { get; }

    public SqliteConnectionFactory ConnectionFactory { get; }

    private TestEnvironment(
        string rootDirectory,
        SecurityGuardPaths paths,
        SqliteConnectionFactory connectionFactory)
    {
        RootDirectory = rootDirectory;
        Paths = paths;
        ConnectionFactory = connectionFactory;
    }

    public static async Task<TestEnvironment> CreateAsync()
    {
        var root =
            Path.Combine(
                Path.GetTempPath(),
                "SecurityGuard.Infrastructure.Tests",
                Guid.NewGuid().ToString("N"));

        var paths =
            new SecurityGuardPaths(root);

        Directory.CreateDirectory(
            paths.RootDirectory);

        Directory.CreateDirectory(
            paths.DataDirectory);

        Directory.CreateDirectory(
            paths.QuarantineDirectory);

        Directory.CreateDirectory(
            paths.LogsDirectory);

        Directory.CreateDirectory(
            paths.TempDirectory);

        var options =
            new StorageOptions(
                paths.DatabasePath);

        var factory =
            new SqliteConnectionFactory(options);

        var initializer =
            new DatabaseInitializer(factory);

        await initializer.InitializeAsync();

        return new TestEnvironment(
            root,
            paths,
            factory);
    }

    public ValueTask DisposeAsync()
    {
        if (Directory.Exists(RootDirectory))
        {
            Directory.Delete(
                RootDirectory,
                true);
        }

        return ValueTask.CompletedTask;
    }
}